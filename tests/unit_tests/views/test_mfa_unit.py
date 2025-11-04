# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
# ---------------- tests/unit_tests/views/test_mfa_unit.py ----------------

import pytest
from unittest import mock
from smtplib import SMTPException
from flask import Flask, session
import re
from superset.utils import mfa as mfa_module
from superset import app as superset_app

class FakeRedis:
    def __init__(self):
        self.store = {}
        self.expire = {}
    def set(self, key, value, ex=None, nx=False, xx=False, keepttl=False, **kwargs):
        exists = key in self.store
        if nx and exists:
            return False
        if xx and not exists:
            return False
        self.store[key] = value
        if ex is not None and not keepttl:
            self.expire[key] = ex
        return True
    def get(self, key):
        return self.store.get(key)
    def delete(self, key):
        self.store.pop(key, None)
        self.expire.pop(key, None)
    def exists(self, key):
        return 1 if key in self.store else 0
    def getdel(self, key):
        val = self.get(key)
        self.delete(key)
        return val
    def ttl(self, key):
        return self.expire.get(key, -2)

def test_generate_otp_format_and_uniqueness():
    otps = {mfa_module.generate_otp() for _ in range(200)}
    for o in otps:
        assert isinstance(o, str)
        assert re.fullmatch(r"\d{6}", o)
    assert len(otps) > 1

def test_hash_and_verify_otp():
    otp, secret = "123456", "mysecret"
    hashed = mfa_module.hash_otp(otp, secret)
    assert mfa_module.verify_otp(otp, hashed, secret)
    assert not mfa_module.verify_otp("000000", hashed, secret)
    assert not mfa_module.verify_otp(otp, hashed, "other")

def test_redis_utils_with_fake_redis(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(mfa_module, 'mfa_redis', fake)
    assert mfa_module.set_otp(1, 'v', ttl=10)
    assert fake.get('otp:1') == 'v'
    assert not mfa_module.set_otp(1, 'v2', nx=True)
    assert not mfa_module.set_otp(2, 'v', xx=True)
    assert mfa_module.get_otp(1) == 'v'
    assert mfa_module.otp_exists(1)
    assert not mfa_module.otp_exists(999)
    fake.set('otp:3', 'x')
    assert mfa_module.get_del_otp(3) == 'x'
    assert mfa_module.get_otp(3) is None
    mfa_module.set_otp(4, 'y')
    mfa_module.delete_otp(4)
    assert mfa_module.get_otp(4) is None
    assert mfa_module.set_resend_cooldown(5, ttl=10)
    assert not mfa_module.set_resend_cooldown(5, ttl=10)

def test_smtp_send_otp_handles_exception(monkeypatch):
    monkeypatch.setattr(mfa_module, 'send_email_smtp', mock.Mock(side_effect=SMTPException('boom')))
    assert not mfa_module.smtp_send_otp('a@b.com', '000000')
    monkeypatch.setattr(mfa_module, 'send_email_smtp', mock.Mock(return_value=None))
    assert mfa_module.smtp_send_otp('a@b.com', '111111') is None

import pytest
from superset import app as superset_app, appbuilder

@pytest.fixture
def client():
    app = superset_app
    app.config.setdefault("SECRET_KEY", "test-secret")
    app.testing = True

    # ✅ Import your MFA views
    from superset.views.mfa import MFAView, MFAAuthDBView

    # ✅ Register MFA routes with Flask-AppBuilder (once)
    if not app.config.get("MFA_VIEW_REGISTERED", False):
        appbuilder.add_view_no_menu(MFAView)
        appbuilder.add_view_no_menu(MFAAuthDBView)
        app.config["MFA_VIEW_REGISTERED"] = True

    with app.test_client() as c:
        with app.app_context():
            yield c

def test_verify_get_without_session_redirects_to_login(client):
    from superset.views import mfa as views
    rv = client.get('/mfa/verify', follow_redirects=False)
    assert rv.status_code in (302, 301)

def test_resend_without_session_returns_401(client):
    from superset.views import mfa as views
    rv = client.post('/mfa/resend')
    assert rv.status_code == 401
    assert rv.is_json
    assert 'error' in rv.get_json()

@pytest.mark.usefixtures("client")
def test_resend_check_only_returns_ttl(monkeypatch, client):
    from superset.views import mfa as views
    from superset.views.mfa import MFAView

    # Build a minimal Flask app to test the view directly
    app = Flask(__name__)
    app.secret_key = "test"
    app.testing = True

    # Register MFAView manually
    view = MFAView()
    view.appbuilder = mock.Mock()
    view.appbuilder.sm = mock.Mock()
    fake_user = mock.Mock(email="x@y.com")
    view.appbuilder.sm.get_user_by_id.return_value = fake_user

    # Patch dependencies
    fake_redis = mock.Mock()
    fake_redis.ttl.return_value = 15
    monkeypatch.setattr(views, "mfa_redis", fake_redis)
    monkeypatch.setattr(views, "otp_exists", lambda _id: True)

    # Create test route
    app.add_url_rule("/mfa/resend", view_func=view.resend_code, methods=["POST"])

    # Simulate request with user session
    with app.test_client() as c:
        with c.session_transaction() as sess:
            sess["mfa_user_id"] = 42
        rv = c.post("/mfa/resend?check_only=true")

    # Assertions
    assert rv.status_code == 200, rv.data
    data = rv.get_json()
    assert "ttl" in data
    assert data["ttl"] == 15