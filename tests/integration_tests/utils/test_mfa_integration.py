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

import pytest
from superset import app as superset_app
from superset.utils import mfa as mfa_module

@pytest.mark.integration
def test_integration_redis_set_get_delete():
    cfg = superset_app.config.get('MFA_REDIS_CONFIG')
    if not cfg:
        pytest.skip('MFA_REDIS_CONFIG not configured in app')
    import redis
    r = redis.Redis(**cfg, decode_responses=True)
    try:
        r.ping()
    except Exception:
        pytest.skip('No Redis server available')
    orig = mfa_module.mfa_redis
    mfa_module.mfa_redis = r
    try:
        assert mfa_module.set_otp(901, 'ival', ttl=5)
        assert mfa_module.get_otp(901) == 'ival'
        assert mfa_module.otp_exists(901)
        mfa_module.delete_otp(901)
        assert mfa_module.get_otp(901) is None
    finally:
        mfa_module.mfa_redis = orig

@pytest.mark.integration
def test_integration_hash_verify_and_store():
    cfg = superset_app.config.get('MFA_REDIS_CONFIG')
    if not cfg:
        pytest.skip('MFA_REDIS_CONFIG not configured in app')
    import redis
    r = redis.Redis(**cfg, decode_responses=True)
    try:
        r.ping()
    except Exception:
        pytest.skip('No Redis server available')
    orig = mfa_module.mfa_redis
    mfa_module.mfa_redis = r
    secret = superset_app.config.get('SECRET_KEY', 'integration-secret')
    try:
        otp = mfa_module.generate_otp()
        hashed = mfa_module.hash_otp(otp, secret)
        assert mfa_module.set_otp(902, hashed, ttl=10)
        stored = mfa_module.get_otp(902)
        assert mfa_module.verify_otp(otp, stored, secret)
        mfa_module.delete_otp(902)
    finally:
        mfa_module.mfa_redis = orig
