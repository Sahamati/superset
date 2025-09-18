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

# from flask_appbuilder.security.views import AuthDBView
from .base import BaseSupersetView
from flask import g, redirect, request, flash, session
from flask_appbuilder._compat import as_unicode
from flask_appbuilder import expose
from flask_login import login_user
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder.utils.base import get_safe_redirect
import logging
logger = logging.getLogger(__name__)

from superset.superset_typing import FlaskResponse

class MFAAuthDBView(BaseSupersetView, AuthDBView):
    route_base = "/login"
    @expose("/", methods=["GET", "POST"])
    def login(self):
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)

        form = LoginForm_db()
        if form.validate_on_submit():
            next_url = get_safe_redirect(request.args.get("next", ""))
            user = self.appbuilder.sm.auth_user_db(
                form.username.data, form.password.data
            )
            if not user:
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login_with(next_url))

            # login_user(user, remember=False)
            session["mfa_user_id"] = user.id
            # session["mfa_expires_at"] = time.time() + 300  # 5 minutes
            session["mfa_next_url"] = next_url
            return redirect("/mfa/verify")

        return self.render_template(
            self.login_template, title=self.title, form=form, appbuilder=self.appbuilder
        )


class MFAView(BaseSupersetView):
    route_base = "/mfa"

    @expose("/verify", methods=["GET"])
    def verify(self) -> FlaskResponse:
        #verify MFA code
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        # get the otp from the request
        logger.info("Rendering MFA verify page")
        return self.render_app_template()
    
    @expose("/verify", methods=["POST"])
    def verify_code(self) -> FlaskResponse:
        code = request.form.get("code")
        user_id = session.get("mfa_user_id")
        logger.info("MFA attempt: user_id=%s, code=%s", user_id, code)

        if not user_id:
            logger.warning("MFA session expired — redirecting to login")
            flash(as_unicode("MFA session expired. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())

        user = self.appbuilder.sm.get_user_by_id(user_id)
        if not user:
            logger.error("MFA failed: no user found for id=%s", user_id)
            flash(as_unicode("User not found. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())

        if code == "123456":  # Replace with actual verification logic
            next_url = session.get("mfa_next_url")
            session.pop("mfa_user_id", None)
            session.pop("mfa_next_url", None)
            login_user(user, remember=False)
            logger.info("MFA success: user_id=%s redirect=%s", user.id, next_url)
            return redirect(next_url)
        else:
            logger.warning("Invalid MFA code for user_id=%s", user_id)
            flash(as_unicode("Invalid MFA code. Please try again."), "danger")
            return redirect("/mfa/verify")