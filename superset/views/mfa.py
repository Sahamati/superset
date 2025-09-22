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
from flask import g, redirect, request, flash, session, make_response
from flask_appbuilder._compat import as_unicode
from flask_appbuilder import expose
from flask_login import login_user
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder.utils.base import get_safe_redirect
from superset.utils.mfa import set_otp, get_otp, delete_otp, generate_otp, smtp_send_otp, get_del_otp
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
from superset.utils.mfa import smtp_send_otp
from superset.superset_typing import FlaskResponse

class MFAAuthDBView(BaseSupersetView, AuthDBView):
    route_base = "/login"
    @expose("/", methods=["GET", "POST"])
    def login(self):
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index())
        
        # TODO if the user comes to the page from mfa verification, remove the mfa_user_id from session

        form = LoginForm_db()
        if form.validate_on_submit():
            next_url = get_safe_redirect(request.args.get("next", ""))
            user = self.appbuilder.sm.auth_user_db(
                form.username.data, form.password.data
            )
            if not user:
                flash(as_unicode(self.invalid_login_message), "warning")
                return redirect(self.appbuilder.get_url_for_login_with(next_url))

            if get_otp(user.id):
                logger.info("OTP already exists for user %s, not generating new one", user.email)
                flash(as_unicode("An OTP has already been sent to your email. Please check your inbox."), "info")
            else:
                # generate the code for mfa
                otp = generate_otp()
                logger.info("Generated OTP for user %s: %s", user.email, otp)
                
                # send the code to the user email
                smtp_send_otp(user.email, otp)
                logger.info("Sending OTP to email: %s", user.email)
                # store the code in redis with expiry of 5 minutes against the user id in redis and then store the user id in session
                set_otp(user.id, otp, ttl=300)
                
            session["mfa_user_id"] = user.id
            session["mfa_next_url"] = next_url
            return redirect("/mfa/verify")

        return self.render_template(
            self.login_template, title=self.title, form=form, appbuilder=self.appbuilder
        )


class MFAView(BaseSupersetView):
    route_base = "/mfa"
    #The get page logic for mfa
    @expose("/verify", methods=["GET"])
    def verify(self) -> FlaskResponse:
        # if the user is logged in already, then go to whatever page they wanted to go to
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index())
        
        # if the session does not have the user_id, then the mfa session has expired/the user did not come from login
        # redirect to login page
        user_id = session.get("mfa_user_id")
        if not user_id:
            logger.warning("Incorrect MFA access  order — redirecting to login")
            flash(as_unicode("MFA session expired. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login)
        logger.info("Rendering MFA verify page")
        return self.render_app_template()
    
    @expose("/verify", methods=["POST"])
    def verify_code(self) -> FlaskResponse:
        
        # Step1: First, get the code from the form
        # Step2: Then, get the user_id from the session. Add redirect logic if user_id not found
        # # The user_id will be there ideally, meaning now the question is what comes first, the code otp processing and checks, or checking the user?
        # whats the point of checking the code if there is no user? But check the code regardless of user, because it might be a bot attack
        # Step3 get the code against the user_id
        
        #Step 1
        code = request.form.get("code")
        
        #Step 2
        user_id = session.get("mfa_user_id")
        logger.info("MFA attempt: user_id=%s, code=%s", user_id, code)

        if not user_id:
            logger.warning("MFA session expired — redirecting to login")
            flash(as_unicode("MFA session expired. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())

        # Step 3
        otp = get_otp(user_id)
        logger.info("Retrieved OTP from Redis for user_id=%s: %s", user_id, otp)
        user = self.appbuilder.sm.get_user_by_id(user_id)
        if not user:
            logger.error("MFA failed: no user found for id=%s", user_id)
            flash(as_unicode("User not found. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())
        
        if code == otp:
            next_url = session.get("mfa_next_url")
            session.pop("mfa_user_id", None)
            session.pop("mfa_next_url", None)
            login_user(user, remember=False)
            delete_otp(user_id)
            logger.info("Deleted OTP from Redis for user_id=%s", user_id)
            logger.info("MFA success: user_id=%s redirect=%s", user.id, next_url)
            return redirect(next_url)
        else:
            logger.warning("Invalid MFA code for user_id=%s", user_id)
            flash(as_unicode("Invalid MFA code. Please try again."), "danger")
            return redirect("/mfa/verify")
    
    @expose("/resend", methods=["POST"])
    def resend_code(self) -> FlaskResponse:
        user_id = session.get("mfa_user_id")
        if not user_id:
            logger.warning("MFA session expired — redirecting to login")
            flash(as_unicode("MFA session expired. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())
        user = self.appbuilder.sm.get_user_by_id(user_id)
        if not user:
            logger.error("MFA resend failed: no user found for id=%s", user_id)
            flash(as_unicode("User not found. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())
        get_del_otp(user_id)  # delete existing otp if any
        otp = generate_otp()
        logger.info("Generated new OTP for user %s: %s", user.email, otp)
        smtp_send_otp(user.email, otp)
        set_otp(user.id, otp, ttl=300)  # store new otp
        logger.info("Resent OTP to email: %s", user.email)
        flash(as_unicode("A new OTP has been sent to your email."), "info")
        return make_response("", 200)
        