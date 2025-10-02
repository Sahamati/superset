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

from .base import BaseSupersetView
from flask import g, redirect, request, flash, session
from flask_appbuilder._compat import as_unicode
from flask_appbuilder import expose
from flask_login import login_user
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder.utils.base import get_safe_redirect
from superset.utils.mfa import get_otp, delete_otp, generate_otp, smtp_send_otp, get_del_otp, set_otp_nx, otp_exists, mfa_redis
from flask import jsonify
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
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
            
            # If the user role is public, login them
            if self.appbuilder.sm.find_role("Public") in user.roles:
                login_user(user, remember=False)
                return redirect(next_url)
            
            # Check if OTP already exists
            if session.get("mfa_user_id") == user.id and otp_exists(user.id):
                logger.info("OTP already exists for user %s: %s, redirecting to verify", user.email, get_otp(user.id))
                flash(as_unicode("Please complete your OTP verification."), "warning")
                return redirect("/mfa/verify")
            
            # generate the otp for mfa
            otp = generate_otp()
            logger.info("Generated OTP for user %s: %s", user.email, otp)
            
            # store the otp in redis with expiry of 5 minutes against the user id in redis and then store the user id in session
            if not set_otp_nx(user.id, otp, ttl=300):
                logger.info("OTP is failing to get set")
            
            # send the code to the user email
            logger.info("About to send OTP")
            try: 
                smtp_send_otp(user.email, otp)
                logger.info("Sent OTP to email: %s. Check mail for bouncebacks", user.email)
            except Exception as e:
                get_del_otp(user.id)
                logger.error("Failed to send OTP to %s: %s", user.email, str(e))
                flash(as_unicode("Failed to send OTP. Please try again."), "warning")
                return redirect(self.appbuilder.get_url_for_login_with(next_url))
            
            session["mfa_user_id"] = user.id
            session["mfa_next_url"] = next_url
            logger.info("Login success")
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
            return redirect(self.appbuilder.get_url_for_index)
        
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
        
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        #Step 1
        code = request.form.get("code")
        
        #Step 2
        user_id = session.get("mfa_user_id")
        logger.info("MFA attempt: user_id=%s, code=%s", user_id, code)

        if not user_id:
            logger.warning("MFA session expired - redirecting to login")
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
        
        if not otp:
            flash(as_unicode("MFA session expired or invalid. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login)
        
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
    
    # Additional Resend logic
    # The cases for circular calls from the frontend between login and mfa have been handled already. The only way the attackers can
    # attack the system is if they are going to try and abuse the resend logic. Blocking it is the best course of action and hence, 
    # only adding the cooldowns to the resend logic should be making more sense than not.
    # Rest of the resend logic is the same. 
    # Receive the resend call the call
    # check if the otp exists and delete it. 
    # Send out a new mail
    # Only new thing that has been added is the proper cooldown management for the resend logic.
    @expose("/resend", methods=["POST"])
    def resend_code(self) -> FlaskResponse:
        user_id = session.get("mfa_user_id")
        if not user_id:
            flash(as_unicode("MFA session expired. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())

        user = self.appbuilder.sm.get_user_by_id(user_id)
        if not user:
            flash(as_unicode("User not found. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())

        # Check if request is "check only" (frontend asking TTL)
        if request.args.get("check_only") == "true":
            ttl = mfa_redis.ttl(f"otp:{user_id}")  # remaining seconds
            return jsonify({"ttl": max(ttl, 0)}), 200

        # Normal resend flow
        ttl_key = f"otp:{user_id}"
        remaining_ttl = mfa_redis.ttl(ttl_key)

        # Enforce cooldown (e.g., 300s)
        COOLDOWN = 300
        if remaining_ttl and remaining_ttl > COOLDOWN - 1:
            return jsonify({"ttl": remaining_ttl}), 429  # Too many requests

        # Delete old OTP & generate new one (the old logic and steps kick in here)
        get_del_otp(user_id)
        otp = generate_otp()
        set_otp_nx(user_id, otp, ttl=300)
        smtp_send_otp(user.email, otp)
        logger.info("Resent OTP to email: %s", user.email)

        return jsonify({"ttl": COOLDOWN}), 200