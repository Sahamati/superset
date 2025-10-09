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
from flask import g, redirect, request, flash, session, current_app
from flask_appbuilder._compat import as_unicode
from flask_appbuilder import expose
from flask_login import login_user
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder.utils.base import get_safe_redirect
from superset.utils.mfa import get_otp, delete_otp, generate_otp, smtp_send_otp, get_del_otp, set_otp, set_resend_cooldown, otp_exists, mfa_redis, hash_otp, verify_otp
from flask import jsonify
import logging
logger = logging.getLogger(__name__)
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
                logger.info("OTP already exists for user, redirecting to mfa verification.")
                flash(as_unicode("Please complete your OTP verification."), "warning")
                return redirect("/mfa/verify")
            
            # generate the otp for mfa
            otp = generate_otp()
            logger.info("Generated OTP for user")
            hashed_otp = hash_otp(otp, current_app.config["SECRET_KEY"])
            
            # store the otp in redis
            if not set_otp(user.id, hashed_otp, ttl=300, nx = True):
                logger.info("Failed to set OTP.")
            if not set_resend_cooldown(user.id, ttl=30):
                logger.info("Failed to set resend cooldown during login.")
            try: 
                smtp_send_otp(user.email, otp)
                logger.info("Sent OTP to email. Check smtp mail for bouncebacks")
            except Exception as e:
                get_del_otp(user.id)
                logger.error("Failed to send OTP: %s", str(e))
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
            flash(as_unicode("Session expired or invalid. Please login again."), "warning")
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
        logger.info("MFA attempted")

        if not user_id:
            logger.warning("MFA session expired - redirecting to login")
            flash(as_unicode("Session expired or invalid. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())

        # Step 3
        otp = get_otp(user_id)
        logger.info("Retrieved OTP for user")
        user = self.appbuilder.sm.get_user_by_id(user_id)
        if not user:
            logger.error("MFA failed: no user found with id=%s", user_id)
            flash(as_unicode("User not found. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login())
        
        if not otp:
            flash(as_unicode("Session expired or invalid. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login)
        
        if verify_otp(code, otp, current_app.config["SECRET_KEY"]):
            next_url = session.get("mfa_next_url")
            session.pop("mfa_user_id", None)
            session.pop("mfa_next_url", None)
            login_user(user, remember=False)
            delete_otp(user_id)
            # don't delete the resend cooldown key for conclusions not mentioned here.
            logger.info("MFA success: redirect=%s", next_url)
            return redirect(next_url)
        else:
            logger.warning("Invalid OTP.")
            flash(as_unicode("Invalid OTP. Please try again."), "danger")
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
            return jsonify({"error": "Session expired or invalid. Please login again."}), 401

        user = self.appbuilder.sm.get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found. Please login again."}), 401

        otp_key = f"otp:{user_id}"
        cooldown_key = f"otp_cooldown:{user_id}"

        # if OTP validity already expired -> force new login
        if not otp_exists(user_id):
            session.pop("mfa_user_id", None)
            flash(as_unicode("OTP expired. Please login again."), "danger")
            return jsonify({"redirect": "/login/"}), 401

        # check-only flow (SPA polling)
        if request.args.get("check_only") == "true":
            ttl = mfa_redis.ttl(cooldown_key)  # OTP validity remaining
            return jsonify({"ttl": max(ttl, 0)}), 200

        # enforce cooldown using utility; block extra calls
        if not set_resend_cooldown(user_id, ttl=30):
            remaining = mfa_redis.ttl(f"otp_cooldown:{user_id}")
            return jsonify({"ttl": max(remaining, 0)}), 429

        # generate new OTP but preserve original OTP expiry window
        current_ttl = mfa_redis.ttl(otp_key)
        if current_ttl <= 0:
            session.pop("mfa_user_id", None)
            session.pop("mfa_next_url", None)
            return jsonify({"error": "OTP expired. Please login again."}), 401

        otp = generate_otp()
        hashed_otp = hash_otp(otp, current_app.config["SECRET_KEY"])
        set_otp(user_id, hashed_otp, keepttl= True, xx= True)
        logger.info("resent otp hash:%s", get_otp(user_id))
        try:
            smtp_send_otp(user.email, otp)
            logger.info("Resent OTP to user email. ttl = %s",current_ttl)
        except Exception as e:
            logger.error("Failed to resend OTP:%s", str(e))
            return jsonify({"error": "Failed to resend OTP. Please try again."}), 500

        return jsonify({"ttl": 30}), 200