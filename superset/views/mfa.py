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

from .base import BaseSupersetView, json_error_response, json_success
from flask import g, redirect, request, flash, session, current_app, Response
from flask_appbuilder._compat import as_unicode
from flask_appbuilder import expose
from flask_login import login_user
from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder.utils.base import get_safe_redirect
from superset.utils.mfa import (get_otp,
delete_otp, 
generate_otp, 
smtp_send_otp, 
get_del_otp, 
set_otp,
set_resend_cooldown,
otp_exists,
mfa_redis,
hash_otp,
verify_otp,
verify_agreements,
get_user_agreements,
require_mfa)
from flask import jsonify

from superset import db
from superset.models.user_agreements import UserAgreements
import datetime
import simplejson as json

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

            if self.appbuilder.sm.find_role("Public") in user.roles:
                # if the user has already agreed to the agreements, proceed to login
                if verify_agreements(user.id):
                    login_user(user, remember=False)
                    logger.info("Public role login (MFA disabled user) - user has accepted agreements, proceeding to login")
                    return redirect(next_url)
                # if the user has not agreed to the agreements, redirect to agreements page
                else:
                    session["mfa_user_id"] = user.id
                    session["mfa_next_url"] = next_url
                    session["mfa_status"] = True
                    logger.info("Public role login (MFA disabled user) - user hasn't accepted agreements, redirecting to agreements")
                    return redirect("/agreements")

            if session.get("mfa_user_id") == user.id and otp_exists(user.id):
                logger.info("OTP already exists for user, redirecting to mfa verification.")
                flash(as_unicode("Please complete your OTP verification."), "warning")
                return redirect("/mfa/verify")
            
            otp = generate_otp()
            logger.info("Generated OTP for user")
            hashed_otp = hash_otp(otp, current_app.config["SECRET_KEY"])
            
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

    @expose("/verify", methods=["GET"])
    def verify(self) -> FlaskResponse:
        
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        
        user_id = session.get("mfa_user_id")
        if not user_id:
            logger.warning("Incorrect MFA access  order — redirecting to login")
            flash(as_unicode("Session expired or invalid. Please login again."), "warning")
            return redirect(self.appbuilder.get_url_for_login)
        logger.info("Rendering MFA verify page")
        return self.render_app_template()
    
    @expose("/verify", methods=["POST"])
    def verify_code(self) -> FlaskResponse:
        
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
            delete_otp(user_id)
            logger.info("OTP verified successfull")
            if verify_agreements(user_id):
                next_url = session.get("mfa_next_url")
                session.pop("mfa_user_id", None)
                login_user(user, remember=False)
                logger.info("MFA success: redirect= %s", next_url)
                return redirect(next_url)
            session["mfa_status"] = True
            logger.info("MFA success: redirecting to agreements")
            return redirect("/agreements")
        else:
            logger.warning("Invalid OTP.")
            flash(as_unicode("Invalid OTP. Please try again."), "danger")
            return redirect("/mfa/verify")
    
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
class AgreementsView(BaseSupersetView):
    route_base = "/agreements"

    @expose("/", methods=["GET"])
    def show(self) -> FlaskResponse:
        if g.user is not None and g.user.is_authenticated:
            return redirect(self.appbuilder.get_url_for_index)
        
        if verify_agreements(session.get("mfa_user_id")):
            logger.info("User has already accepted agreements. Redirecting to login.")
            flash(as_unicode("You have already accepted the agreements."), "info")
            return redirect(self.appbuilder.get_url_for_login)
        
        status =session.get("mfa_status")
        if not status or  status is not True:
            logger.warning("Agreements accessed without completing MFA")
            flash(as_unicode("Please complete your OTP verification."), "warning")
            return redirect("/mfa/verify")
        
        return self.render_app_template()

    @expose("/api/status", methods=["GET"])
    @require_mfa
    def status(self) -> FlaskResponse:
        user_id = session.get("mfa_user_id")
        if not user_id:
            return json_error_response("No session", status=401)

        ua = get_user_agreements(user_id)

        return json_success(json.dumps({
            "touAccepted": ua.tou_accepted,
            "ppAccepted": ua.pp_accepted,
        }))

    @expose("/api/accept", methods=["POST"])
    @require_mfa
    def accept(self) -> FlaskResponse:
        user_id = session.get("mfa_user_id")
        if not user_id:
            return json_error_response("No session", status=401)

        # Try JSON first, fallback to form data (because postForm isn’t JSON)
        payload = request.get_json(silent=True) or request.form.to_dict()
        agreement_type = payload.get("type")

        user_agreements = db.session.query(UserAgreements).filter_by(id=user_id).first()
        if not user_agreements:
            return json_error_response("User agreements not found", status=404)

        now = datetime.datetime.now(datetime.timezone.utc)
        if agreement_type == "tou":
            user_agreements.tou_accepted = True
            user_agreements.tou_accepted_on = now
            user_agreements.tou_version = current_app.config.get("TERMS_OF_USE", 0.0)
        elif agreement_type == "pp":
            user_agreements.pp_accepted = True
            user_agreements.pp_accepted_on = now
            user_agreements.pp_version = current_app.config.get("PRIVACY_POLICY", 0.0)
        else:
            return json_error_response("Invalid agreement type", status=400)

        db.session.commit()

        # If both agreements accepted → finalize login
        if user_agreements.tou_accepted and user_agreements.pp_accepted:
            user = self.appbuilder.sm.get_user_by_id(user_id)
            login_user(user, remember=False)
            session.pop("mfa_user_id", None)
            session.pop("mfa_status", None)
            next_url = session.pop("mfa_next_url") or current_app.appbuilder.get_url_for_index()
            return redirect(next_url)

        # Otherwise still pending
        return json_success(json.dumps({"success": True}))
