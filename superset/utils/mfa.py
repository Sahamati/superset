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

from flask import current_app
from superset.utils.core import send_email_smtp
import secrets
from superset import app
from smtplib import SMTPException
import hashlib
import redis
import hmac

from typing import Optional
import logging

# Agreement imports:
from superset import db
from superset.models.user_agreements import UserAgreements
from functools import wraps
from flask import session, request, redirect
from superset.views.base import json_error_response

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# otp util
def smtp_send_otp(user_email: str, otp: str, **kwargs) -> None:
    subject = current_app.config.get("MFA_EMAIL_SUBJECT", "Your Login Verification OTP")
    body = current_app.config.get("MFA_EMAIL_TEMPLATE", "{code}").format(code=otp)

    send_email_smtp(
        to=user_email,
        subject=subject,
        config=current_app.config["MFA_EMAIL_CONFIG"],
        html_content=body,
        **kwargs,
    )


# generate otp util    
def generate_otp() -> str:
    """Generate a 6-digit OTP."""
    otp = f"{secrets.randbelow(1000000):06}"
    return otp

# redis util
MFA_REDIS_CONFIG = app.config["MFA_REDIS_CONFIG"]

mfa_redis = redis.Redis(
    **app.config["MFA_REDIS_CONFIG"],
    decode_responses=True, # ensure we get strings back instead of bytes
)

def set_otp(id: int, otp: str, ttl: int = 300, **kwargs) -> bool:
    """
    Store OTP in Redis with a time-to-live (default 5 minutes).
    Additional Redis parameters (nx, xx, etc.) can be passed via kwargs.

    Args:
        id (int): User ID
        otp (str): OTP string
        ttl (int, optional): Expiration in seconds. Defaults to 300.
        **kwargs: Extra parameters for redis.set (nx, xx, etc.)

    Returns:
        bool: True if the key was set, False otherwise
    """
    key = f"otp:{id}"
    if 'keepttl' in kwargs and kwargs['keepttl']:
        # Redis will throw if ex or px is also passed
        result = mfa_redis.set(key, otp, **kwargs)
    else:
        result = mfa_redis.set(key, otp, ex=ttl, **kwargs)
    return bool(result)


def set_resend_cooldown(user_id: int, ttl: int = 30) -> bool:
    """
    Set a resend cooldown (default 30s) for the given user.
    Returns True if the cooldown was successfully set, False if it already exists.
    """
    key = f"otp_cooldown:{user_id}"
    result = mfa_redis.set(key, 1, ex=ttl, nx=True)
    return bool(result)

def get_otp(id: int) -> Optional[str]:
    """
    Retrieve OTP for a given email.
    """
    key = f"otp:{id}"
    return mfa_redis.get(key)

def delete_otp(id: int) -> None:
    """
    Delete OTP once it’s verified.
    """
    key = f"otp:{id}"
    mfa_redis.delete(key)
    
def get_del_otp(id: int) -> Optional[str]:
    """
    Retrieve and delete OTP for a given email.
    """
    key = f"otp:{id}"
    if mfa_redis.exists(key):
        return mfa_redis.getdel(key)
    return None

def otp_exists(id: int) -> bool:
    """
    Check if otp exists or not.
    """
    key = f"otp:{id}"
    if mfa_redis.exists(key):
        return True
    return False

def hash_otp(otp: str, secret_key: str) -> str:
    """Returns a secure hash of the OTP using HMAC-SHA256."""
    return hmac.new(secret_key.encode(), otp.encode(), hashlib.sha256).hexdigest()

def verify_otp(provided_otp: str, stored_hash: str, secret_key: str) -> bool:
    """Compares an OTP with its stored hash safely."""
    return hmac.compare_digest(
        hash_otp(provided_otp, secret_key),
        stored_hash
    )
    
# Agreements page functions are defined here. Bring these out into its own thing before doing anything else.
def get_user_agreements(user_id: int) -> Optional[UserAgreements]:
    return (
        db.session.query(UserAgreements)
        .filter(UserAgreements.id == user_id)
        .first()
    )


def verify_agreements(user_id: int) -> bool:
    logger.info("Verifying agreements for user_id=%s", user_id)
    ua = get_user_agreements(user_id)
    if not ua:
        logger.error("No agreements found for user_id=%s", user_id)
        return False
    return ua.tou_accepted and ua.pp_accepted


def require_mfa(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("mfa_status"):
            logger.warning(
                "Blocked agreements access without MFA. "
                "Path=%s, Method=%s, Remote=%s, Accept=%s",
                request.path,
                request.method,
                request.remote_addr,
                request.accept_mimetypes.to_header(),
            )

            # For API/ajax calls -> return JSON error with redirect hint
            if request.accept_mimetypes["application/json"] >= request.accept_mimetypes["text/html"]:
                return json_error_response(
                    msg="MFA required",
                    status=401,
                    payload={"link": "/mfa/verify"},
                )

            # For browser navigation -> redirect user to MFA verify page
            return redirect("/mfa/verify")

        # Log success path only if needed (optional)
        logger.debug("MFA check passed for path=%s", request.path)
        return f(*args, **kwargs)
    return wrapper