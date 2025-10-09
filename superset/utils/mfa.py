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
logger = logging.getLogger("superset")
logger.setLevel(logging.INFO)

# otp util
def smtp_send_otp(user_email: str, otp: str) -> bool:
        """Send the OTP to the user's email address via SMTP."""
        subject = "Sahamati SaaNs Login OTP"
        body = f"Your login verification otp is: {otp}"
        try:
            send_email_smtp(
                to=user_email,
                subject=subject,
                config=current_app.config,
                html_content=body,
            )
        except SMTPException as e:
            logger.warning("Failed to send otp (smtp)", e)
            return False

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