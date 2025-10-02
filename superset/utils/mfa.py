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

import redis

from typing import Optional
import logging
logger = logging.getLogger("superset")
logger.setLevel(logging.INFO)

# otp util
def smtp_send_otp(user_email: str, otp: str) -> bool:
        """Send the OTP to the user's email address via SMTP."""
        subject = "Your MFA Code"
        body = f"Your MFA code is: {otp}"
        try:
            send_email_smtp(
                to=user_email,
                subject=subject,
                config=current_app.config,
                html_content=body,
            )
        except SMTPException as e:
            logger.warning("Failed to send otp to: %s %s", e)
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

def set_otp_nx(id: int, otp: str, ttl: int = 300) -> bool:
    """
    Store OTP with a time-to-live (default 5 minutes).
    """
    key = f"otp:{id}"
    result = mfa_redis.set(key, otp, ex= ttl, nx= True)
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