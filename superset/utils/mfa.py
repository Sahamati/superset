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

import redis
import os

from typing import Optional
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# otp util
def smtp_send_otp(user_email: str, otp: str) -> None:
        """Send the OTP to the user's email address via SMTP."""
        subject = "Your MFA Code"
        body = f"Your MFA code is: {otp}"
        send_email_smtp(
            to=user_email,
            subject=subject,
            config=current_app.config,
            html_content=body,
        )
        logger.info("Sent MFA code to %s", user_email)
        logger.info("OTP: %s", otp)
        logger.info("Config: %s", current_app.config["SMTP_HOST"])

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

def set_otp(id: int, otp: str, ttl: int = 300) -> None:
    """
    Store OTP with a time-to-live (default 5 minutes).
    """
    key = f"otp:{id}"
    mfa_redis.set(key, ttl, otp, nx=True)  # <--- safe Redis command for OTPs


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

# def get_last_otp_time(id: int) -> Optional[float]:
#     """
#     Retrieve the last OTP generation time for a given user ID.
#     """
#     key = f"otp_time:{id}"
#     timestamp = mfa_redis.get(key)
#     return float(timestamp) if timestamp else None

# def set_last_otp_time(id: int) -> None:
#     """
#     Store the current time as the last OTP generation time.
#     """
#     key = f"otp_time:{id}"
#     mfa_redis.set(key, os.path.getmtime(__file__))  # Using file's mod time as a proxy for current time