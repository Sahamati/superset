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
from sqlalchemy import Column, Boolean, DateTime, String, Float
from flask_appbuilder import Model
from flask_appbuilder.models.mixins import UserExtensionMixin

from sqlalchemy import event
from superset.extensions import db
from flask_appbuilder.security.sqla.models import User
import logging

logger = logging.getLogger(__name__)

class UserAgreements(UserExtensionMixin, Model):
    __tablename__ = "ab_user_extended"
    __mapper_args__ = {"polymorphic_identity": "ab_user_extended"}

    tou_accepted = Column(Boolean, default=False, nullable=False)
    pp_accepted = Column(Boolean, default=False, nullable=False)

    tou_accepted_on = Column(DateTime, nullable=True)
    pp_accepted_on = Column(DateTime, nullable=True)

    tou_version = Column(Float, nullable=True)
    pp_version = Column(Float, nullable=True)
    
def create_user_agreements(mapper, connection, target):
    """
    SQLAlchemy after_insert hook:
    Automatically create a UserAgreements row whenever a new User is inserted.
    """
    logger.info("Creating UserAgreements row for new user_id=%s", target.id)
    connection.execute(
        UserAgreements.__table__.insert().values(
            id=target.id,
            tou_accepted=False,
            pp_accepted=False,
            tou_version=None,
            pp_version=None,
        )
    )

def delete_user_agreements(mapper, connection, target):
    """
    SQLAlchemy after_delete hook:
    Automatically clean up UserAgreements row when a User is deleted.
    """
    logger.info("Deleting UserAgreements row for user_id=%s", target.id)
    connection.execute(
        UserAgreements.__table__.delete().where(UserAgreements.id == target.id)
    )

# Register listeners explicitly (at import time)
event.listen(User, "after_insert", create_user_agreements)
event.listen(User, "after_delete", delete_user_agreements)