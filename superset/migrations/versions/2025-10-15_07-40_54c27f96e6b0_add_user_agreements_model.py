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
"""add_user_agreements_model

Revision ID: 54c27f96e6b0
Revises: 4b85906e5b91
Create Date: 2025-10-15 07:40:38.799692

"""

# revision identifiers, used by Alembic.
revision = '54c27f96e6b0'
down_revision = '4b85906e5b91'

from alembic import op
import sqlalchemy as sa

def upgrade():
    op.create_table(
        'ab_user_extended',
        sa.Column('id', sa.Integer(), sa.ForeignKey('ab_user.id', ondelete="CASCADE"), primary_key=True),
        sa.Column('tou_accepted', sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column('pp_accepted', sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column('tou_accepted_on', sa.DateTime(), nullable=True),
        sa.Column('pp_accepted_on', sa.DateTime(), nullable=True),
        sa.Column('tou_version', sa.Numeric(4, 2), nullable=True),
        sa.Column('pp_version', sa.Numeric(4, 2), nullable=True),
    )
    conn = op.get_bind()
    conn.execute("""
        INSERT INTO ab_user_extended (id, tou_accepted, pp_accepted, tou_accepted_on, pp_accepted_on, tou_version, pp_version)
        SELECT id, false, false, NULL, NULL, NULL, NULL
        FROM ab_user
        WHERE id NOT IN (SELECT id FROM ab_user_extended)
    """)

def downgrade():
    op.drop_table('ab_user_extended')