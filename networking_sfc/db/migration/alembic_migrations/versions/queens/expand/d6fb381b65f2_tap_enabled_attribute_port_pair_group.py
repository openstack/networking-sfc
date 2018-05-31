# Copyright (c) 2017 One Convergence Inc
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#

from alembic import op
import sqlalchemy as sa

"""add tap_enabled attribute to port-pair-group

Revision ID: d6fb381b65f2
Revises: a3ad63aa834f
Create Date: 2017-08-03 13:57:59.908621

"""

# revision identifiers, used by Alembic.
revision = 'd6fb381b65f2'
down_revision = '53ed5bec6cff'


def upgrade():
    op.add_column('sfc_port_pair_groups',
                  sa.Column('tap_enabled',
                            sa.Boolean,
                            server_default=sa.sql.false(),
                            nullable=False)
                  )
