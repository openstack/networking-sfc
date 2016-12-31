# Copyright 2016 Futurewei. All rights reserved.
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

"""update flow classifier

Revision ID: d1002a1f97f6
Revises: 5a475fc853e6
Create Date: 2016-06-03 10:23:52.850934

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd1002a1f97f6'
down_revision = '5a475fc853e6'


def upgrade():
    op.alter_column('sfc_flow_classifiers', 'logical_source_port',
                    nullable=True, existing_type=sa.String(length=36),
                    existing_nullable=False)
