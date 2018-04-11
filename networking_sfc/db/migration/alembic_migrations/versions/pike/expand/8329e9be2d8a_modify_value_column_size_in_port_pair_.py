# Copyright 2015 Futurewei. All rights reserved.
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

"""modify_value_column_size_in_port_pair_group_params

Revision ID: 8329e9be2d8a
Revises: 61832141fb82
Create Date: 2017-04-19 15:13:29.833652

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '8329e9be2d8a'
down_revision = '61832141fb82'


def upgrade():
    op.alter_column('sfc_port_pair_group_params', 'value',
                    existing_type=sa.String(255), type_=sa.String(1024))
