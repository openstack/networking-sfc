# Copyright 2017 Futurewei. All rights reserved.
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

"""_add_fwd_path_and_in_mac_column

Revision ID: b3adaf631bab
Revises: fa75d46a7f11
Create Date: 2016-10-27 17:01:16.793173

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b3adaf631bab'
down_revision = 'fa75d46a7f11'


def upgrade():
    op.add_column('sfc_path_nodes', sa.Column('fwd_path', sa.Boolean(),
                                              nullable=False))
    op.add_column('sfc_portpair_details', sa.Column('in_mac_address',
                                                    sa.String(length=32),
                                                    nullable=True))
