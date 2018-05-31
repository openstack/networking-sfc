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

"""add_ppg_n_tuple_mapping_column

Revision ID: 61832141fb82
Revises: 6185f1633a3d
Create Date: 2017-04-10 16:39:58.026839

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '61832141fb82'
down_revision = '6185f1633a3d'


def upgrade():
    op.add_column('sfc_path_nodes', sa.Column('ppg_n_tuple_mapping',
                                              sa.String(1024),
                                              nullable=True))
