# Copyright (c) 2017 One Convergence Inc. All rights reserved.
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

"""extra attributes for pathnode

Revision ID: a3ad63aa834f
Revises: 8329e9be2d8a
Create Date: 2017-08-03 13:57:59.908621

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a3ad63aa834f'
down_revision = 'd6fb381b65f2'


def upgrade():
    op.add_column('sfc_path_nodes',
                  sa.Column('tap_enabled', sa.Boolean(), nullable=False,
                            server_default=sa.sql.false()))
    op.add_column('sfc_path_nodes',
                  sa.Column('previous_node_id', sa.String(length=36)))
    op.create_foreign_key('node_fk', 'sfc_path_nodes', 'sfc_path_nodes',
                          ['previous_node_id'], ['id'], ondelete='SET NULL')
