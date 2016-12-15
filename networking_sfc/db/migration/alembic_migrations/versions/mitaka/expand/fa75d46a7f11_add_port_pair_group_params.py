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

"""add_port_pair_group_params

Revision ID: fa75d46a7f11
Revises: d1002a1f97f6
Create Date: 2016-07-03 10:15:29.371910

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'fa75d46a7f11'
down_revision = 'd1002a1f97f6'


def upgrade():
    op.create_table('sfc_port_pair_group_params',
                    sa.Column('keyword', sa.String(length=255),
                              nullable=False),
                    sa.Column('value', sa.String(length=255),
                              nullable=True),
                    sa.Column('pair_group_id', sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['pair_group_id'],
                                            ['sfc_port_pair_groups.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('keyword', 'pair_group_id'),
                    mysql_engine='InnoDB'
                    )
    op.add_column('sfc_port_chains', sa.Column('chain_id',
                  sa.Integer(), nullable=False))
    op.create_unique_constraint(None, 'sfc_port_chains', ['chain_id'])
    op.add_column('sfc_port_pair_groups', sa.Column('group_id',
                  sa.Integer(), nullable=False))
    op.create_unique_constraint(None, 'sfc_port_pair_groups', ['group_id'])
