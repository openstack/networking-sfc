# Copyright 2017 Intel Corporation.
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

"""Add Service Graph API resource

Revision ID: 53ed5bec6cff
Revises: 8329e9be2d8a
Create Date: 2017-05-24 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '53ed5bec6cff'
down_revision = '8329e9be2d8a'


def upgrade():
    op.create_table('sfc_service_graphs',
                    sa.Column('project_id',
                              sa.String(length=255),
                              nullable=True),
                    sa.Column('id',
                              sa.String(length=36),
                              nullable=False),
                    sa.Column('name',
                              sa.String(length=255),
                              nullable=True),
                    sa.Column('description',
                              sa.String(length=255),
                              nullable=True),
                    sa.PrimaryKeyConstraint('id'),
                    mysql_engine='InnoDB')
    op.create_index(op.f('ix_sfc_service_graphs_project_id'),
                    'sfc_service_graphs',
                    ['project_id'],
                    unique=False)
    op.create_table('sfc_service_graph_chain_associations',
                    sa.Column('service_graph_id',
                              sa.String(length=36),
                              nullable=False),
                    sa.Column('src_chain',
                              sa.String(length=36),
                              nullable=False),
                    sa.Column('dst_chain',
                              sa.String(length=36),
                              nullable=False),
                    sa.ForeignKeyConstraint(['dst_chain'],
                                            ['sfc_port_chains.id'],
                                            ondelete='RESTRICT'),
                    sa.ForeignKeyConstraint(['service_graph_id'],
                                            ['sfc_service_graphs.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['src_chain'],
                                            ['sfc_port_chains.id'],
                                            ondelete='RESTRICT'),
                    sa.PrimaryKeyConstraint('service_graph_id',
                                            'src_chain',
                                            'dst_chain'),
                    mysql_engine='InnoDB')
