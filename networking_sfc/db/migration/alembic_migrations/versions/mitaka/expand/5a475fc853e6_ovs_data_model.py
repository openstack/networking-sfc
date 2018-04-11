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

"""Defining OVS data-model

Revision ID: 5a475fc853e6
Revises: c3e178d4a985
Create Date: 2015-09-30 18:00:57.758762

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '5a475fc853e6'
down_revision = 'c3e178d4a985'


def upgrade():
    op.create_table('sfc_portpair_details',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('id', sa.String(length=36),
                              nullable=False),
                    sa.Column('ingress', sa.String(length=36),
                              nullable=True),
                    sa.Column('egress', sa.String(length=36),
                              nullable=True),
                    sa.Column('host_id', sa.String(length=255),
                              nullable=False),
                    sa.Column('mac_address', sa.String(length=32),
                              nullable=False),
                    sa.Column('network_type', sa.String(length=8),
                              nullable=True),
                    sa.Column('segment_id', sa.Integer(),
                              nullable=True),
                    sa.Column('local_endpoint', sa.String(length=64),
                              nullable=False),
                    sa.PrimaryKeyConstraint('id')
                    )

    op.create_index(
        op.f('ix_sfc_portpair_details_tenant_id'),
        'sfc_portpair_details', ['tenant_id'], unique=False
    )
    op.create_table('sfc_uuid_intid_associations',
                    sa.Column('id', sa.String(length=36), nullable=False),
                    sa.Column('uuid', sa.String(length=36), nullable=False),
                    sa.Column('intid', sa.Integer(), nullable=False),
                    sa.Column('type_', sa.String(length=32), nullable=False),
                    sa.PrimaryKeyConstraint('id', 'uuid'),
                    sa.UniqueConstraint('intid')
                    )

    op.create_table('sfc_path_nodes',
                    sa.Column('tenant_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('id', sa.String(length=36),
                              nullable=False),
                    sa.Column('nsp', sa.Integer(),
                              nullable=False),
                    sa.Column('nsi', sa.Integer(),
                              nullable=False),
                    sa.Column('node_type', sa.String(length=32),
                              nullable=True),
                    sa.Column('portchain_id', sa.String(length=255),
                              nullable=True),
                    sa.Column('status', sa.String(length=32),
                              nullable=True),
                    sa.Column('next_group_id', sa.Integer(),
                              nullable=True),
                    sa.Column('next_hop', sa.String(length=512),
                              nullable=True),
                    sa.ForeignKeyConstraint(['portchain_id'],
                                            ['sfc_port_chains.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('id')
                    )
    op.create_index(
        op.f('ix_sfc_path_nodes_tenant_id'),
        'sfc_path_nodes', ['tenant_id'], unique=False
    )

    op.create_table('sfc_path_port_associations',
                    sa.Column('pathnode_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('portpair_id', sa.String(length=36),
                              nullable=False),
                    sa.Column('weight', sa.Integer(),
                              nullable=False),
                    sa.ForeignKeyConstraint(['pathnode_id'],
                                            ['sfc_path_nodes.id'],
                                            ondelete='CASCADE'),
                    sa.ForeignKeyConstraint(['portpair_id'],
                                            ['sfc_portpair_details.id'],
                                            ondelete='CASCADE'),
                    sa.PrimaryKeyConstraint('pathnode_id', 'portpair_id')
                    )
