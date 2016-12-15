# Copyright 2015 Futurewei.  All rights reserved.
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

"""Defining Port Chain data-model.

Revision ID: c3e178d4a985
Revises: 9768e6a66c9
Create Date: 2015-09-11 11:37:19.349951

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c3e178d4a985'
down_revision = '9768e6a66c9'


def upgrade():
    op.create_table(
        'sfc_port_pair_groups',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tenant_id', sa.String(length=255),
                  nullable=True, index=True),
        sa.Column('name', sa.String(length=255),
                  nullable=True),
        sa.Column('description', sa.String(length=255),
                  nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'sfc_port_pairs',
        sa.Column('tenant_id', sa.String(length=255),
                  nullable=True, index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('description', sa.String(length=255),
                  nullable=True),
        sa.Column('ingress', sa.String(length=36), nullable=False),
        sa.Column('egress', sa.String(length=36), nullable=False),
        sa.Column('portpairgroup_id', sa.String(length=36), nullable=True),
        sa.ForeignKeyConstraint(['egress'], ['ports.id'],
                                ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['ingress'], ['ports.id'],
                                ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['portpairgroup_id'],
                                ['sfc_port_pair_groups.id'],
                                ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ingress', 'egress',
                            name='uniq_sfc_port_pairs0ingress0egress')
    )

    op.create_table(
        'sfc_port_chains',
        sa.Column('tenant_id', sa.String(length=255),
                  nullable=True, index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255),
                  nullable=True),
        sa.Column('description', sa.String(length=255),
                  nullable=True),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'sfc_chain_group_associations',
        sa.Column('portpairgroup_id', sa.String(length=36), nullable=False),
        sa.Column('portchain_id', sa.String(length=36), nullable=False),
        sa.Column('position', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['portchain_id'], ['sfc_port_chains.id'], ),
        sa.ForeignKeyConstraint(['portpairgroup_id'],
                                ['sfc_port_pair_groups.id'],
                                ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('portpairgroup_id', 'portchain_id')
    )

    op.create_table(
        'sfc_port_chain_parameters',
        sa.Column('keyword', sa.String(length=255), nullable=False),
        sa.Column('value', sa.String(length=255), nullable=True),
        sa.Column('chain_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['chain_id'], ['sfc_port_chains.id'], ),
        sa.PrimaryKeyConstraint('keyword', 'chain_id')
    )

    op.create_table(
        'sfc_service_function_params',
        sa.Column('keyword', sa.String(length=255), nullable=False),
        sa.Column('value', sa.String(length=255), nullable=True),
        sa.Column('pair_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['pair_id'], ['sfc_port_pairs.id'], ),
        sa.PrimaryKeyConstraint('keyword', 'pair_id')
    )

    op.create_table(
        'sfc_chain_classifier_associations',
        sa.Column('flowclassifier_id', sa.String(length=36), nullable=False),
        sa.Column('portchain_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['flowclassifier_id'],
                                ['sfc_flow_classifiers.id'],
                                ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['portchain_id'], ['sfc_port_chains.id'], ),
        sa.PrimaryKeyConstraint('flowclassifier_id', 'portchain_id'),
        sa.UniqueConstraint('flowclassifier_id')
    )
