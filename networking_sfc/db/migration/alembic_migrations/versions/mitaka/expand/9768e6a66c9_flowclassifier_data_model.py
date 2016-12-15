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

"""Defining flow-classifier data-model

Revision ID: 9768e6a66c9
Revises: 24fc7241aa5
Create Date: 2015-09-30 17:54:35.852573

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '9768e6a66c9'
down_revision = '24fc7241aa5'


def upgrade():
    op.create_table(
        'sfc_flow_classifiers',
        sa.Column('tenant_id', sa.String(length=255),
                  nullable=True, index=True),
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('ethertype', sa.String(length=40), nullable=True),
        sa.Column('protocol', sa.String(length=40), nullable=True),
        sa.Column('description', sa.String(length=255),
                  nullable=True),
        sa.Column('source_port_range_min', sa.Integer(), nullable=True),
        sa.Column('source_port_range_max', sa.Integer(), nullable=True),
        sa.Column('destination_port_range_min', sa.Integer(), nullable=True),
        sa.Column('destination_port_range_max', sa.Integer(), nullable=True),
        sa.Column('source_ip_prefix', sa.String(length=255), nullable=True),
        sa.Column('destination_ip_prefix', sa.String(length=255),
                  nullable=True),
        sa.Column('logical_source_port', sa.String(length=36),
                  nullable=False),
        sa.Column('logical_destination_port', sa.String(length=36),
                  nullable=True),
        sa.ForeignKeyConstraint(['logical_source_port'], ['ports.id'],
                                ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['logical_destination_port'], ['ports.id'],
                                ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_table(
        'sfc_flow_classifier_l7_parameters',
        sa.Column('keyword', sa.String(length=255), nullable=False),
        sa.Column('value', sa.String(length=255), nullable=True),
        sa.Column('classifier_id', sa.String(length=36), nullable=False),
        sa.ForeignKeyConstraint(['classifier_id'],
                                ['sfc_flow_classifiers.id'], ),
        sa.PrimaryKeyConstraint('keyword', 'classifier_id')
    )
