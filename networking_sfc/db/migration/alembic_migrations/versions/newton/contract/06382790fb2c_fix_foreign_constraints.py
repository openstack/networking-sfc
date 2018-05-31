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

"""fix foreign constraints

Revision ID: 06382790fb2c
Create Date: 2016-08-11 14:45:34.416120

"""

from alembic import op
from sqlalchemy.engine import reflection

from neutron.db import migration

# revision identifiers, used by Alembic.
revision = '06382790fb2c'
down_revision = '010308b06b49'


def upgrade():
    inspector = reflection.Inspector.from_engine(op.get_bind())

    fks_to_cascade = {
        'sfc_flow_classifier_l7_parameters': 'classifier_id',
        'sfc_chain_group_associations': 'portchain_id',
        'sfc_port_chain_parameters': 'chain_id',
        'sfc_service_function_params': 'pair_id',
        'sfc_chain_classifier_associations': 'portchain_id'
    }

    for table, column in fks_to_cascade.items():
        fk_constraints = inspector.get_foreign_keys(table)
        for fk in fk_constraints:
            if column in fk['constrained_columns']:
                fk['options']['ondelete'] = 'CASCADE'
                migration.remove_foreign_keys(table, fk_constraints)
                migration.create_foreign_keys(table, fk_constraints)
