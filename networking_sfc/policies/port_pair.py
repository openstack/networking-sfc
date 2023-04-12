#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

from neutron_lib import policy as base
from oslo_policy import policy


rules = [
    policy.DocumentedRuleDefault(
        'create_port_pair',
        base.RULE_ANY,
        'Create a port pair',
        [
            {
                'method': 'POST',
                'path': '/sfc/port_pairs',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_port_pair',
        base.RULE_ADMIN_OR_OWNER,
        'Update a port pair',
        [
            {
                'method': 'PUT',
                'path': '/sfc/port_pairs/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_port_pair',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a port pair',
        [
            {
                'method': 'DELETE',
                'path': '/sfc/port_pairs/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_port_pair',
        base.RULE_ADMIN_OR_OWNER,
        'Get port pairs',
        [
            {
                'method': 'GET',
                'path': '/sfc/port_pairs',
            },
            {
                'method': 'GET',
                'path': '/sfc/port_pairs/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
