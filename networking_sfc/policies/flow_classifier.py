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
        'create_flow_classifier',
        base.RULE_ANY,
        'Create a flow classifier',
        [
            {
                'method': 'POST',
                'path': '/sfc/flow_classifiers',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'update_flow_classifier',
        base.RULE_ADMIN_OR_OWNER,
        'Update a flow classifier',
        [
            {
                'method': 'PUT',
                'path': '/sfc/flow_classifiers/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'delete_flow_classifier',
        base.RULE_ADMIN_OR_OWNER,
        'Delete a flow classifier',
        [
            {
                'method': 'DELETE',
                'path': '/sfc/flow_classifiers/{id}',
            },
        ]
    ),
    policy.DocumentedRuleDefault(
        'get_flow_classifier',
        base.RULE_ADMIN_OR_OWNER,
        'Get flow classifiers',
        [
            {
                'method': 'GET',
                'path': '/sfc/flow_classifiers',
            },
            {
                'method': 'GET',
                'path': '/sfc/flow_classifiers/{id}',
            },
        ]
    ),
]


def list_rules():
    return rules
