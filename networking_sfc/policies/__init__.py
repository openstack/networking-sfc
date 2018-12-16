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

import itertools

from networking_sfc.policies import flow_classifier
from networking_sfc.policies import port_chain
from networking_sfc.policies import port_pair
from networking_sfc.policies import port_pair_group
from networking_sfc.policies import service_graph


def list_rules():
    return itertools.chain(
        flow_classifier.list_rules(),
        port_chain.list_rules(),
        port_pair_group.list_rules(),
        port_pair.list_rules(),
        service_graph.list_rules(),
    )
