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

from neutron.tests.functional.agent import test_l2_ovs_agent

from networking_sfc.services.sfc.agent import agent as ovs_agent
from networking_sfc.services.sfc.agent import br_int
from networking_sfc.services.sfc.agent import br_phys
from networking_sfc.services.sfc.agent import br_tun


class TestOVSAgent(test_l2_ovs_agent.TestOVSAgent):

    def _bridge_classes(self):
        return {
            'br_int': br_int.OVSIntegrationBridge,
            'br_phys': br_phys.OVSPhysicalBridge,
            'br_tun': br_tun.OVSTunnelBridge
        }

    def create_agent(self, create_tunnels=True, ancillary_bridge=None):
        super(TestOVSAgent, self).create_agent(
            create_tunnels=create_tunnels, ancillary_bridge=ancillary_bridge
        )
        agent = ovs_agent.OVSSfcAgent(self._bridge_classes(),
                                      self.config)
        return agent
