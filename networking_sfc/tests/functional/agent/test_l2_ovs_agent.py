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

import mock

from neutron.plugins.common import constants as p_const
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

    def create_agent(self, create_tunnels=True, ancillary_bridge=None,
                     local_ip='192.168.10.1'):
        if create_tunnels:
            tunnel_types = [p_const.TYPE_VXLAN]
        else:
            tunnel_types = None
        bridge_mappings = ['physnet:%s' % self.br_phys]
        self.config.set_override('tunnel_types', tunnel_types, "AGENT")
        self.config.set_override('polling_interval', 1, "AGENT")
        self.config.set_override('prevent_arp_spoofing', False, "AGENT")
        self.config.set_override('local_ip', local_ip, "OVS")
        self.config.set_override('bridge_mappings', bridge_mappings, "OVS")
        # Physical bridges should be created prior to running
        self._bridge_classes()['br_phys'](self.br_phys).create()
        agent = ovs_agent.OVSSfcAgent(self._bridge_classes(),
                                      self.config)
        self.addCleanup(self.ovs.delete_bridge, self.br_int)
        if tunnel_types:
            self.addCleanup(self.ovs.delete_bridge, self.br_tun)
        self.addCleanup(self.ovs.delete_bridge, self.br_phys)
        agent.sg_agent = mock.Mock()
        agent.ancillary_brs = []
        if ancillary_bridge:
            agent.ancillary_brs.append(ancillary_bridge)
        return agent
