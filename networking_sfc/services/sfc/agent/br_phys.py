# Copyright 2015 Huawei.  All rights reserved.
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

"""
* references
** OVS agent https://wiki.openstack.org/wiki/Ovs-flow-logic
"""
from networking_sfc.services.sfc.common import ovs_ext_lib
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import (
    br_phys)


class OVSPhysicalBridge(br_phys.OVSPhysicalBridge, ovs_ext_lib.OVSBridgeExt):
    def setup_controllers(self, conf):
        self.set_protocols("[]")
        self.del_controller()

    def mod_flow(self, **kwargs):
        ovs_ext_lib.OVSBridgeExt.mod_flow(self, **kwargs)

    def run_ofctl(self, cmd, args, process_input=None):
        return ovs_ext_lib.OVSBridgeExt.run_ofctl(
            self, cmd, args, process_input=process_input)
