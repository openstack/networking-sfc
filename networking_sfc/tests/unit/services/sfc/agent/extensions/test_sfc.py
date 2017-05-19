# Copyright 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import mock

from neutron.plugins.ml2.drivers.openvswitch.agent import (
    ovs_agent_extension_api as ovs_ext_api)
from neutron.plugins.ml2.drivers.openvswitch.agent.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import (
    ovs_bridge)
from neutron.tests import base
from neutron_lib import context

from networking_sfc.services.sfc.agent.extensions import sfc


class SfcAgentExtensionTestCase(base.BaseTestCase):
    def setUp(self):
        super(SfcAgentExtensionTestCase, self).setUp()

        conn_patcher = mock.patch('neutron.agent.ovsdb.impl_idl._connection')
        conn_patcher.start()
        self.addCleanup(conn_patcher.stop)

        self.sfc_ext = sfc.SfcAgentExtension()
        self.context = context.get_admin_context()
        self.connection = mock.Mock()
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
            ovs_bridge.OVSAgentBridge('br-int'),
            ovs_bridge.OVSAgentBridge('br-tun'))
        self.sfc_ext.consume_api(self.agent_api)

        # Don't rely on used driver
        mock.patch(
            'neutron.manager.NeutronManager.load_class_for_provider',
            return_value=lambda: mock.Mock(spec=sfc.SfcAgentDriver)
        ).start()

        self.sfc_ext.initialize(
            self.connection, constants.EXTENSION_DRIVER_TYPE)

    def test_update_empty_flow_rules(self):
        self.sfc_ext.update_flow_rules(self.context, flowrule_entries={})

        self.assertFalse(self.sfc_ext.sfc_driver.update_flow_rules.called)
