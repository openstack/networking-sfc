# Copyright 2015 Huawei.
# Copyright 2016 Red Hat, Inc.
# Copyright 2017 Intel Corporation.
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

from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.plugins.ml2.drivers.openvswitch.agent import (
    ovs_agent_extension_api as ovs_ext_api)
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import (
    ovs_bridge)

from neutron.tests.unit.plugins.ml2.drivers.openvswitch.agent import (
    ovs_test_base)

from networking_sfc.services.sfc.agent.extensions.openvswitch import sfc_driver
from networking_sfc.services.sfc.common import ovs_ext_lib


class SfcAgentDriverTestCase(ovs_test_base.OVSOFCtlTestBase):
    def _clear_local_entries(self):
        self.executed_cmds = []
        self.node_flowrules = []
        self.added_flows = []
        self.deleted_flows = []
        self.group_mapping = {}
        self.deleted_groups = []
        self.port_mapping = {}

    def setUp(self):
        cfg.CONF.set_override('local_ip', '10.0.0.1', 'OVS')
        super(SfcAgentDriverTestCase, self).setUp()
        self._clear_local_entries()

        self.execute = mock.patch.object(
            utils, "execute", self.mock_execute,
            spec=utils.execute)
        self.execute.start()

        self.set_protocols = mock.patch(
            'neutron.agent.common.ovs_lib.OVSBridge.set_protocols')
        self.set_protocols.start()
        self.add_flow = mock.patch(
            "neutron.agent.common.ovs_lib.OVSBridge.add_flow",
            self.mock_add_flow
        )
        self.add_flow.start()
        self.delete_flows = mock.patch(
            "neutron.agent.common.ovs_lib.OVSBridge.delete_flows",
            self.mock_delete_flows
        )
        self.delete_flows.start()

        self.int_patch = 1
        self.tun_patch = 2
        self.default_port_mapping = {
            'patch-int': {
                'ofport': self.int_patch
            },
            'patch-tun': {
                'ofport': self.tun_patch
            }
        }
        self.get_vif_port_by_id = mock.patch.object(
            ovs_lib.OVSBridge, "get_vif_port_by_id",
            self.mock_get_vif_port_by_id
        )
        self.get_vif_port_by_id.start()
        self.get_vlan_by_port = mock.patch.object(
            sfc_driver.SfcOVSAgentDriver, "_get_vlan_by_port",
            self.mock_get_vlan_by_port
        )
        self.get_vlan_by_port.start()
        self.get_port_ofport = mock.patch.object(
            ovs_lib.OVSBridge, "get_port_ofport",
            self.mock_get_port_ofport
        )
        self.get_port_ofport.start()
        self.set_secure_mode = mock.patch.object(
            ovs_lib.OVSBridge, "set_secure_mode",
            self.mock_set_secure_mode
        )
        self.set_secure_mode.start()

        self.del_controller = mock.patch.object(
            ovs_lib.OVSBridge, "del_controller",
            self.mock_del_controller
        )
        self.del_controller.start()
        self.get_bridges = mock.patch.object(
            ovs_lib.BaseOVS, "get_bridges",
            self.mock_get_bridges
        )
        self.get_bridges.start()
        self.get_vif_ports = mock.patch.object(
            ovs_lib.OVSBridge, "get_vif_ports",
            self.mock_get_vif_ports
        )
        self.get_vif_ports.start()
        self.get_ports_attributes = mock.patch.object(
            ovs_lib.OVSBridge, "get_ports_attributes",
            self.mock_get_ports_attributes
        )
        self.get_ports_attributes.start()
        self.delete_port = mock.patch.object(
            ovs_lib.OVSBridge, "delete_port",
            self.mock_delete_port
        )
        self.delete_port.start()
        self.create = mock.patch.object(
            ovs_lib.OVSBridge, "create",
            self.mock_create
        )
        self.create.start()
        self.add_port = mock.patch.object(
            ovs_lib.OVSBridge, "add_port",
            self.mock_add_port
        )
        self.add_port.start()
        self.bridge_exists = mock.patch.object(
            ovs_lib.BaseOVS, "bridge_exists",
            self.mock_bridge_exists
        )
        self.bridge_exists.start()
        self.port_exists = mock.patch.object(
            ovs_lib.BaseOVS, "port_exists",
            self.mock_port_exists
        )
        self.port_exists.start()
        self.capabilities = mock.patch.object(
            ovs_lib.BaseOVS, "capabilities",
            self.mock_capabilities
        )
        self.capabilities.start()
        self.apply_flows = mock.patch.object(
            ovs_lib.DeferredOVSBridge, "apply_flows",
            self.mock_apply_flows
        )
        self.apply_flows.start()

        self.dump_group_for_id = mock.patch.object(
            ovs_ext_lib.SfcOVSBridgeExt, "dump_group_for_id",
            self.mock_dump_group_for_id
        )
        self.dump_group_for_id.start()
        self.add_group = mock.patch.object(
            ovs_ext_lib.SfcOVSBridgeExt, "add_group",
            self.mock_add_group
        )
        self.add_group.start()
        self.mod_group = mock.patch.object(
            ovs_ext_lib.SfcOVSBridgeExt, "mod_group",
            self.mock_mod_group
        )
        self.mod_group.start()
        self.delete_group = mock.patch.object(
            ovs_ext_lib.SfcOVSBridgeExt, "delete_group",
            self.mock_delete_group
        )
        self.delete_group.start()

        self.sfc_driver = sfc_driver.SfcOVSAgentDriver()
        self.agent_api = ovs_ext_api.OVSAgentExtensionAPI(
            ovs_bridge.OVSAgentBridge('br-int'),
            ovs_bridge.OVSAgentBridge('br-tun'))
        self.sfc_driver.consume_api(self.agent_api)
        self.sfc_driver.initialize()

        self._clear_local_entries()

    def mock_delete_group(self, group_id):
        if group_id == 'all':
            self.group_mapping = {}
        else:
            if group_id in self.group_mapping:
                del self.group_mapping[group_id]
        self.deleted_groups.append(group_id)

    def mock_mod_group(self, group_id, **kwargs):
        kwargs['group_id'] = group_id
        self.group_mapping[group_id] = kwargs

    def mock_add_group(self, group_id, **kwargs):
        kwargs['group_id'] = group_id
        self.group_mapping[group_id] = kwargs

    def mock_dump_group_for_id(self, group_id):
        if group_id in self.group_mapping:
            group_list = []
            group = self.group_mapping[group_id]
            for group_key, group_value in group.items():
                group_list.append('%s=%s' % (group_key, group_value))
            return ' '.join(group_list)
        else:
            return ''

    def mock_set_secure_mode(self):
        pass

    def mock_del_controller(self):
        pass

    def mock_get_bridges(self):
        return ['br-int', 'br-tun']

    def mock_get_port_ofport(self, port_name):
        for port_id, port_values in self.port_mapping.items():
            if port_values['port_name'] == port_name:
                return port_values['ofport']
        if port_name in self.default_port_mapping:
            return self.default_port_mapping[port_name]['ofport']
        return ovs_lib.INVALID_OFPORT

    def mock_add_port(self, port_name, *interface_attr_tuples):
        return self.mock_get_port_ofport(port_name)

    def mock_bridge_exists(self, bridge_name):
        return True

    def mock_port_exists(self, port_name):
        return True

    def mock_capabilities(self):
        return {'datapath_types': [], 'iface_types': []}

    def mock_apply_flows(self):
        pass

    def mock_get_vif_port_by_id(self, port_id):
        if port_id in self.port_mapping:
            port_values = self.port_mapping[port_id]
            return ovs_lib.VifPort(
                port_values['port_name'],
                port_values['ofport'],
                port_id,
                port_values['vif_mac'],
                self.sfc_driver.br_int
            )

    def mock_get_vlan_by_port(self, port_id):
        return 0

    def mock_get_vif_ports(self, ofport_filter):
        vif_ports = []
        for port_id, port_values in self.port_mapping.items():
            vif_ports.append(
                ovs_lib.VifPort(
                    port_values['port_name'],
                    port_values['ofport'],
                    port_id,
                    port_values['vif_mac'],
                    self.sfc_driver.br_int
                )
            )
        return vif_ports

    def mock_get_ports_attributes(
        self, table, columns=None, ports=None,
        check_error=True, log_errors=True,
        if_exists=False
    ):
        port_infos = []
        for port_id, port_values in self.port_mapping.items():
            port_info = {}
            if columns:
                if 'name' in columns:
                    port_info['name'] = port_values['port_name']
                if 'ofport' in columns:
                    port_info['ofport'] = port_values['ofport']
                if 'extenal_ids' in columns:
                    port_info['extenal_ids'] = {
                        'iface-id': port_id,
                        'attached-mac': port_values['vif_mac']
                    }
                if 'other_config' in columns:
                    port_info['other_config'] = {}
                if 'tag' in columns:
                    port_info['tag'] = []
            else:
                port_info = {
                    'name': port_values['port_name'],
                    'ofport': port_values['ofport'],
                    'extenal_ids': {
                        'iface-id': port_id,
                        'attached-mac': port_values['vif_mac']
                    },
                    'other_config': {},
                    'tag': []
                }
            if ports:
                if port_values['port_name'] in ports:
                    port_infos.append(port_info)
            else:
                port_infos.append(port_info)
        return port_infos

    def mock_delete_port(self, port_name):
        found_port_id = None
        for port_id, port_values in self.port_mapping.items():
            if port_values['port_name'] == port_name:
                found_port_id = port_id
        if found_port_id:
            del self.port_mapping[found_port_id]

    def mock_create(self, secure_mode=False):
        pass

    def mock_add_flow(self, *args, **kwargs):
        if kwargs not in self.added_flows:
            self.added_flows.append(kwargs)

    def mock_delete_flows(self, *args, **kwargs):
        if kwargs not in self.deleted_flows:
            self.deleted_flows.append(kwargs)

    def mock_get_flowrules_by_host_portid(self, context, port_id):
        return [
            flowrule
            for flowrule in self.node_flowrules
            if (
                flowrule['ingress'] == port_id or
                flowrule['egress'] == port_id
            )
        ]

    def mock_get_all_src_node_flowrules(self, context):
        return [
            flowrule
            for flowrule in self.node_flowrules
            if (
                flowrule['node_type'] == 'src_node' and
                flowrule['egress'] is None
            )
        ]

    def mock_execute(self, cmd, *args, **kwargs):
        self.executed_cmds.append(' '.join(cmd))

    def tearDown(self):
        self.execute.stop()
        self.set_protocols.stop()
        self.add_flow.stop()
        self.delete_flows.stop()
        self.get_vif_port_by_id.stop()
        self.get_vlan_by_port.stop()
        self.get_port_ofport.stop()
        self.set_secure_mode.stop()
        self.del_controller.stop()
        self.get_bridges.stop()
        self.get_vif_ports.stop()
        self.get_ports_attributes.stop()
        self.delete_port.stop()
        self.create.stop()
        self.add_port.stop()
        self.bridge_exists.stop()
        self.port_exists.stop()
        self.capabilities.stop()
        self.apply_flows.stop()
        self.dump_group_for_id.stop()
        self.add_group.stop()
        self.mod_group.stop()
        self.delete_group.stop()
        self._clear_local_entries()
        super(SfcAgentDriverTestCase, self).tearDown()

    def _prepare_update_flow_rules_sf_node_empty_next_hops(self, pc_corr,
                                                           pp_corr):
        self.port_mapping = {
            'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 254,
                'ingress': u'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579',
                'next_hops': None,
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': u'2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_group_id': None,
                'nsp': 256,
                'add_fcs': [],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )

    def test_update_flow_rules_sf_node_empty_next_hops(self):
        self._prepare_update_flow_rules_sf_node_empty_next_hops('mpls', None)
        self.assertEqual(
            [],
            self.executed_cmds
        )
        self.assertEqual(
            [{
                'actions': 'strip_vlan, pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65791,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {},
            self.group_mapping
        )

    def test_update_flow_rules_sf_node_empty_next_hops_no_proxy(self):
        self._prepare_update_flow_rules_sf_node_empty_next_hops('mpls', 'mpls')
        self.assertEqual(
            [],
            self.executed_cmds
        )
        self.assertEqual(
            [{
                'actions': 'strip_vlan, output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65791,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {},
            self.group_mapping
        )

    def test_update_flow_rules_src_node_empty_next_hops(self):
        self.port_mapping = {
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 254,
                'ingress': None,
                'next_hops': None,
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'src_node',
                'egress': u'2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_group_id': None,
                'nsp': 256,
                'add_fcs': [],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )
        self.assertEqual(
            [],
            self.added_flows
        )
        self.assertEqual(
            {},
            self.group_mapping
        )

    def _prepare_update_flow_rules_src_node_empty_next_hops_a_d(self,
                                                                pc_corr,
                                                                pp_corr):
        self.port_mapping = {
            '9bedd01e-c216-4dfd-b48e-fbd5c8212ba4': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }

        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 255,
                'ingress': None,
                'next_hops': None,
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 100,
                }],
                'group_refcnt': 1,
                'node_type': 'src_node',
                'egress': u'9bedd01e-c216-4dfd-b48e-fbd5c8212ba4',
                'next_group_id': None,
                'nsp': 256,
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 100,
                }],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def _test_update_flow_rules_src_empty_next_hops_a_d(self, pc_corr):
        self._prepare_update_flow_rules_src_node_empty_next_hops_a_d(
            pc_corr, None)
        self.assertEqual(
            [{
                'actions': 'normal',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }],
            self.added_flows
        )
        self.assertEqual(
            [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff',
                'strict': True,
            }],
            self.deleted_flows
        )
        self.assertEqual(
            {},
            self.group_mapping
        )

    def test_update_flow_rules_src_node_empty_next_hops_add_fcs_del_fcs(self):
        self._test_update_flow_rules_src_empty_next_hops_a_d('mpls')

    def test_update_flow_rules_src_node_empty_next_hops_a_d_no_proxy(self):
        self._prepare_update_flow_rules_src_node_empty_next_hops_a_d(
            'mpls', 'mpls')
        self.assertEqual(
            [{
                'actions': 'normal',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }],
            self.added_flows
        )
        self.assertEqual(
            [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff',
                'strict': True,
            }],
            self.deleted_flows
        )
        self.assertEqual(
            {},
            self.group_mapping
        )

    def _prepare_update_flow_rules_sf_node_empty_next_hops_a_d(self, pc_corr,
                                                               pp_corr):
        self.port_mapping = {
            '9bedd01e-c216-4dfd-b48e-fbd5c8212ba4': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }

        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 255,
                'ingress': '2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_hops': None,
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 100,
                }],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': u'9bedd01e-c216-4dfd-b48e-fbd5c8212ba4',
                'next_group_id': None,
                'nsp': 256,
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 100,
                }],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def test_update_flow_rules_sf_node_empty_next_hops_add_fcs_del_fcs(self):
        self._prepare_update_flow_rules_sf_node_empty_next_hops_a_d(
            'mpls', None)
        self.assertEqual(
            [],
            self.executed_cmds
        )
        self.assertEqual(
            [{
                'actions': 'normal',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': 'strip_vlan, pop_mpls:0x0800,output:42',
                'dl_dst': '00:01:02:03:06:08',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff',
                'strict': True,
            }],
            self.deleted_flows
        )
        self.assertEqual(
            {},
            self.group_mapping
        )

    def test_update_flow_rules_sf_node_empty_next_hops_a_d_no_proxy(self):
        # this test exercises the last SF_NODE in a chain with encapsulation
        self._prepare_update_flow_rules_sf_node_empty_next_hops_a_d(
            'mpls', 'mpls')
        self.assertEqual(
            [{
                'actions': 'pop_mpls:0x0800,normal',
                'dl_type': 34887,
                'in_port': 42,
                'mpls_label': 65791,
                'priority': 30,
                'table': 0
            }, {
                'actions': 'strip_vlan, output:42',
                'dl_dst': '00:01:02:03:06:08',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            [{
                'dl_type': 34887,
                'in_port': 42,
                'mpls_label': 65791,
                'priority': 30,
                'table': 0,
                'strict': True,
            }],
            self.deleted_flows
        )
        self.assertEqual(
            {},
            self.group_mapping
        )

    def _prepare_update_flow_rules_src_node_next_hops_add_fcs(self,
                                                              pc_corr,
                                                              pp_corr_nh):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'local_endpoint': '10.0.0.2',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'net_uuid': '8768d2b3-746d-4868-ae0e-e81861c2b4e7',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'in_mac_address': '12:34:56:78:cf:23',
                    'pp_corr': pp_corr_nh
                }],
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'src_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'nsp': 256,
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': None
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def test_update_flow_rules_src_node_next_hops_add_fcs(self):
        self._prepare_update_flow_rules_src_node_next_hops_add_fcs(
            'mpls', None)
        self.assertEqual(
            [{
                'actions': (
                    'push_mpls:0x8847,set_mpls_label:65791,'
                    'set_mpls_ttl:255,mod_vlan_vid:0,,output:2'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 2048,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def test_update_flow_rules_src_node_next_hops_add_fcs_no_proxy(self):
        self._prepare_update_flow_rules_src_node_next_hops_add_fcs(
            'mpls', 'mpls')
        self.assertEqual(
            [{
                'actions': (
                    'mod_vlan_vid:0,,output:2'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'push_mpls:0x8847,set_mpls_label:65791,'
                           'set_mpls_ttl:255,group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def _prepare_update_flow_rules_src_node_next_hops_same_host_a(
            self, pc_corr, pp_corr_nh):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'local_endpoint': '10.0.0.1',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'net_uuid': '8768d2b3-746d-4868-ae0e-e81861c2b4e7',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'in_mac_address': '12:34:56:78:cf:23',
                    'pp_corr': pp_corr_nh
                }],
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'src_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'nsp': 256,
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': None
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def test_update_flow_rules_src_node_next_hops_same_host_add_fcs(self):
        self._prepare_update_flow_rules_src_node_next_hops_same_host_a(
            'mpls', None)
        self.assertEqual(
            [{
                'actions': (
                    'push_mpls:0x8847,set_mpls_label:65791,'
                    'set_mpls_ttl:255,mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 2048,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def test_update_flow_rules_src_node_next_hops_same_host_a_no_proxy(self):
        self._prepare_update_flow_rules_src_node_next_hops_same_host_a(
            'mpls', 'mpls')
        self.assertEqual(
            [{
                'actions': (
                    'mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'push_mpls:0x8847,set_mpls_label:65791,'
                           'set_mpls_ttl:255,group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def _prepare_update_flow_rules_sf_node_next_hops_add_fcs(self,
                                                             pc_corr,
                                                             pp_corr,
                                                             pp_corr_nh):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            },
            '6331a00d-779b-462b-b0e4-6a65aa3164ef': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },

        }
        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 255,
                'ingress': '6331a00d-779b-462b-b0e4-6a65aa3164ef',
                'next_hops': [{
                    'local_endpoint': '10.0.0.2',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'net_uuid': '8768d2b3-746d-4868-ae0e-e81861c2b4e7',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'in_mac_address': '12:34:56:78:cf:23',
                    'pp_corr': pp_corr_nh
                }],
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'nsp': 256,
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def test_update_flow_rules_sf_node_next_hops_add_fcs(self):
        self._prepare_update_flow_rules_sf_node_next_hops_add_fcs('mpls',
                                                                  None,
                                                                  None)
        self.assertEqual(
            [{
                'actions': (
                    'push_mpls:0x8847,set_mpls_label:65791,'
                    'set_mpls_ttl:255,mod_vlan_vid:0,,output:2'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 2048,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': 'strip_vlan, pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def test_update_flow_rules_sf_node_next_hops_add_fcs_nh(self):
        self._prepare_update_flow_rules_sf_node_next_hops_add_fcs('mpls',
                                                                  None,
                                                                  'mpls')
        self.assertEqual(
            [{
                'actions': (
                    'mod_vlan_vid:0,,output:2'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'push_mpls:0x8847,set_mpls_label:65791,'
                           'set_mpls_ttl:255,group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': 'strip_vlan, pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def test_update_flowrules_srcnode_no_nexthops_add_del_fcs_symmetric(self):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'src_port',
                'ofport': 32,
                'vif_mac': '00:01:02:03:05:07',
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        for flow_rule in self.node_flowrules:
            if flow_rule['fwd_path']:
                status = []
                self.agent.update_flow_rules(
                    {
                        'nsi': 255,
                        'ingress': None,
                        'next_hops': None,
                        'del_fcs': [{
                            'source_port_range_min': 100,
                            'destination_ip_prefix': u'10.200.0.0/16',
                            'protocol': u'tcp',
                            'l7_parameters': {},
                            'source_port_range_max': 100,
                            'source_ip_prefix': u'10.100.0.0/16',
                            'destination_port_range_min': 100,
                            'ethertype': u'IPv4',
                            'destination_port_range_max': 100,
                        }],
                        'group_refcnt': 1,
                        'node_type': 'src_node',
                        'egress': u'29e38fb2-a643-43b1-baa8-a86596461cd5',
                        'next_group_id': None,
                        'nsp': 256,
                        'add_fcs': [{
                            'source_port_range_min': 100,
                            'destination_ip_prefix': u'10.200.0.0/16',
                            'protocol': u'tcp',
                            'l7_parameters': {},
                            'source_port_range_max': 100,
                            'source_ip_prefix': u'10.100.0.0/16',
                            'destination_port_range_min': 100,
                            'ethertype': u'IPv4',
                            'destination_port_range_max': 100,
                        }],
                        'id': uuidutils.generate_uuid(),
                        'fwd_path': True
                    },
                    status
                )
                self.assertEqual(
                    [],
                    self.executed_cmds
                )
                self.assertEqual(
                    [{
                        'actions': 'normal',
                        'dl_type': 2048,
                        'in_port': 42,
                        'nw_dst': u'10.200.0.0/16',
                        'nw_proto': 6,
                        'nw_src': u'10.100.0.0/16',
                        'priority': 30,
                        'table': 0,
                        'tp_dst': '0x64/0xffff',
                        'tp_src': '0x64/0xffff'
                    }],
                    self.added_flows
                )
                self.assertEqual(
                    [{
                        'dl_type': 2048,
                        'in_port': 42,
                        'nw_dst': u'10.200.0.0/16',
                        'nw_proto': 6,
                        'nw_src': u'10.100.0.0/16',
                        'table': 0,
                        'tp_dst': '0x64/0xffff',
                        'tp_src': '0x64/0xffff'
                    }],
                    self.deleted_flows
                )
                self.assertEqual(
                    {},
                    self.group_mapping
                )
            else:
                status = []
                self.agent.update_flow_rules(
                    {
                        'nsi': 255,
                        'ingress': None,
                        'next_hops': None,
                        'del_fcs': [{
                            'source_port_range_min': 100,
                            'destination_ip_prefix': u'10.100.0.0/16',
                            'protocol': u'tcp',
                            'l7_parameters': {},
                            'source_port_range_max': 100,
                            'source_ip_prefix': u'10.200.0.0/16',
                            'destination_port_range_min': 100,
                            'ethertype': u'IPv4',
                            'destination_port_range_max': 100,
                        }],
                        'group_refcnt': 1,
                        'node_type': 'src_node',
                        'egress': u'8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                        'next_group_id': None,
                        'nsp': 256,
                        'add_fcs': [{
                            'source_port_range_min': 100,
                            'destination_ip_prefix': u'10.100.0.0/16',
                            'protocol': u'tcp',
                            'l7_parameters': {},
                            'source_port_range_max': 100,
                            'source_ip_prefix': u'10.200.0.0/16',
                            'destination_port_range_min': 100,
                            'ethertype': u'IPv4',
                            'destination_port_range_max': 100,
                        }],
                        'id': uuidutils.generate_uuid(),
                        'fwd_path': False
                    },
                    status
                )
                self.assertEqual(
                    [],
                    self.executed_cmds
                )
                self.assertEqual(
                    [{
                        'actions': 'normal',
                        'dl_type': 2048,
                        'in_port': 32,
                        'nw_dst': u'10.100.0.0/16',
                        'nw_proto': 6,
                        'nw_src': u'10.200.0.0/16',
                        'priority': 30,
                        'table': 0,
                        'tp_dst': '0x64/0xffff',
                        'tp_src': '0x64/0xffff'
                    }],
                    self.added_flows
                )
                self.assertEqual(
                    [{
                        'dl_type': 2048,
                        'in_port': 32,
                        'nw_dst': u'10.100.0.0/16',
                        'nw_proto': 6,
                        'nw_src': u'10.200.0.0/16',
                        'table': 0,
                        'tp_dst': '0x64/0xffff',
                        'tp_src': '0x64/0xffff',
                        'strict': True,
                    }],
                    self.deleted_flows
                )
                self.assertEqual(
                    {},
                    self.group_mapping
                )

    def _test_update_flow_rules_sf_node_next_hops_add_fcs_no_proxy(self,
                                                                   pp_corr_nh):
        self._prepare_update_flow_rules_sf_node_next_hops_add_fcs('mpls',
                                                                  'mpls',
                                                                  pp_corr_nh)
        self.assertEqual(
            [{
                'actions': (
                    'mod_vlan_vid:0,,output:2'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'in_port': 42,
                'mpls_label': 65791,
                'priority': 30,
                'table': 0
            }, {
                'actions': 'strip_vlan, output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def test_update_flow_rules_sf_node_next_hops_add_fcs_no_proxy(self):
        self._test_update_flow_rules_sf_node_next_hops_add_fcs_no_proxy(None)

    def test_update_flow_rules_sf_node_next_hops_add_fcs_no_proxy_nh(self):
        self._test_update_flow_rules_sf_node_next_hops_add_fcs_no_proxy('mpls')

    def _prepare_update_flow_rules_sf_node_next_hops_same_host_add_fcs(
            self, pc_corr, pp_corr, pp_corr_nh):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            },
            '6331a00d-779b-462b-b0e4-6a65aa3164ef': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },

        }
        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 255,
                'ingress': '6331a00d-779b-462b-b0e4-6a65aa3164ef',
                'next_hops': [{
                    'local_endpoint': '10.0.0.1',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'net_uuid': '8768d2b3-746d-4868-ae0e-e81861c2b4e7',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'in_mac_address': '12:34:56:78:cf:23',
                    'pp_corr': pp_corr_nh
                }],
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'nsp': 256,
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'pc_corr': pc_corr,
                'pp_corr': pp_corr,
                'id': uuidutils.generate_uuid(),
                'fwd_path': True
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def test_update_flow_rules_sf_node_next_hops_same_host_add_fcs(self):
        self._prepare_update_flow_rules_sf_node_next_hops_same_host_add_fcs(
            'mpls', None, None)
        self.assertEqual(
            [{
                'actions': (
                    'push_mpls:0x8847,set_mpls_label:65791,set_mpls_ttl:255,'
                    'mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 2048,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': 'strip_vlan, pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def test_update_flow_rules_sf_node_next_hops_same_host_add_fcs_nh(self):
        self._prepare_update_flow_rules_sf_node_next_hops_same_host_add_fcs(
            'mpls', None, 'mpls')
        self.assertEqual(
            [{
                'actions': (
                    'mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'push_mpls:0x8847,set_mpls_label:65791,'
                           'set_mpls_ttl:255,group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': 'strip_vlan, pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def _test_update_flow_rules_sf_node_next_hops_same_h_a_no_proxy(self,
                                                                    pp_c_nh):
        self._prepare_update_flow_rules_sf_node_next_hops_same_host_add_fcs(
            'mpls', 'mpls', pp_c_nh)
        self.assertEqual(
            [{
                'actions': (
                    'mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'in_port': 42,
                'mpls_label': 65791,
                'priority': 30,
                'table': 0
            }, {
                'actions': 'strip_vlan, output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def test_update_flow_rules_sf_node_next_hops_same_h_a_no_proxy(self):
        self._test_update_flow_rules_sf_node_next_hops_same_h_a_no_proxy(None)

    def test_update_flow_rules_sf_node_next_hops_same_h_a_no_proxy_nh(self):
        self._test_update_flow_rules_sf_node_next_hops_same_h_a_no_proxy(
            'mpls'
        )

    def _prepare_update_flow_rules_sf_node_many_hops_all_mpls(self, pp_corr):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '1234d2b3-746d-4868-ae0e-e81861c25678': {
                'port_name': 'port3',
                'ofport': 9,
                'vif_mac': '00:01:02:0a:0b:0c',
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            },
            '6331a00d-779b-462b-b0e4-6a65aa3164ef': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },

        }
        status = []
        self.sfc_driver.update_flow_rules(
            {
                'nsi': 255,
                'ingress': '6331a00d-779b-462b-b0e4-6a65aa3164ef',
                'next_hops': [{
                    'local_endpoint': '10.0.0.1',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'net_uuid': '8768d2b3-746d-4868-ae0e-e81861c2b4e7',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'in_mac_address': '12:34:56:78:cf:23',
                    'pp_corr': 'mpls'
                }, {
                    'local_endpoint': '10.0.0.1',
                    'ingress': '1234d2b3-746d-4868-ae0e-e81861c25678',
                    'weight': 1,
                    'net_uuid': '1234d2b3-746d-4868-ae0e-e81861c25678',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'in_mac_address': '12:34:56:78:ab:cd',
                    'pp_corr': 'mpls'
                }],
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'nsp': 256,
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'pc_corr': 'mpls',
                'pp_corr': pp_corr,
                'id': uuidutils.generate_uuid(),
                'fwd_path': True
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def _assert_update_flow_rules_sf_node_many_hops_no_proxy(self):
        self.assertEqual(
            [{
                'actions': (
                    'mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': (
                    'mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:ab:cd',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'in_port': 42,
                'mpls_label': 65791,
                'priority': 30,
                'table': 0
            }, {
                'actions': 'strip_vlan, output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5),'
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:ab:cd, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def test_update_flow_rules_sf_node_many_hops_all_mpls_no_proxy(self):
        self._prepare_update_flow_rules_sf_node_many_hops_all_mpls('mpls')
        self._assert_update_flow_rules_sf_node_many_hops_no_proxy()

    def test_update_flow_rules_sf_node_many_hops_all_mpls(self):
        self._prepare_update_flow_rules_sf_node_many_hops_all_mpls(None)
        self.assertEqual(
            [{
                'actions': (
                    'mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:cf:23',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': (
                    'mod_vlan_vid:0,,resubmit(,10)'),
                'dl_dst': '12:34:56:78:ab:cd',
                'dl_type': 34887,
                'priority': 0,
                'table': 5
            }, {
                'actions': 'push_mpls:0x8847,set_mpls_label:65791,'
                           'set_mpls_ttl:255,group:1',
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': 'strip_vlan, pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'dl_vlan': 0,
                'mpls_label': 65792,
                'priority': 1,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            {
                1: {
                    'buckets': (
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:cf:23, '
                        'resubmit(,5),'
                        'bucket=weight=1, '
                        'mod_dl_dst:12:34:56:78:ab:cd, '
                        'resubmit(,5)'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            },
            self.group_mapping
        )

    def _prepare_delete_flow_rules_sf_node_empty_del_fcs(self, pc_corr,
                                                         pp_corr):
        self.port_mapping = {
            'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.delete_flow_rule(
            {
                'nsi': 254,
                'ingress': u'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579',
                'next_hops': None,
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': u'2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_group_id': None,
                'nsp': 256,
                'add_fcs': [],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def test_delete_flow_rules_sf_node_empty_del_fcs(self):
        self._prepare_delete_flow_rules_sf_node_empty_del_fcs('mpls', None)
        self.assertEqual(
            [{
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65791,
                'table': 10
            }],
            self.deleted_flows
        )
        self.assertEqual(
            [],
            self.deleted_groups
        )

    def test_delete_flow_rules_sf_node_empty_del_fcs_no_proxy(self):
        self._prepare_delete_flow_rules_sf_node_empty_del_fcs('mpls', 'mpls')
        self.assertEqual(
            [{
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65791,
                'table': 10
            }],
            self.deleted_flows
        )
        self.assertEqual(
            [],
            self.deleted_groups
        )

    def _prepare_delete_flow_rules_src_node_empty_del_fcs(self, pc_corr,
                                                          pp_corr):
        self.port_mapping = {
            'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.delete_flow_rule(
            {
                'nsi': 254,
                'ingress': None,
                'next_hops': None,
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': u'2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_group_id': None,
                'nsp': 256,
                'add_fcs': [],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def _test_delete_flow_rules_src_node_empty_del_fcs(self, pc_corr,
                                                       pp_corr):
        self._prepare_delete_flow_rules_src_node_empty_del_fcs(pc_corr,
                                                               pp_corr)
        self.assertEqual(
            [],
            self.deleted_flows
        )
        self.assertEqual(
            [],
            self.deleted_groups
        )

    def test_delete_flow_rules_src_node_empty_del_fcs(self):
        self._test_delete_flow_rules_src_node_empty_del_fcs('mpls', None)

    def test_delete_flow_rules_src_node_empty_del_fcs_no_proxy(self):
        self._test_delete_flow_rules_src_node_empty_del_fcs('mpls', 'mpls')

    def _prepare_delete_flow_rules_sf_node_del_fcs(self, pc_corr,
                                                   pp_corr):
        self.port_mapping = {
            'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.delete_flow_rule(
            {
                'nsi': 254,
                'ingress': u'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579',
                'next_hops': None,
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': u'2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_group_id': None,
                'nsp': 256,
                'add_fcs': [],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def test_delete_flow_rules_sf_node_del_fcs(self):
        self._prepare_delete_flow_rules_sf_node_del_fcs('mpls', None)
        self.assertEqual(
            [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff',
                'strict': True,
            }, {
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65791,
                'table': 10
            }],
            self.deleted_flows
        )
        self.assertEqual(
            [],
            self.deleted_groups
        )

    def test_delete_flow_rules_sf_node_del_fcs_no_proxy(self):
        self._prepare_delete_flow_rules_sf_node_del_fcs('mpls', 'mpls')
        self.assertEqual(
            [{
                'dl_type': 34887,
                'in_port': 42,
                'mpls_label': 65790,
                'priority': 30,
                'table': 0,
                'strict': True,
            }, {
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65791,
                'table': 10
            }],
            self.deleted_flows
        )
        self.assertEqual(
            [],
            self.deleted_groups
        )

    def _prepare_delete_flow_rules_src_node_del_fcs(self, pc_corr,
                                                    pp_corr):
        self.port_mapping = {
            'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.delete_flow_rule(
            {
                'nsi': 254,
                'ingress': None,
                'next_hops': None,
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'group_refcnt': 1,
                'node_type': 'src_node',
                'egress': u'2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_group_id': None,
                'nsp': 256,
                'add_fcs': [],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def _test_delete_flow_rules_src_node_del_fcs(self, pc_corr, pp_corr):
        self._prepare_delete_flow_rules_src_node_del_fcs(pc_corr,
                                                         pp_corr)
        self.assertEqual(
            [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff',
                'strict': True,
            }],
            self.deleted_flows
        )
        self.assertEqual(
            [],
            self.deleted_groups
        )

    def test_delete_flow_rules_src_node_del_fcs(self):
        self._test_delete_flow_rules_src_node_del_fcs('mpls', None)

    def test_delete_flow_rules_src_node_del_fcs_no_proxy(self):
        self._test_delete_flow_rules_src_node_del_fcs('mpls', 'mpls')

    def _prepare_delete_flow_rules_src_node_next_hops_del_fcs(self,
                                                              pc_corr,
                                                              pp_corr,
                                                              pp_corr_nh):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.delete_flow_rule(
            {
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'net_uuid': '8768d2b3-746d-4868-ae0e-e81861c2b4e7',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'local_endpoint': '10.0.0.2',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'in_mac_address': '12:34:56:78:cf:23',
                    'pp_corr': pp_corr_nh
                }],
                'add_fcs': [],
                'group_refcnt': 1,
                'node_type': 'src_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'nsp': 256,
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def _test_delete_flow_rules_src_node_next_hops_del_fcs(self,
                                                           pc_corr,
                                                           pp_corr,
                                                           pp_corr_nh):
        self._prepare_delete_flow_rules_src_node_next_hops_del_fcs(pc_corr,
                                                                   pp_corr,
                                                                   pp_corr_nh)
        self.assertEqual(
            [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff',
                'strict': True,
            }, {
                'dl_dst': '12:34:56:78:cf:23',
                'table': 5
            }],
            self.deleted_flows
        )
        self.assertEqual(
            [1],
            self.deleted_groups
        )

    def test_delete_flow_rules_src_node_next_hops_del_fcs(self):
        self._test_delete_flow_rules_src_node_next_hops_del_fcs('mpls',
                                                                None, None)

    def test_delete_flow_rules_src_node_next_hops_del_fcs_no_proxy(self):
        self._test_delete_flow_rules_src_node_next_hops_del_fcs('mpls',
                                                                'mpls', None)

    def test_delete_flow_rules_src_node_next_hops_del_fcs_nh(self):
        self._test_delete_flow_rules_src_node_next_hops_del_fcs('mpls',
                                                                None, 'mpls')

    def test_delete_flow_rules_src_node_next_hops_del_fcs_no_proxy_nh(self):
        self._test_delete_flow_rules_src_node_next_hops_del_fcs('mpls',
                                                                'mpls', 'mpls')

    def _prepare_delete_flow_rules_sf_node_next_hops_del_fcs(self,
                                                             pc_corr,
                                                             pp_corr,
                                                             pp_corr_nh):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07',
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08',
            }
        }
        status = []
        self.sfc_driver.delete_flow_rule(
            {
                'nsi': 255,
                'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                'next_hops': [{
                    'net_uuid': '8768d2b3-746d-4868-ae0e-e81861c2b4e7',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'local_endpoint': '10.0.0.2',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'in_mac_address': '12:34:56:78:cf:23',
                    'pp_corr': pp_corr_nh
                }],
                'add_fcs': [],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'nsp': 256,
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'id': uuidutils.generate_uuid(),
                'fwd_path': True,
                'pc_corr': pc_corr,
                'pp_corr': pp_corr
            },
            status
        )
        self.assertEqual(
            [],
            self.executed_cmds
        )

    def _test_delete_flow_rules_sf_node_next_hops_del_fcs(self, pp_corr_nh):
        self._prepare_delete_flow_rules_sf_node_next_hops_del_fcs('mpls',
                                                                  None,
                                                                  pp_corr_nh)
        self.assertEqual(
            [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'priority': 30,
                'table': 0,
                'tp_dst': '0x64/0xffff',
                'tp_src': '0x64/0xffff',
                'strict': True,
            }, {
                'dl_dst': '12:34:56:78:cf:23',
                'table': 5
            }, {
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65792,
                'table': 10
            }],
            self.deleted_flows
        )
        self.assertEqual(
            [1],
            self.deleted_groups
        )

    def test_delete_flow_rules_sf_node_next_hops_del_fcs(self):
        self._test_delete_flow_rules_sf_node_next_hops_del_fcs(None)

    def test_delete_flow_rules_sf_node_next_hops_del_fcs_nh(self):
        self._test_delete_flow_rules_sf_node_next_hops_del_fcs('mpls')

    def _test_delete_flow_rules_sf_node_next_hops_del_fcs_no_proxy(self,
                                                                   pp_corr_nh):
        self._prepare_delete_flow_rules_sf_node_next_hops_del_fcs('mpls',
                                                                  'mpls',
                                                                  pp_corr_nh)
        self.assertEqual(
            [{
                'dl_type': 34887,
                'mpls_label': 65791,
                'in_port': 42,
                'priority': 30,
                'table': 0,
                'strict': True,
            }, {
                'dl_dst': '12:34:56:78:cf:23',
                'table': 5
            }, {
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65792,
                'table': 10
            }],
            self.deleted_flows
        )
        self.assertEqual(
            [1],
            self.deleted_groups
        )

    def test_delete_flow_rules_sf_node_next_hops_del_fcs_no_proxy(self):
        self._test_delete_flow_rules_sf_node_next_hops_del_fcs_no_proxy(None)

    def test_delete_flow_rules_sf_node_next_hops_del_fcs_no_proxy_nh(self):
        self._test_delete_flow_rules_sf_node_next_hops_del_fcs_no_proxy('mpls')

    def test_init_agent_empty_flowrules(self):
        # in setUp we call _clear_local_entries() so whatever was done
        # during initialize() is lost ; here, we really want to check the
        # _clear_sfc_flow_on_int_br done at initialize
        self.sfc_driver._clear_sfc_flow_on_int_br()
        self.assertEqual(
            [{
                'actions': 'resubmit(,10)',
                'eth_type': 34887,
                'priority': 20,
                'table': 0
            }, {
                'actions': 'drop',
                'priority': 0,
                'table': 10
            }],
            self.added_flows
        )
        self.assertEqual(
            ["all"],
            self.deleted_groups
        )
        self.assertEqual({}, self.group_mapping)
