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

import mock
import six

from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.agent import rpc as agent_rpc
from neutron import context
from neutron.tests import base

from networking_sfc.services.sfc.agent import (
    ovs_sfc_agent as agent)
from networking_sfc.services.sfc.agent import br_int
from networking_sfc.services.sfc.agent import br_phys
from networking_sfc.services.sfc.agent import br_tun
from networking_sfc.services.sfc.common import ovs_ext_lib


class OVSSfcAgentTestCase(base.BaseTestCase):
    def setUp(self):
        super(OVSSfcAgentTestCase, self).setUp()
        mock.patch(
            'neutron.agent.common.ovs_lib.OVSBridge.get_ports_attributes',
            return_value=[]
        ).start()
        mock.patch(
            'neutron.agent.common.ovs_lib.BaseOVS.config',
            new_callable=mock.PropertyMock,
            return_value={}
        ).start()
        self.executed_cmds = []
        self.node_flowrules = []
        self.backup_plugin_rpc = agent.SfcPluginApi
        self.plugin_rpc = mock.Mock()
        self.plugin_rpc.get_flowrules_by_host_portid = mock.Mock(
            side_effect=self.mock_get_flowrules_by_host_portid
        )
        self.plugin_rpc.get_all_src_node_flowrules = mock.Mock(
            side_effect=self.mock_get_all_src_node_flowrules
        )
        agent.SfcPluginApi = mock.Mock(
            return_value=self.plugin_rpc
        )
        self.create_consumers = mock.patch.object(
            agent_rpc, "create_consumers",
            self.mock_create_consumers
        )
        self.create_consumers.start()
        self.execute = mock.patch.object(
            utils, "execute", self.mock_execute,
            spec=utils.execute)
        self.execute.start()
        self.added_flows = []
        self.add_flow = mock.patch.object(
            ovs_lib.OVSBridge, "add_flow", self.mock_add_flow
        )
        self.add_flow.start()
        self.deleted_flows = []
        self.delete_flows = mock.patch.object(
            ovs_lib.OVSBridge, "delete_flows", self.mock_delete_flows
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
        self.port_mapping = {}
        self.get_vif_port_by_id = mock.patch.object(
            ovs_lib.OVSBridge, "get_vif_port_by_id",
            self.mock_get_vif_port_by_id
        )
        self.get_vif_port_by_id.start()
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
        self.protocols = []
        self.set_protocols = mock.patch.object(
            ovs_lib.OVSBridge, "set_protocols",
            self.mock_set_protocols
        )
        self.set_protocols.start()
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
        self.apply_flows = mock.patch.object(
            ovs_lib.DeferredOVSBridge, "apply_flows",
            self.mock_apply_flows
        )
        self.apply_flows.start()
        self.group_mapping = {}
        self.deleted_groups = []
        self.dump_group_for_id = mock.patch.object(
            ovs_ext_lib.OVSBridgeExt, "dump_group_for_id",
            self.mock_dump_group_for_id
        )
        self.dump_group_for_id.start()
        self.add_group = mock.patch.object(
            ovs_ext_lib.OVSBridgeExt, "add_group",
            self.mock_add_group
        )
        self.add_group.start()
        self.mod_group = mock.patch.object(
            ovs_ext_lib.OVSBridgeExt, "mod_group",
            self.mock_mod_group
        )
        self.mod_group.start()
        self.delete_group = mock.patch.object(
            ovs_ext_lib.OVSBridgeExt, "delete_group",
            self.mock_delete_group
        )
        self.delete_group.start()
        self.local_ip = '10.0.0.1'
        self.bridge_classes = {
            'br_int': br_int.OVSIntegrationBridge,
            'br_phys': br_phys.OVSPhysicalBridge,
            'br_tun': br_tun.OVSTunnelBridge,
        }
        self.context = context.get_admin_context_without_session()
        self.init_agent()

    def init_agent(self):
        self.added_flows = []
        self.deleted_flows = []
        self.group_mapping = {}
        self.deleted_groups = []
        self.agent = agent.OVSSfcAgent(
            self.bridge_classes,
            'br-int',
            'br-tun',
            self.local_ip,
            {},
            2,
            tunnel_types=['gre', 'vxlan']
        )

    def mock_create_consumers(
        self, endpoints, prefix, topic_details, start_listening=True
    ):
        self.added_flows = []
        self.deleted_flows = []
        return mock.Mock()

    def mock_delete_group(self, group_id):
        if group_id == 'all':
            self.group_mapping = {}
        else:
            if group_id in self.group_mapping:
                del self.group_mapping[group_id]
            else:
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
            for group_key, group_value in six.iteritems(group):
                group_list.append('%s=%s' % (group_key, group_value))
            return ' '.join(group_list)
        else:
            return ''

    def mock_set_secure_mode(self):
        pass

    def mock_set_protocols(self, protocols):
        self.protocols = protocols

    def mock_del_controller(self):
        pass

    def mock_get_bridges(self):
        return ['br-int', 'br-tun']

    def mock_get_port_ofport(self, port_name):
        for port_id, port_values in six.iteritems(self.port_mapping):
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
                self.agent.int_br
            )

    def mock_get_vif_ports(self):
        vif_ports = []
        for port_id, port_values in six.iteritems(self.port_mapping):
            vif_ports.append(
                ovs_lib.VifPort(
                    port_values['port_name'],
                    port_values['ofport'],
                    port_id,
                    port_values['vif_mac'],
                    self.agent.int_br
                )
            )
        return vif_ports

    def mock_get_ports_attributes(
        self, table, columns=None, ports=None,
        check_error=True, log_errors=True,
        if_exists=False
    ):
        port_infos = []
        for port_id, port_values in six.iteritems(self.port_mapping):
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
        for port_id, port_values in six.iteritems(self.port_mapping):
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
        agent.SfcPluginApi = self.backup_plugin_rpc
        self.create_consumers.stop()
        self.execute.stop()
        self.add_flow.stop()
        self.delete_flows.stop()
        self.get_vif_port_by_id.stop()
        self.get_port_ofport.stop()
        self.set_secure_mode.stop()
        self.set_protocols.stop()
        self.del_controller.stop()
        self.get_bridges.stop()
        self.get_vif_ports.stop()
        self.get_ports_attributes.stop()
        self.delete_port.stop()
        self.create.stop()
        self.add_port.stop()
        self.bridge_exists.stop()
        self.port_exists.stop()
        self.apply_flows.stop()
        self.dump_group_for_id.stop()
        self.add_group.stop()
        self.mod_group.stop()
        self.delete_group.stop()
        self.node_flowrules = []
        self.added_flows = []
        self.deleted_flows = []
        self.group_mapping = {}
        self.deleted_groups = []
        self.port_mapping = {}
        super(OVSSfcAgentTestCase, self).tearDown()

    def test_update_empty_flow_rules(self):
        self.port_mapping = {
            'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            }
        }
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.added_flows, [{
                'actions': 'resubmit(,%d)' % agent.SF_SELECTOR,
                'dl_type': 34887,
                'priority': agent.PC_DEF_PRI,
                'table': 0
            }, {
                'actions': 'resubmit(,%d)' % agent.FWD_SELECTOR,
                'dl_type': 34887,
                'priority': agent.PC_DEF_PRI
            }, {
                'actions': 'output:%d' % self.int_patch,
                'priority': 0,
                'table': agent.FWD_SELECTOR
            }, {
                'actions': 'resubmit(,%d)' % agent.GRP_SELECTOR,
                'in_port': self.int_patch,
                'priority': agent.PC_DEF_PRI,
                'table': agent.FWD_SELECTOR
            }]
        )
        self.assertEqual(
            self.group_mapping, {}
        )

    def test_update_flow_rules_port_pair(self):
        self.port_mapping = {
            'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            }
        }
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': u'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579',
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 75,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:fd:b2',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_group_id': None,
                'host_id': u'test1',
                'nsp': 256,
                'portchain_id': u'84c1411f-7a94-4b4f-9a8b-ad9607c67c76',
                'add_fcs': [],
                'id': '611bdc42-12b3-4639-8faf-83da4e6403f7'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.added_flows, [{
                'actions': 'resubmit(,%d)' % agent.SF_SELECTOR,
                'dl_type': 34887,
                'priority': agent.PC_DEF_PRI,
                'table': 0
            }, {
                'actions': 'resubmit(,%d)' % agent.FWD_SELECTOR,
                'dl_type': 34887,
                'priority': agent.PC_DEF_PRI
            }, {
                'actions': 'output:%d' % self.int_patch,
                'priority': 0,
                'table': agent.FWD_SELECTOR
            }, {
                'actions': 'resubmit(,%d)' % agent.GRP_SELECTOR,
                'in_port': self.int_patch,
                'priority': agent.PC_DEF_PRI,
                'table': agent.FWD_SELECTOR
            }, {
                'actions': 'pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': agent.SF_SELECTOR
            }]
        )
        self.assertEqual(
            self.group_mapping, {}
        )

    def test_update_flow_rules_flow_classifiers(self):
        self.port_mapping = {
            'e1229670-2a07-450d-bdc9-34e71c301206': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '9bedd01e-c216-4dfd-b48e-fbd5c8212ba4': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            }
        }

        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 255,
                'ingress': None,
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 43,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:72:05',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'src_node',
                'egress': u'9bedd01e-c216-4dfd-b48e-fbd5c8212ba4',
                'next_group_id': 1,
                'host_id': u'test1',
                'nsp': 256,
                'portchain_id': u'8cba323e-5e67-4df0-a4b0-7e1ef486a656',
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'logical_destination_port': (
                        'e1229670-2a07-450d-bdc9-34e71c301206'),
                    'l7_parameters': {},
                    'source_port_range_max': 200,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 400,
                    'logical_source_port': (
                        '9bedd01e-c216-4dfd-b48e-fbd5c8212ba4')
                }],
                'id': '611bdc42-12b3-4639-8faf-83da4e6403f7'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 253,
                'ingress': 'e1229670-2a07-450d-bdc9-34e71c301206',
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 43,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:c5:f3',
                'network_type': 'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'dst_node',
                'egress': None,
                'next_group_id': None,
                'host_id': u'test2',
                'nsp': 256,
                'portchain_id': '8cba323e-5e67-4df0-a4b0-7e1ef486a656',
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': 'tcp',
                    'logical_destination_port': (
                        'e1229670-2a07-450d-bdc9-34e71c301206'),
                    'l7_parameters': {},
                    'source_port_range_max': 200,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 400,
                    'logical_source_port': (
                        '9bedd01e-c216-4dfd-b48e-fbd5c8212ba4')
                }],
                'id': '611bdc42-12b3-4639-8faf-83da4e6403f8'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.added_flows, [{
                'actions': 'resubmit(,%d)' % agent.SF_SELECTOR,
                'dl_type': 34887,
                'priority': agent.PC_DEF_PRI,
                'table': 0
            }, {
                'actions': 'resubmit(,%d)' % agent.FWD_SELECTOR,
                'dl_type': 34887,
                'priority': agent.PC_DEF_PRI
            }, {
                'actions': 'output:%d' % self.int_patch,
                'priority': 0,
                'table': agent.FWD_SELECTOR
            }, {
                'actions': 'resubmit(,%d)' % agent.GRP_SELECTOR,
                'in_port': self.int_patch,
                'priority': agent.PC_DEF_PRI,
                'table': agent.FWD_SELECTOR
            }, {
                'actions': 'pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': agent.SF_SELECTOR
            }]
        )
        self.assertEqual(
            self.group_mapping, {}
        )

    def test_update_flow_rules_flow_classifiers_port_pairs(self):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            '82a575e0-6a6e-46ba-a5fc-692407839a85': {
                'port_name': 'port3',
                'ofport': 60,
                'vif_mac': '00:01:02:03:06:09'
            },
            '93466f5d-252e-4552-afc6-5fb3f6019f76': {
                'port_name': 'port4',
                'ofport': 25,
                'vif_mac': '00:01:02:03:06:10'
            }
        }
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'local_endpoint': '10.0.0.2',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'mac_address': '12:34:56:78:cf:23'
                }],
                'del_fcs': [],
                'segment_id': 33,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:ed:01',
                'network_type': 'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'src_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'host_id': 'test1',
                'nsp': 256,
                'portchain_id': 'b9570dc9-822b-41fc-a27c-d915a21a3fe8',
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'logical_destination_port': (
                        '82a575e0-6a6e-46ba-a5fc-692407839a85'),
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 300,
                    'logical_source_port': (
                        '29e38fb2-a643-43b1-baa8-a86596461cd5')
                }],
                'id': '73e97aad-8c0f-44e3-bee0-c0a641b00b66'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 253,
                'ingress': '82a575e0-6a6e-46ba-a5fc-692407839a85',
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 33,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:a6:84',
                'network_type': 'gre',
                'local_endpoint': '10.0.0.2',
                'node_type': 'dst_node',
                'egress': None,
                'next_group_id': None,
                'host_id': 'test2',
                'nsp': 256,
                'portchain_id': 'b9570dc9-822b-41fc-a27c-d915a21a3fe8',
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': '10.200.0.0/16',
                    'protocol': u'tcp',
                    'logical_destination_port': (
                        '82a575e0-6a6e-46ba-a5fc-692407839a85'),
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 300,
                    'logical_source_port': (
                        '29e38fb2-a643-43b1-baa8-a86596461cd5')
                }],
                'id': 'fa385d84-7d78-44e7-aa8d-7b4a279a14d7'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                'next_hops': [{
                    'local_endpoint': '10.0.0.2',
                    'ingress': '82a575e0-6a6e-46ba-a5fc-692407839a85',
                    'weight': 1,
                    'mac_address': '12:34:56:78:a6:84'
                }],
                'del_fcs': [],
                'segment_id': 33,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:cf:23',
                'network_type': 'gre',
                'local_endpoint': '10.0.0.2',
                'node_type': 'sf_node',
                'egress': '93466f5d-252e-4552-afc6-5fb3f6019f76',
                'next_group_id': None,
                'host_id': 'test3',
                'nsp': 256,
                'portchain_id': 'b9570dc9-822b-41fc-a27c-d915a21a3fe8',
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': '10.200.0.0/16',
                    'protocol': u'tcp',
                    'logical_destination_port': (
                        '82a575e0-6a6e-46ba-a5fc-692407839a85'),
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 300,
                    'logical_source_port': (
                        '29e38fb2-a643-43b1-baa8-a86596461cd5')
                }],
                'id': '07cc65a8-e99b-4175-a2f1-69b87eb8090a'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.added_flows, [{
                'actions': 'resubmit(,%d)' % agent.SF_SELECTOR,
                'dl_type': 34887,
                'priority': agent.PC_DEF_PRI,
                'table': 0
            }, {
                'actions': 'resubmit(,%d)' % agent.FWD_SELECTOR,
                'dl_type': 34887,
                'priority': agent.PC_DEF_PRI
            }, {
                'actions': 'output:%d' % self.int_patch,
                'priority': 0,
                'table': agent.FWD_SELECTOR
            }, {
                'actions': 'resubmit(,%d)' % agent.GRP_SELECTOR,
                'in_port': self.int_patch,
                'priority': agent.PC_DEF_PRI,
                'table': agent.FWD_SELECTOR
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': 10,
                'table': 0,
                'tp_dst': '0x12c/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 0,
                'table': agent.GRP_SELECTOR
            }, {
                'actions': 'pop_mpls:0x0800,output:60',
                'dl_dst': '00:01:02:03:06:09',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': agent.SF_SELECTOR
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:a6:84,'
                    'set_field:33->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65790,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': 0,
                'table': agent.GRP_SELECTOR,
                'tp_dst': '0x12c/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 25,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'priority': agent.PC_DEF_PRI,
                'table': 0,
                'tp_dst': '0x12c/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'actions': 'pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': agent.SF_SELECTOR
            }]
        )
        self.assertEqual(
            self.group_mapping, {
                1: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:cf:23,'
                        'set_field:33->tun_id,output:[]'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            }
        )

    def test_update_flow_rules_flow_classifiers_multi_port_groups(self):
        self.port_mapping = {
            '6331a00d-779b-462b-b0e4-6a65aa3164ef': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '1ebf82cf-70f9-43fd-8b90-6546f7d13040': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            '34032c43-5207-43bb-95cb-cf426266fa11': {
                'port_name': 'port3',
                'ofport': 60,
                'vif_mac': '00:01:02:03:06:09'
            },
            'eaeec782-4ee8-4c7f-8ecb-f759dab4c723': {
                'port_name': 'port4',
                'ofport': 25,
                'vif_mac': '00:01:02:03:06:10'
            },
            'f56df7aa-e521-41ce-9001-ed7bedb65c9e': {
                'port_name': 'port5',
                'ofport': 5,
                'vif_mac': '00:01:02:03:06:11'
            },
            '15dc026d-0520-4f92-9841-1056e62fdcaa': {
                'port_name': 'port6',
                'ofport': 50,
                'vif_mac': '00:01:02:03:06:12'
            },
            'd98a48fe-4ef7-4aa6-89fa-02312e54c1bd': {
                'port_name': 'port7',
                'ofport': 4,
                'vif_mac': '00:01:02:03:06:13'
            },
            'd412d042-d8bc-4dd9-b2be-b29c7e8b2c1b': {
                'port_name': 'port8',
                'ofport': 8,
                'vif_mac': '00:01:02:03:06:14'
            }
        }
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'local_endpoint': '10.0.0.2',
                    'ingress': '34032c43-5207-43bb-95cb-cf426266fa11',
                    'weight': 1,
                    'mac_address': '12:34:56:78:b0:88'
                }],
                'del_fcs': [],
                'segment_id': 37,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:74:91',
                'network_type': 'gre',
                'local_endpoint': '10.0.0.2',
                'node_type': 'src_node',
                'egress': '6331a00d-779b-462b-b0e4-6a65aa3164ef',
                'next_group_id': 1,
                'host_id': 'test1',
                'nsp': 256,
                'portchain_id': 'd0b48df7-47ab-4909-b864-9aae1a6ee6fb',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '1ebf82cf-70f9-43fd-8b90-6546f7d13040'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '6331a00d-779b-462b-b0e4-6a65aa3164ef')
                }],
                'id': 'bbb1e50c-ecbb-400c-a7e9-8aed8f36993f'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 251,
                'ingress': '1ebf82cf-70f9-43fd-8b90-6546f7d13040',
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 37,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:b7:0d',
                'network_type': 'gre',
                'local_endpoint': '10.0.0.2',
                'node_type': 'dst_node',
                'egress': None,
                'next_group_id': None,
                'host_id': 'test2',
                'nsp': 256,
                'portchain_id': 'd0b48df7-47ab-4909-b864-9aae1a6ee6fb',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '1ebf82cf-s70f9-43fd-8b90-6546f7d13040'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '6331a00d-779b-462b-b0e4-6a65aa3164ef')
                }],
                'id': '7ed75c14-2283-484a-97b8-30e23fbf7457'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': '34032c43-5207-43bb-95cb-cf426266fa11',
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'f56df7aa-e521-41ce-9001-ed7bedb65c9e',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:b1:0d'
                }],
                'del_fcs': [],
                'segment_id': 37,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:b0:88',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'eaeec782-4ee8-4c7f-8ecb-f759dab4c723',
                'next_group_id': 2,
                'host_id': u'test3',
                'nsp': 256,
                'portchain_id': u'd0b48df7-47ab-4909-b864-9aae1a6ee6fb',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '1ebf82cf-70f9-43fd-8b90-6546f7d13040'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '6331a00d-779b-462b-b0e4-6a65aa3164ef')
                }],
                'id': 'f9fd9c7a-0100-43fb-aea9-30c67f2a731a'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 253,
                'ingress': 'f56df7aa-e521-41ce-9001-ed7bedb65c9e',
                'next_hops': [{
                    'local_endpoint': '10.0.0.2',
                    'ingress': 'd98a48fe-4ef7-4aa6-89fa-02312e54c1bd',
                    'weight': 1,
                    'mac_address': '12:34:56:78:4e:dd'
                }],
                'del_fcs': [],
                'segment_id': 37,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:b1:0d',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'15dc026d-0520-4f92-9841-1056e62fdcaa',
                'next_group_id': 3,
                'host_id': u'test5',
                'nsp': 256,
                'portchain_id': u'd0b48df7-47ab-4909-b864-9aae1a6ee6fb',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '1ebf82cf-70f9-43fd-8b90-6546f7d13040'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '6331a00d-779b-462b-b0e4-6a65aa3164ef')
                }],
                'id': '62f4bb35-1b4a-4cc4-bf07-f40ed5c2d6a7'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 252,
                'ingress': u'd98a48fe-4ef7-4aa6-89fa-02312e54c1bd',
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'1ebf82cf-70f9-43fd-8b90-6546f7d13040',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:b7:0d'
                }],
                'del_fcs': [],
                'segment_id': 37,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:4e:dd',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'd412d042-d8bc-4dd9-b2be-b29c7e8b2c1b',
                'next_group_id': None,
                'host_id': u'test7',
                'nsp': 256,
                'portchain_id': u'd0b48df7-47ab-4909-b864-9aae1a6ee6fb',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '1ebf82cf-70f9-43fd-8b90-6546f7d13040'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '6331a00d-779b-462b-b0e4-6a65aa3164ef')
                }],
                'id': 'a535e740-02cc-47ef-aab1-7bcb1594db9b'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.added_flows, [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:%d' % self.int_patch,
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': self.int_patch,
                'priority': 10,
                'table': 30
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 6,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 0,
                'table': 31
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:42'
                ),
                'dl_dst': '00:01:02:03:06:08',
                'dl_type': 34887,
                'mpls_label': 65788,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 25,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:2',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 0,
                'table': 31
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:60'
                ),
                'dl_dst': '00:01:02:03:06:09',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65789,'
                    'set_mpls_ttl:253,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 50,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:3',
                'dl_type': 34887,
                'mpls_label': 65789,
                'priority': 0,
                'table': 31
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:5'
                ),
                'dl_dst': '00:01:02:03:06:11',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:b7:0d,'
                    'set_field:37->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65788,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 0,
                'table': 31,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65788,'
                    'set_mpls_ttl:252,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 8,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:4'
                ),
                'dl_dst': '00:01:02:03:06:13',
                'dl_type': 34887,
                'mpls_label': 65789,
                'priority': 1,
                'table': 5
            }]
        )
        self.assertEqual(
            self.group_mapping, {
                1: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:b0:88,'
                        'set_field:37->tun_id,output:[]'
                    ),
                    'group_id': 1,
                    'type': 'select'
                },
                2: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:b1:0d,'
                        'set_field:37->tun_id,output:[]'
                    ),
                    'group_id': 2,
                    'type': 'select'
                },
                3: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:4e:dd,'
                        'set_field:37->tun_id,output:[]'
                    ),
                    'group_id': 3,
                    'type': 'select'
                }
            }
        )

    def test_update_flow_rules_flow_classifiers_multi_port_pairs(self):
        self.port_mapping = {
            '9864d8e8-0aff-486e-8b84-7a8d20c017d4': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '21047d09-eaa7-4296-af56-b509e4a10853': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            '38266cfe-cd42-413e-80ff-d0d0c74ad260': {
                'port_name': 'port3',
                'ofport': 60,
                'vif_mac': '00:01:02:03:06:09'
            },
            '272be90c-b140-4e9d-8dd3-1993fbb3656c': {
                'port_name': 'port4',
                'ofport': 25,
                'vif_mac': '00:01:02:03:06:10'
            },
            'd1791c8d-a07a-4f35-bd52-b99395da0d76': {
                'port_name': 'port5',
                'ofport': 5,
                'vif_mac': '00:01:02:03:06:11'
            },
            'ed2804bd-d61a-49e7-9007-76d2540ae78a': {
                'port_name': 'port6',
                'ofport': 50,
                'vif_mac': '00:01:02:03:06:12'
            },
            'bdf4f759-ca35-4cf5-89ac-53da0d6b3fbf': {
                'port_name': 'port7',
                'ofport': 4,
                'vif_mac': '00:01:02:03:06:13'
            },
            'a55b9062-d3fa-4dc2-a4df-bb8b2a908c19': {
                'port_name': 'port8',
                'ofport': 8,
                'vif_mac': '00:01:02:03:06:14'
            }
        }
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'38266cfe-cd42-413e-80ff-d0d0c74ad260',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:74:c1'
                }, {
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'd1791c8d-a07a-4f35-bd52-b99395da0d76',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:4f:6e'
                }, {
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'bdf4f759-ca35-4cf5-89ac-53da0d6b3fbf',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:d5:66'
                }],
                'del_fcs': [],
                'segment_id': 51,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:9c:70',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'src_node',
                'egress': u'9864d8e8-0aff-486e-8b84-7a8d20c017d4',
                'next_group_id': 1,
                'host_id': u'test1',
                'nsp': 256,
                'portchain_id': u'3dddbb0c-5ac4-437c-9b62-ed7ddf8df37f',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '21047d09-eaa7-4296-af56-b509e4a10853'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '9864d8e8-0aff-486e-8b84-7a8d20c017d4')
                }],
                'id': '677dfe31-8566-4bd8-8a1e-5f8efd7a45eb'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 253,
                'ingress': u'21047d09-eaa7-4296-af56-b509e4a10853',
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 51,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:67:cb',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'dst_node',
                'egress': None,
                'next_group_id': None,
                'host_id': u'test2',
                'nsp': 256,
                'portchain_id': u'3dddbb0c-5ac4-437c-9b62-ed7ddf8df37f',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '21047d09-eaa7-4296-af56-b509e4a10853'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '9864d8e8-0aff-486e-8b84-7a8d20c017d4')
                }],
                'id': '4f275568-38cb-45a1-a162-e0d1d4ef335d'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': u'38266cfe-cd42-413e-80ff-d0d0c74ad260',
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'21047d09-eaa7-4296-af56-b509e4a10853',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:67:cb'
                }],
                'del_fcs': [],
                'segment_id': 51,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:74:c1',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'272be90c-b140-4e9d-8dd3-1993fbb3656c',
                'next_group_id': None,
                'host_id': u'test3',
                'nsp': 256,
                'portchain_id': u'3dddbb0c-5ac4-437c-9b62-ed7ddf8df37f',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '21047d09-eaa7-4296-af56-b509e4a10853'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '9864d8e8-0aff-486e-8b84-7a8d20c017d4')
                }],
                'id': '48fd97b1-e166-4aff-906f-8096a48a7cb1'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': u'd1791c8d-a07a-4f35-bd52-b99395da0d76',
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'21047d09-eaa7-4296-af56-b509e4a10853',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:67:cb'
                }],
                'del_fcs': [],
                'segment_id': 51,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:4f:6e',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'ed2804bd-d61a-49e7-9007-76d2540ae78a',
                'next_group_id': None,
                'host_id': u'test5',
                'nsp': 256,
                'portchain_id': u'3dddbb0c-5ac4-437c-9b62-ed7ddf8df37f',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '21047d09-eaa7-4296-af56-b509e4a10853'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '9864d8e8-0aff-486e-8b84-7a8d20c017d4')
                }],
                'id': '48fd97b1-e166-4aff-906f-8096a48a7cb1'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': u'bdf4f759-ca35-4cf5-89ac-53da0d6b3fbf',
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'21047d09-eaa7-4296-af56-b509e4a10853',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:67:cb'
                }],
                'del_fcs': [],
                'segment_id': 51,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:d5:66',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'a55b9062-d3fa-4dc2-a4df-bb8b2a908c19',
                'next_group_id': None,
                'host_id': u'test7',
                'nsp': 256,
                'portchain_id': u'3dddbb0c-5ac4-437c-9b62-ed7ddf8df37f',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '21047d09-eaa7-4296-af56-b509e4a10853'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '9864d8e8-0aff-486e-8b84-7a8d20c017d4')
                }],
                'id': '48fd97b1-e166-4aff-906f-8096a48a7cb1'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.added_flows, [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:%d' % self.int_patch,
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': self.int_patch,
                'priority': 10,
                'table': 30
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 6,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 0,
                'table': 31
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:42'
                ),
                'dl_dst': '00:01:02:03:06:08',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:67:cb,'
                    'set_field:51->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65790,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 0,
                'table': 31,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 25,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:60'
                ),
                'dl_dst': '00:01:02:03:06:09',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 50,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:5'
                ),
                'dl_dst': '00:01:02:03:06:11',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 8,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:4'
                ),
                'dl_dst': '00:01:02:03:06:13',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': 5
            }]
        )
        self.assertEqual(
            self.group_mapping, {
                1: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:74:c1,'
                        'set_field:51->tun_id,output:[],'
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:4f:6e,'
                        'set_field:51->tun_id,output:[],'
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:d5:66,'
                        'set_field:51->tun_id,output:[]'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            }
        )

    def test_update_flow_rules_multi_flow_classifiers(self):
        self.port_mapping = {
            '54abe601-6685-4c38-9b9d-0d8381a43d56': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            'c2de00c2-bd91-4f60-8a7d-5a3ea8f65e77': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            '460a5875-b0c6-408e-ada4-0ef01d39bcff': {
                'port_name': 'port3',
                'ofport': 60,
                'vif_mac': '00:01:02:03:06:09'
            },
            'b2b8a556-593b-4695-8812-cdd33a314867': {
                'port_name': 'port4',
                'ofport': 25,
                'vif_mac': '00:01:02:03:06:10'
            },
            '2656a373-a985-4940-90d1-cfe172951e0c': {
                'port_name': 'port5',
                'ofport': 5,
                'vif_mac': '00:01:02:03:06:11'
            },
            'a979a847-3014-43ea-b37d-5a3775a173c7': {
                'port_name': 'port6',
                'ofport': 50,
                'vif_mac': '00:01:02:03:06:12'
            }
        }
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'2656a373-a985-4940-90d1-cfe172951e0c',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:5f:ea'
                }],
                'del_fcs': [],
                'segment_id': 58,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:b9:09',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'src_node',
                'egress': u'54abe601-6685-4c38-9b9d-0d8381a43d56',
                'next_group_id': 1,
                'host_id': u'test1',
                'nsp': 256,
                'portchain_id': u'3eefdf29-ea8f-4794-a36f-5e60ec7fe208',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '460a5875-b0c6-408e-ada4-0ef01d39bcff'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '54abe601-6685-4c38-9b9d-0d8381a43d56')
                }],
                'id': 'd2e675d3-739e-4451-95d5-a15e23c6eaac'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'2656a373-a985-4940-90d1-cfe172951e0c',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:5f:ea'
                }],
                'del_fcs': [],
                'segment_id': 58,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:4d:d1',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'src_node',
                'egress': u'c2de00c2-bd91-4f60-8a7d-5a3ea8f65e77',
                'next_group_id': 1,
                'host_id': u'test3',
                'nsp': 256,
                'portchain_id': u'3eefdf29-ea8f-4794-a36f-5e60ec7fe208',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        'b2b8a556-593b-4695-8812-cdd33a314867'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        'c2de00c2-bd91-4f60-8a7d-5a3ea8f65e77')
                }],
                'id': 'd2e675d3-739e-4451-95d5-a15e23c6eaac'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 253,
                'ingress': u'460a5875-b0c6-408e-ada4-0ef01d39bcff',
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 58,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:fc:b8',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'dst_node',
                'egress': None,
                'next_group_id': None,
                'host_id': u'test2',
                'nsp': 256,
                'portchain_id': u'3eefdf29-ea8f-4794-a36f-5e60ec7fe208',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '460a5875-b0c6-408e-ada4-0ef01d39bcff'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '54abe601-6685-4c38-9b9d-0d8381a43d56')
                }],
                'id': '029823ae-8524-4e1c-8f5b-4ee7ec55f1bd'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 253,
                'ingress': u'b2b8a556-593b-4695-8812-cdd33a314867',
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 58,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:7b:15',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'dst_node',
                'egress': None,
                'next_group_id': None,
                'host_id': u'test4',
                'nsp': 256,
                'portchain_id': u'3eefdf29-ea8f-4794-a36f-5e60ec7fe208',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        'b2b8a556-593b-4695-8812-cdd33a314867'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        'c2de00c2-bd91-4f60-8a7d-5a3ea8f65e77')
                }],
                'id': '029823ae-8524-4e1c-8f5b-4ee7ec55f1bd'
            }
        )
        self.agent.update_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': u'2656a373-a985-4940-90d1-cfe172951e0c',
                'next_hops': [{
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'460a5875-b0c6-408e-ada4-0ef01d39bcff',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:fc:b8'
                }, {
                    'local_endpoint': u'10.0.0.2',
                    'ingress': u'b2b8a556-593b-4695-8812-cdd33a314867',
                    'weight': 1,
                    'mac_address': u'12:34:56:78:7b:15'
                }],
                'del_fcs': [],
                'segment_id': 58,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:5f:ea',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'a979a847-3014-43ea-b37d-5a3775a173c7',
                'next_group_id': None,
                'host_id': u'test5',
                'nsp': 256,
                'portchain_id': u'3eefdf29-ea8f-4794-a36f-5e60ec7fe208',
                'add_fcs': [{
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        '460a5875-b0c6-408e-ada4-0ef01d39bcff'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        '54abe601-6685-4c38-9b9d-0d8381a43d56')
                }, {
                    'source_port_range_min': None,
                    'destination_ip_prefix': None,
                    'protocol': None,
                    'logical_destination_port': (
                        'b2b8a556-593b-4695-8812-cdd33a314867'),
                    'l7_parameters': {},
                    'source_port_range_max': None,
                    'source_ip_prefix': None,
                    'destination_port_range_min': None,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': None,
                    'logical_source_port': (
                        'c2de00c2-bd91-4f60-8a7d-5a3ea8f65e77')
                }],
                'id': '983cfa51-f9e6-4e36-8f6c-0c84df915cd1'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.added_flows, [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:%d' % self.int_patch,
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': self.int_patch,
                'priority': 10,
                'table': 30
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 6,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 0,
                'table': 31
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:60'
                ),
                'dl_dst': '00:01:02:03:06:09',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:25'
                ),
                'dl_dst': '00:01:02:03:06:10',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:fc:b8,'
                    'set_field:58->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65790,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 0,
                'table': 31,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:%d' % self.tun_patch
                ),
                'dl_type': 2048,
                'in_port': 50,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:7b:15,'
                    'set_field:58->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65790,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 0,
                'table': 31,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:5'
                ),
                'dl_dst': '00:01:02:03:06:11',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': 5
            }]
        )
        self.assertEqual(
            self.group_mapping, {
                1: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:5f:ea,'
                        'set_field:58->tun_id,output:[]'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            }
        )

    def test_delete_flow_rules_port_pair(self):
        self.port_mapping = {
            'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '2f1d2140-42ce-4979-9542-7ef25796e536': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            }
        }
        self.agent.delete_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': u'dd7374b9-a6ac-4a66-a4a6-7d3dee2a1579',
                'next_hops': None,
                'del_fcs': [],
                'segment_id': 75,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:fd:b2',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'sf_node',
                'egress': u'2f1d2140-42ce-4979-9542-7ef25796e536',
                'next_group_id': None,
                'host_id': u'test1',
                'nsp': 256,
                'portchain_id': u'84c1411f-7a94-4b4f-9a8b-ad9607c67c76',
                'add_fcs': [],
                'id': '611bdc42-12b3-4639-8faf-83da4e6403f7'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.deleted_flows, [{
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': '65791',
                'table': 5
            }, {
                'dl_type': 34887,
                'mpls_label': '65790',
                'table': 31
            }]
        )
        self.assertEqual(
            self.deleted_groups, [
            ]
        )

    def test_delete_flow_rules_flow_classifiers(self):
        self.port_mapping = {
            'e1229670-2a07-450d-bdc9-34e71c301206': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '9bedd01e-c216-4dfd-b48e-fbd5c8212ba4': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            }
        }

        self.agent.delete_flow_rules(
            self.context, flowrule_entries={
                'nsi': 255,
                'ingress': None,
                'next_hops': None,
                'add_fcs': [],
                'segment_id': 43,
                'group_refcnt': 1,
                'mac_address': u'12:34:56:78:72:05',
                'network_type': u'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'src_node',
                'egress': u'9bedd01e-c216-4dfd-b48e-fbd5c8212ba4',
                'next_group_id': 1,
                'host_id': u'test1',
                'nsp': 256,
                'portchain_id': u'8cba323e-5e67-4df0-a4b0-7e1ef486a656',
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'logical_destination_port': (
                        'e1229670-2a07-450d-bdc9-34e71c301206'),
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 300,
                    'logical_source_port': (
                        '9bedd01e-c216-4dfd-b48e-fbd5c8212ba4')
                }],
                'id': '611bdc42-12b3-4639-8faf-83da4e6403f7'
            }
        )
        self.agent.delete_flow_rules(
            self.context, flowrule_entries={
                'nsi': 253,
                'ingress': 'e1229670-2a07-450d-bdc9-34e71c301206',
                'next_hops': None,
                'add_fcs': [],
                'segment_id': 43,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:c5:f3',
                'network_type': 'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'dst_node',
                'egress': None,
                'next_group_id': None,
                'host_id': u'test2',
                'nsp': 256,
                'portchain_id': '8cba323e-5e67-4df0-a4b0-7e1ef486a656',
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': 'tcp',
                    'logical_destination_port': (
                        'e1229670-2a07-450d-bdc9-34e71c301206'),
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 300,
                    'logical_source_port': (
                        '9bedd01e-c216-4dfd-b48e-fbd5c8212ba4')
                }],
                'id': '611bdc42-12b3-4639-8faf-83da4e6403f8'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.deleted_flows, [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'table': 0,
                'tp_dst': '0x12c/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'dl_type': 34887,
                'mpls_label': '65791',
                'table': 31
            }, {
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': '65790',
                'table': 5
            }]
        )
        self.assertEqual(
            self.deleted_groups, [1]
        )

    def test_delete_flow_rules_flow_classifiers_port_pairs(self):
        self.port_mapping = {
            '8768d2b3-746d-4868-ae0e-e81861c2b4e6': {
                'port_name': 'port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '29e38fb2-a643-43b1-baa8-a86596461cd5': {
                'port_name': 'port2',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            '82a575e0-6a6e-46ba-a5fc-692407839a85': {
                'port_name': 'port3',
                'ofport': 60,
                'vif_mac': '00:01:02:03:06:09'
            },
            '93466f5d-252e-4552-afc6-5fb3f6019f76': {
                'port_name': 'port4',
                'ofport': 25,
                'vif_mac': '00:01:02:03:06:10'
            }
        }
        self.agent.delete_flow_rules(
            self.context, flowrule_entries={
                'nsi': 255,
                'ingress': None,
                'next_hops': [{
                    'local_endpoint': '10.0.0.2',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'mac_address': '12:34:56:78:cf:23'
                }],
                'add_fcs': [],
                'segment_id': 33,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:ed:01',
                'network_type': 'gre',
                'local_endpoint': u'10.0.0.2',
                'node_type': 'src_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'host_id': 'test1',
                'nsp': 256,
                'portchain_id': 'b9570dc9-822b-41fc-a27c-d915a21a3fe8',
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'logical_destination_port': (
                        '82a575e0-6a6e-46ba-a5fc-692407839a85'),
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 300,
                    'logical_source_port': (
                        '29e38fb2-a643-43b1-baa8-a86596461cd5')
                }],
                'id': '73e97aad-8c0f-44e3-bee0-c0a641b00b66'
            }
        )
        self.agent.delete_flow_rules(
            self.context, flowrule_entries={
                'nsi': 253,
                'ingress': '82a575e0-6a6e-46ba-a5fc-692407839a85',
                'next_hops': None,
                'add_fcs': [],
                'segment_id': 33,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:a6:84',
                'network_type': 'gre',
                'local_endpoint': '10.0.0.2',
                'node_type': 'dst_node',
                'egress': None,
                'next_group_id': None,
                'host_id': 'test2',
                'nsp': 256,
                'portchain_id': 'b9570dc9-822b-41fc-a27c-d915a21a3fe8',
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': '10.200.0.0/16',
                    'protocol': u'tcp',
                    'logical_destination_port': (
                        '82a575e0-6a6e-46ba-a5fc-692407839a85'),
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 300,
                    'logical_source_port': (
                        '29e38fb2-a643-43b1-baa8-a86596461cd5')
                }],
                'id': 'fa385d84-7d78-44e7-aa8d-7b4a279a14d7'
            }
        )
        self.agent.delete_flow_rules(
            self.context, flowrule_entries={
                'nsi': 254,
                'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                'next_hops': [{
                    'local_endpoint': '10.0.0.2',
                    'ingress': '82a575e0-6a6e-46ba-a5fc-692407839a85',
                    'weight': 1,
                    'mac_address': '12:34:56:78:a6:84'
                }],
                'add_fcs': [],
                'segment_id': 33,
                'group_refcnt': 1,
                'mac_address': '12:34:56:78:cf:23',
                'network_type': 'gre',
                'local_endpoint': '10.0.0.2',
                'node_type': 'sf_node',
                'egress': '93466f5d-252e-4552-afc6-5fb3f6019f76',
                'next_group_id': None,
                'host_id': 'test3',
                'nsp': 256,
                'portchain_id': 'b9570dc9-822b-41fc-a27c-d915a21a3fe8',
                'del_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': '10.200.0.0/16',
                    'protocol': u'tcp',
                    'logical_destination_port': (
                        '82a575e0-6a6e-46ba-a5fc-692407839a85'),
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': u'10.100.0.0/16',
                    'destination_port_range_min': 300,
                    'ethertype': u'IPv4',
                    'destination_port_range_max': 300,
                    'logical_source_port': (
                        '29e38fb2-a643-43b1-baa8-a86596461cd5')
                }],
                'id': '07cc65a8-e99b-4175-a2f1-69b87eb8090a'
            }
        )
        self.assertEqual(
            self.executed_cmds, [
            ]
        )
        self.assertEqual(
            self.deleted_flows, [{
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': u'10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': '10.100.0.0/16',
                'table': 0,
                'tp_dst': '0x12c/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'dl_type': 34887,
                'mpls_label': '65791',
                'table': 31
            }, {
                'dl_dst': '00:01:02:03:06:09',
                'dl_type': 34887,
                'mpls_label': '65790',
                'table': 5
            }, {
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': '65791',
                'table': 5
            }, {
                'dl_type': 2048,
                'in_port': 25,
                'nw_dst': '10.200.0.0/16',
                'nw_proto': 6,
                'nw_src': u'10.100.0.0/16',
                'table': 0,
                'tp_dst': '0x12c/0xffff',
                'tp_src': '0x64/0xffff'
            }, {
                'dl_type': 34887,
                'mpls_label': '65790',
                'table': 31
            }]
        )
        self.assertEqual(
            self.deleted_groups, [1]
        )

    def test_init_agent_empty_flowrules(self):
        self.node_flowrules = []
        self.init_agent()
        self.assertItemsEqual(
            self.added_flows,
            [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:1',
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': 1,
                'priority': 10,
                'table': 30
            }]
        )
        self.assertEqual(self.group_mapping, {})

    def test_init_agent_portchain_portpairs(self):
        self.port_mapping = {
            '4f72c5fc-37e9-4e6f-8cd8-e8166c4b45c4': {
                'port_name': 'ingress',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '57f35c35-dceb-4934-9a78-b40a0a3e16b3': {
                'port_name': 'egress',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            }
        }
        self.node_flowrules = [{
            'nsi': 254,
            'ingress': '4f72c5fc-37e9-4e6f-8cd8-e8166c4b45c4',
            'next_hops': None,
            'del_fcs': [],
            'segment_id': 34,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:2d:f4',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.2',
            'node_type': 'sf_node',
            'egress': '57f35c35-dceb-4934-9a78-b40a0a3e16b3',
            'next_group_id': None,
            'host_id': u'test2',
            'nsp': 256,
            'portchain_id': '0f604e43-c941-4f42-a96c-8bd027e5507d',
            'add_fcs': [],
            'id': 'b6ebb2c3-4e9c-4146-8a74-f3985173dc44'
        }]
        self.init_agent()
        for port_id in self.port_mapping:
            self.agent.sfc_treat_devices_added_updated(port_id)
        self.assertItemsEqual(
            self.added_flows,
            [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:1',
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': 1,
                'priority': 10,
                'table': 30
            }, {
                'actions': 'pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': agent.SF_SELECTOR
            }]
        )
        self.assertEqual(self.group_mapping, {})

    def test_init_agent_portchain_flowclassifiers(self):
        self.port_mapping = {
            '5aa33c52-535a-48eb-a77c-e02329bb9eb7': {
                'port_name': 'src_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '079d214c-1aea-439d-bf3c-dad03db47dcb': {
                'port_name': 'dst_port',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            }
        }
        self.node_flowrules = [{
            'nsi': 253,
            'ingress': '5aa33c52-535a-48eb-a77c-e02329bb9eb7',
            'next_hops': None,
            'del_fcs': [],
            'segment_id': 43,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:ac:22',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.3',
            'node_type': 'dst_node',
            'egress': None,
            'next_group_id': None,
            'host_id': 'test2',
            'nsp': 256,
            'portchain_id': 'd66efb47-f080-41da-8499-c6e89327ecc0',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '5aa33c52-535a-48eb-a77c-e02329bb9eb7'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '079d214c-1aea-439d-bf3c-dad03db47dcb'
            }],
            'id': '9d8ec269-874a-42b2-825f-d25858341ec2'
        }, {
            'nsi': 255,
            'ingress': None,
            'next_hops': None,
            'del_fcs': [],
            'segment_id': 43,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:e3:b3',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.2',
            'node_type': 'src_node',
            'egress': '079d214c-1aea-439d-bf3c-dad03db47dcb',
            'next_group_id': 1,
            'host_id': 'test1',
            'nsp': 256,
            'portchain_id': 'd66efb47-f080-41da-8499-c6e89327ecc0',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '5aa33c52-535a-48eb-a77c-e02329bb9eb7'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '079d214c-1aea-439d-bf3c-dad03db47dcb'
            }],
            'id': u'361811ed-2902-4d35-9fe4-a3a2b062ef37'
        }]
        self.init_agent()
        for port_id in self.port_mapping:
            self.agent.sfc_treat_devices_added_updated(port_id)
        self.assertItemsEqual(
            self.added_flows,
            [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:1',
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': 1,
                'priority': 10,
                'table': 30
            }, {
                'actions': 'pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }]
        )
        self.assertEqual(self.group_mapping, {})

    def test_init_agent_portchain_flow_classifiers_port_pairs(self):
        self.port_mapping = {
            '2881f577-3828-40f2-855d-2f86d63a4733': {
                'port_name': 'dst_port',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '5546e281-319b-4bdd-95c9-37fe4244aeb3': {
                'port_name': 'ingress',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            'c45ccd73-46ad-4d91-b44d-68c15a822521': {
                'port_name': 'egress',
                'ofport': 43,
                'vif_mac': '00:01:02:03:06:09'
            },
            'd2ebbafb-500e-4926-9751-de73906a1e00': {
                'port_name': 'src_port',
                'ofport': 44,
                'vif_mac': '00:01:02:03:06:10'
            }
        }
        self.node_flowrules = [{
            'nsi': 253,
            'ingress': '2881f577-3828-40f2-855d-2f86d63a4733',
            'next_hops': None,
            'del_fcs': [],
            'segment_id': 67,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:17:0c',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.3',
            'node_type': 'dst_node',
            'egress': None,
            'next_group_id': None,
            'host_id': 'test2',
            'nsp': 256,
            'portchain_id': 'cddb174c-9e50-4411-b844-41ecb9caf4c4',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': u'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2881f577-3828-40f2-855d-2f86d63a4733'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': 'd2ebbafb-500e-4926-9751-de73906a1e00'
            }],
            'id': '752ca419-6729-461f-993f-fbd44bbd0edb'
        }, {
            'nsi': 254,
            'ingress': '5546e281-319b-4bdd-95c9-37fe4244aeb3',
            'next_hops': [{
                'local_endpoint': '10.0.0.3',
                'ingress': '2881f577-3828-40f2-855d-2f86d63a4733',
                'weight': 1,
                'mac_address': '12:34:56:78:17:0c'
            }],
            'del_fcs': [],
            'segment_id': 67,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:ca:de',
            'network_type': u'gre',
            'local_endpoint': '10.0.0.4',
            'node_type': 'sf_node',
            'egress': 'c45ccd73-46ad-4d91-b44d-68c15a822521',
            'next_group_id': None,
            'host_id': 'test4',
            'nsp': 256,
            'portchain_id': 'cddb174c-9e50-4411-b844-41ecb9caf4c4',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2881f577-3828-40f2-855d-2f86d63a4733'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': 'd2ebbafb-500e-4926-9751-de73906a1e00'
            }],
            'id': 'f70d81ec-1b7c-4ab4-9cf3-da5375ad47e9'
        }, {
            'nsi': 255,
            'ingress': None,
            'next_hops': [{
                'local_endpoint': '10.0.0.4',
                'ingress': '5546e281-319b-4bdd-95c9-37fe4244aeb3',
                'weight': 1,
                'mac_address': '12:34:56:78:ca:de'
            }],
            'del_fcs': [],
            'segment_id': 67,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:8c:68',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.2',
            'node_type': 'src_node',
            'egress': 'd2ebbafb-500e-4926-9751-de73906a1e00',
            'next_group_id': 1,
            'host_id': 'test1',
            'nsp': 256,
            'portchain_id': 'cddb174c-9e50-4411-b844-41ecb9caf4c4',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2881f577-3828-40f2-855d-2f86d63a4733'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': 'd2ebbafb-500e-4926-9751-de73906a1e00'
            }],
            'id': 'f52624f0-81d9-4041-81cf-dfe151d3a949'
        }]
        self.init_agent()
        for port_id in self.port_mapping:
            self.agent.sfc_treat_devices_added_updated(port_id)
        self.assertItemsEqual(
            self.added_flows, [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:1',
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': 1,
                'priority': 10,
                'table': 30
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,'
                    'output:2'
                ),
                'dl_type': 2048,
                'in_port': 44,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 0,
                'table': 31
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:17:0c,'
                    'set_field:67->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65790,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 0,
                'table': 31,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:2'
                ),
                'dl_type': 2048,
                'in_port': 43,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'pop_mpls:0x0800,output:42',
                'dl_dst': '00:01:02:03:06:08',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': 5
            }, {
                'actions': 'pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }]
        )
        self.assertEqual(
            self.group_mapping, {
                1: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:ca:de,'
                        'set_field:67->tun_id,output:[]'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            }
        )

    def test_init_agent_portchain_multi_port_groups_port_pairs(self):
        self.port_mapping = {
            '495d5bcf-f8ef-47d7-995a-5a8ef2e6d1ea': {
                'port_name': 'ingress1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '0dd212fb-1e0f-4b1a-abc2-a3a39bbab3ef': {
                'port_name': 'egress1',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            '6d7aa494-7796-46ea-9cfe-52d2b0f84217': {
                'port_name': 'src_port',
                'ofport': 43,
                'vif_mac': '00:01:02:03:06:09'
            },
            '028c5816-7d4b-453e-8ec2-f3a084ae992f': {
                'port_name': 'ingress2',
                'ofport': 44,
                'vif_mac': '00:01:02:03:06:10'
            },
            '3e4e8d33-334b-4c67-8e04-143eeb6f8351': {
                'port_name': 'egress2',
                'ofport': 45,
                'vif_mac': '00:01:02:03:06:11'
            },
            '73d1dbc7-ba46-4b16-85a0-73b106a96fa1': {
                'port_name': 'dst_port',
                'ofport': 46,
                'vif_mac': '00:01:02:03:06:12'
            },
            '1778085d-9f81-4e1e-9748-0bafece63344': {
                'port_name': 'ingress3',
                'ofport': 47,
                'vif_mac': '00:01:02:03:06:13'
            },
            'a47cbe65-ea3f-4faa-af27-8212a121c91f': {
                'port_name': 'egress3',
                'ofport': 48,
                'vif_mac': '00:01:02:03:06:14'
            }
        }
        self.node_flowrules = [{
            'nsi': 254,
            'ingress': '495d5bcf-f8ef-47d7-995a-5a8ef2e6d1ea',
            'next_hops': [{
                'local_endpoint': u'10.0.0.6',
                'ingress': '73d1dbc7-ba46-4b16-85a0-73b106a96fa1',
                'weight': 1,
                'mac_address': '12:34:56:78:51:cc'
            }],
            'del_fcs': [],
            'segment_id': 7,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:1d:84',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.4',
            'node_type': 'sf_node',
            'egress': '0dd212fb-1e0f-4b1a-abc2-a3a39bbab3ef',
            'next_group_id': 2,
            'host_id': 'test3',
            'nsp': 256,
            'portchain_id': '0aa6b9fe-6b5e-4b72-91aa-45bce6587ca7',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    'a47cbe65-ea3f-4faa-af27-8212a121c91f'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '6d7aa494-7796-46ea-9cfe-52d2b0f84217'
            }],
            'id': u'1fe85cf2-41fb-4b30-80de-4ae35d3c2b1c'
        }, {
            'nsi': 255,
            'ingress': None,
            'next_hops': [{
                'local_endpoint': '10.0.0.4',
                'ingress': '495d5bcf-f8ef-47d7-995a-5a8ef2e6d1ea',
                'weight': 1,
                'mac_address': '12:34:56:78:1d:84'
            }],
            'del_fcs': [],
            'segment_id': 7,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:45:d7',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.2',
            'node_type': 'src_node',
            'egress': '6d7aa494-7796-46ea-9cfe-52d2b0f84217',
            'next_group_id': 1,
            'host_id': 'test1',
            'nsp': 256,
            'portchain_id': '0aa6b9fe-6b5e-4b72-91aa-45bce6587ca7',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    'a47cbe65-ea3f-4faa-af27-8212a121c91f'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '6d7aa494-7796-46ea-9cfe-52d2b0f84217'
            }],
            'id': '3c4b700b-e993-4378-b41a-95f609b3c799'
        }, {
            'nsi': 252,
            'ingress': '028c5816-7d4b-453e-8ec2-f3a084ae992f',
            'next_hops': [{
                'local_endpoint': '10.0.0.3',
                'ingress': 'a47cbe65-ea3f-4faa-af27-8212a121c91f',
                'weight': 1,
                'mac_address': '12:34:56:78:54:76'
            }],
            'del_fcs': [],
            'segment_id': 7,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:47:34',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.8',
            'node_type': 'sf_node',
            'egress': '3e4e8d33-334b-4c67-8e04-143eeb6f8351',
            'next_group_id': None,
            'host_id': 'test8',
            'nsp': 256,
            'portchain_id': '0aa6b9fe-6b5e-4b72-91aa-45bce6587ca7',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    'a47cbe65-ea3f-4faa-af27-8212a121c91f'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': u'6d7aa494-7796-46ea-9cfe-52d2b0f84217'
            }],
            'id': '05574d93-104e-425f-8a30-640721f2c749'
        }, {
            'nsi': 253,
            'ingress': '73d1dbc7-ba46-4b16-85a0-73b106a96fa1',
            'next_hops': [{
                'local_endpoint': '10.0.0.8',
                'ingress': '028c5816-7d4b-453e-8ec2-f3a084ae992f',
                'weight': 1,
                'mac_address': '12:34:56:78:47:34'
            }],
            'del_fcs': [],
            'segment_id': 7,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:51:cc',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.6',
            'node_type': 'sf_node',
            'egress': '1778085d-9f81-4e1e-9748-0bafece63344',
            'next_group_id': 3,
            'host_id': 'test5',
            'nsp': 256,
            'portchain_id': '0aa6b9fe-6b5e-4b72-91aa-45bce6587ca7',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    'a47cbe65-ea3f-4faa-af27-8212a121c91f'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '6d7aa494-7796-46ea-9cfe-52d2b0f84217'
            }],
            'id': u'5038a916-93de-4734-a830-d88c9d65566c'
        }, {
            'nsi': 251,
            'ingress': 'a47cbe65-ea3f-4faa-af27-8212a121c91f',
            'next_hops': None,
            'del_fcs': [],
            'segment_id': 7,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:54:76',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.3',
            'node_type': 'dst_node',
            'egress': None,
            'next_group_id': None,
            'host_id': 'test2',
            'nsp': 256,
            'portchain_id': '0aa6b9fe-6b5e-4b72-91aa-45bce6587ca7',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    'a47cbe65-ea3f-4faa-af27-8212a121c91f'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '6d7aa494-7796-46ea-9cfe-52d2b0f84217'
            }],
            'id': '42b8abe6-5bfa-47c5-a992-771e333dae52'
        }]
        self.init_agent()
        for port_id in self.port_mapping:
            self.agent.sfc_treat_devices_added_updated(port_id)
        self.assertItemsEqual(
            self.added_flows, [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:1',
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': 1,
                'priority': 10,
                'table': 30
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65789,'
                    'set_mpls_ttl:253,output:2'
                ),
                'dl_type': 2048,
                'in_port': 47,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:3',
                'dl_type': 34887,
                'mpls_label': 65789,
                'priority': 0,
                'table': 31
            }, {
                'actions': (
                    'pop_mpls:0x0800,'
                    'output:46'
                ),
                'dl_dst': '00:01:02:03:06:12',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:54:76,'
                    'set_field:7->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65788,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 0,
                'table': 31,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65788,'
                    'set_mpls_ttl:252,output:2'
                ),
                'dl_type': 2048,
                'in_port': 45,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'pop_mpls:0x0800,output:44',
                'dl_dst': '00:01:02:03:06:10',
                'dl_type': 34887,
                'mpls_label': 65789,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:2'
                ),
                'dl_type': 2048,
                'in_port': 43,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 0,
                'table': 31
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:2'
                ),
                'dl_type': 2048,
                'in_port': 42,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:2',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 0,
                'table': 31
            }, {
                'actions': 'pop_mpls:0x0800,output:6',
                'dl_dst': '00:01:02:03:05:07',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': 5
            }, {
                'actions': 'pop_mpls:0x0800,output:48',
                'dl_dst': '00:01:02:03:06:14',
                'dl_type': 34887,
                'mpls_label': 65788,
                'priority': 1,
                'table': 5
            }]
        )
        self.assertEqual(
            self.group_mapping, {
                1: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:1d:84,'
                        'set_field:7->tun_id,output:[]'
                    ),
                    'group_id': 1,
                    'type': 'select'
                },
                2: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:51:cc,'
                        'set_field:7->tun_id,output:[]'
                    ),
                    'group_id': 2,
                    'type': 'select'
                },
                3: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:47:34,'
                        'set_field:7->tun_id,output:[]'
                    ),
                    'group_id': 3,
                    'type': 'select'
                }
            }
        )

    def test_init_agent_portchain_port_group_multi_port_pairs(self):
        self.port_mapping = {
            '8849af69-117d-4db9-83fa-85329b0efbd6': {
                'port_name': 'ingress1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '51f58f0f-6870-4e75-9fd1-13cf3ce29b3e': {
                'port_name': 'egress1',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            'a57a8160-a202-477b-aca1-e7c006bc93a2': {
                'port_name': 'src_port',
                'ofport': 43,
                'vif_mac': '00:01:02:03:06:09'
            },
            '23d02749-7f2b-456d-b9f1-7869300375d4': {
                'port_name': 'ingress2',
                'ofport': 44,
                'vif_mac': '00:01:02:03:06:10'
            },
            'c5dacf1c-f84a-43e0-8873-b2cba77970af': {
                'port_name': 'egress2',
                'ofport': 45,
                'vif_mac': '00:01:02:03:06:11'
            },
            '2b17abfa-7afb-4e83-8e15-ad21a6044bb7': {
                'port_name': 'dst_port',
                'ofport': 46,
                'vif_mac': '00:01:02:03:06:12'
            },
            'b299c792-28c8-4f6a-84a0-589163a9b1d4': {
                'port_name': 'ingress3',
                'ofport': 47,
                'vif_mac': '00:01:02:03:06:13'
            },
            '60d47d04-42c0-4478-9136-6247fd5d058d': {
                'port_name': 'egress3',
                'ofport': 48,
                'vif_mac': '00:01:02:03:06:14'
            }
        }
        self.node_flowrules = [{
            'nsi': 254,
            'ingress': '8849af69-117d-4db9-83fa-85329b0efbd6',
            'next_hops': [{
                'local_endpoint': '10.0.0.3',
                'ingress': '2b17abfa-7afb-4e83-8e15-ad21a6044bb7',
                'weight': 1,
                'mac_address': '12:34:56:78:68:3a'
            }],
            'del_fcs': [],
            'segment_id': 68,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:fe:38',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.6',
            'node_type': 'sf_node',
            'egress': '51f58f0f-6870-4e75-9fd1-13cf3ce29b3e',
            'next_group_id': None,
            'host_id': 'test6',
            'nsp': 256,
            'portchain_id': '10f6a764-6963-4b8e-9ae4-a1e5e805915e',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2b17abfa-7afb-4e83-8e15-ad21a6044bb7'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': 'a57a8160-a202-477b-aca1-e7c006bc93a2'
            }],
            'id': u'1409e7b8-ed6f-41ae-ba6b-8ef96bbb8da9'
        }, {
            'nsi': 255,
            'ingress': None,
            'next_hops': [{
                'local_endpoint': '10.0.0.4',
                'ingress': 'b299c792-28c8-4f6a-84a0-589163a9b1d4',
                'weight': 1,
                'mac_address': '12:34:56:78:58:ee'
            }, {
                'local_endpoint': '10.0.0.6',
                'ingress': '8849af69-117d-4db9-83fa-85329b0efbd6',
                'weight': 1,
                'mac_address': '12:34:56:78:fe:38'
            }, {
                'local_endpoint': '10.0.0.8',
                'ingress': '23d02749-7f2b-456d-b9f1-7869300375d4',
                'weight': 1,
                'mac_address': '12:34:56:78:32:30'
            }],
            'del_fcs': [],
            'segment_id': 68,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:e0:a9',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.2',
            'node_type': 'src_node',
            'egress': 'a57a8160-a202-477b-aca1-e7c006bc93a2',
            'next_group_id': 1,
            'host_id': 'test1',
            'nsp': 256,
            'portchain_id': '10f6a764-6963-4b8e-9ae4-a1e5e805915e',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2b17abfa-7afb-4e83-8e15-ad21a6044bb7'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': (
                    'a57a8160-a202-477b-aca1-e7c006bc93a2')
            }],
            'id': '6c686bd6-a064-4650-ace7-0bd34fa4238a'
        }, {
            'nsi': 254,
            'ingress': '23d02749-7f2b-456d-b9f1-7869300375d4',
            'next_hops': [{
                'local_endpoint': '10.0.0.3',
                'ingress': '2b17abfa-7afb-4e83-8e15-ad21a6044bb7',
                'weight': 1,
                'mac_address': '12:34:56:78:68:3a'
            }],
            'del_fcs': [],
            'segment_id': 68,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:32:30',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.8',
            'node_type': 'sf_node',
            'egress': 'c5dacf1c-f84a-43e0-8873-b2cba77970af',
            'next_group_id': None,
            'host_id': u'test8',
            'nsp': 256,
            'portchain_id': '10f6a764-6963-4b8e-9ae4-a1e5e805915e',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2b17abfa-7afb-4e83-8e15-ad21a6044bb7'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': (
                    'a57a8160-a202-477b-aca1-e7c006bc93a2')
            }],
            'id': u'1409e7b8-ed6f-41ae-ba6b-8ef96bbb8da9'
        }, {
            'nsi': 253,
            'ingress': '2b17abfa-7afb-4e83-8e15-ad21a6044bb7',
            'next_hops': None,
            'del_fcs': [],
            'segment_id': 68,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:68:3a',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.3',
            'node_type': 'dst_node',
            'egress': None,
            'next_group_id': None,
            'host_id': 'test2',
            'nsp': 256,
            'portchain_id': '10f6a764-6963-4b8e-9ae4-a1e5e805915e',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2b17abfa-7afb-4e83-8e15-ad21a6044bb7'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': (
                    'a57a8160-a202-477b-aca1-e7c006bc93a2')
            }],
            'id': '12a279c1-cf81-4c1b-bac3-e9690465aeaf'
        }, {
            'nsi': 254,
            'ingress': 'b299c792-28c8-4f6a-84a0-589163a9b1d4',
            'next_hops': [{
                'local_endpoint': '10.0.0.3',
                'ingress': '2b17abfa-7afb-4e83-8e15-ad21a6044bb7',
                'weight': 1,
                'mac_address': '12:34:56:78:68:3a'
            }],
            'del_fcs': [],
            'segment_id': 68,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:58:ee',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.4',
            'node_type': 'sf_node',
            'egress': '60d47d04-42c0-4478-9136-6247fd5d058d',
            'next_group_id': None,
            'host_id': 'test4',
            'nsp': 256,
            'portchain_id': '10f6a764-6963-4b8e-9ae4-a1e5e805915e',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2b17abfa-7afb-4e83-8e15-ad21a6044bb7'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': 'a57a8160-a202-477b-aca1-e7c006bc93a2'
            }],
            'id': '1409e7b8-ed6f-41ae-ba6b-8ef96bbb8da9'
        }]
        self.init_agent()
        for port_id in self.port_mapping:
            self.agent.sfc_treat_devices_added_updated(port_id)
        self.assertItemsEqual(
            self.added_flows, [{
                'priority': 10,
                'table': 0,
                'dl_type': 34887,
                'actions': 'resubmit(,5)'
            }, {
                'dl_type': 34887,
                'priority': 10,
                'actions': 'resubmit(,30)'
            }, {
                'priority': 0,
                'table': 30,
                'actions': 'output:1'
            }, {
                'priority': 10,
                'table': 30,
                'actions': 'resubmit(,31)',
                'in_port': 1
            }, {
                'dl_type': 34887,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'actions': (
                    'mod_dl_dst:12:34:56:78:68:3a,'
                    'set_field:68->tun_id,output:[]'
                ),
                'priority': 0,
                'mpls_label': 65790,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0',
                'table': 31,
                'nw_src': '0.0.0.0/0.0.0.0'
            }, {
                'dl_type': 2048,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:2'
                ),
                'priority': 10,
                'tp_dst': '0/0x0',
                'table': 0,
                'tp_src': '0/0x0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'in_port': 42
            }, {
                'dl_type': 34887,
                'actions': 'pop_mpls:0x0800,output:6',
                'priority': 1,
                'mpls_label': 65791,
                'table': 5,
                'dl_dst': '00:01:02:03:05:07'
            }, {
                'dl_type': 2048,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:2'
                ),
                'priority': 10,
                'tp_dst': '0/0x0',
                'table': 0,
                'tp_src': '0/0x0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'in_port': 45
            }, {
                'dl_type': 34887,
                'actions': 'pop_mpls:0x0800,output:44',
                'priority': 1,
                'mpls_label': 65791,
                'table': 5,
                'dl_dst': '00:01:02:03:06:10'
            }, {
                'dl_type': 2048,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:2'
                ),
                'priority': 10,
                'tp_dst': '0/0x0',
                'table': 0,
                'tp_src': '0/0x0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'in_port': 48
            }, {
                'dl_type': 34887,
                'actions': 'pop_mpls:0x0800,output:47',
                'priority': 1,
                'mpls_label': 65791,
                'table': 5,
                'dl_dst': '00:01:02:03:06:13'
            }, {
                'dl_type': 2048,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:2'
                ),
                'priority': 10,
                'tp_dst': '0/0x0',
                'table': 0,
                'tp_src': '0/0x0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'in_port': 43
            }, {
                'priority': 0,
                'table': 31,
                'dl_type': 34887,
                'mpls_label': 65791,
                'actions': 'group:1'
            }, {
                'dl_type': 34887,
                'actions': 'pop_mpls:0x0800,output:46',
                'priority': 1,
                'mpls_label': 65790,
                'table': 5,
                'dl_dst': '00:01:02:03:06:12'
            }]
        )
        self.assertEqual(
            self.group_mapping, {
                1: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:58:ee,'
                        'set_field:68->tun_id,output:[],'
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:fe:38,'
                        'set_field:68->tun_id,output:[],'
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:32:30,'
                        'set_field:68->tun_id,output:[]'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            }
        )

    def test_init_agent_portchain_multi_flow_classifiers_port_pairs(self):
        self.port_mapping = {
            '7b718ad7-c2cc-4de0-9ac0-d5f4b6e975aa': {
                'port_name': 'src_port1',
                'ofport': 6,
                'vif_mac': '00:01:02:03:05:07'
            },
            '9ac01d29-797a-4904-97a0-eecc7661b2ad': {
                'port_name': 'ingress',
                'ofport': 42,
                'vif_mac': '00:01:02:03:06:08'
            },
            '02ebda8f-44e5-41ee-8d80-ec47b3c2732e': {
                'port_name': 'egress',
                'ofport': 43,
                'vif_mac': '00:01:02:03:06:09'
            },
            '32971131-e44c-4aad-85f9-7d9f10d07393': {
                'port_name': 'src_port2',
                'ofport': 44,
                'vif_mac': '00:01:02:03:06:10'
            },
            'b7c69625-9cde-48dd-8858-5d773b002e73': {
                'port_name': 'dst_port1',
                'ofport': 45,
                'vif_mac': '00:01:02:03:06:11'
            },
            '2b7e8e42-b35d-4d49-8397-62088efe144f': {
                'port_name': 'dst_port2',
                'ofport': 46,
                'vif_mac': '00:01:02:03:06:12'
            }
        }
        self.node_flowrules = [{
            'nsi': 255,
            'ingress': None,
            'next_hops': [{
                'local_endpoint': '10.0.0.6',
                'ingress': '9ac01d29-797a-4904-97a0-eecc7661b2ad',
                'weight': 1,
                'mac_address': '12:34:56:78:52:39'
            }],
            'del_fcs': [],
            'segment_id': 82,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:65:d7',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.4',
            'node_type': 'src_node',
            'egress': '7b718ad7-c2cc-4de0-9ac0-d5f4b6e975aa',
            'next_group_id': 1,
            'host_id': 'test3',
            'nsp': 256,
            'portchain_id': 'd92114e8-56df-4bd7-9cf2-fce5ac01c94f',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2b7e8e42-b35d-4d49-8397-62088efe144f'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '7b718ad7-c2cc-4de0-9ac0-d5f4b6e975aa'
            }],
            'id': u'44c469bf-6c48-4f8f-bb4f-de87b44b02b6'
        }, {
            'nsi': 254,
            'ingress': '9ac01d29-797a-4904-97a0-eecc7661b2ad',
            'next_hops': [{
                'local_endpoint': '10.0.0.3',
                'ingress': 'b7c69625-9cde-48dd-8858-5d773b002e73',
                'weight': 1,
                'mac_address': '12:34:56:78:36:e9'
            }, {
                'local_endpoint': '10.0.0.5',
                'ingress': '2b7e8e42-b35d-4d49-8397-62088efe144f',
                'weight': 1,
                'mac_address': '12:34:56:78:51:9a'
            }],
            'del_fcs': [],
            'segment_id': 82,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:52:39',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.6',
            'node_type': 'sf_node',
            'egress': '02ebda8f-44e5-41ee-8d80-ec47b3c2732e',
            'next_group_id': None,
            'host_id': 'test6',
            'nsp': 256,
            'portchain_id': 'd92114e8-56df-4bd7-9cf2-fce5ac01c94f',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    'b7c69625-9cde-48dd-8858-5d773b002e73'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '32971131-e44c-4aad-85f9-7d9f10d07393'
            }, {
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2b7e8e42-b35d-4d49-8397-62088efe144f'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': '7b718ad7-c2cc-4de0-9ac0-d5f4b6e975aa'
            }],
            'id': u'c065e0c3-a904-4bac-adf2-f038b717c9c2'
        }, {
            'nsi': 255,
            'ingress': None,
            'next_hops': [{
                'local_endpoint': '10.0.0.6',
                'ingress': '9ac01d29-797a-4904-97a0-eecc7661b2ad',
                'weight': 1,
                'mac_address': '12:34:56:78:52:39'
            }],
            'del_fcs': [],
            'segment_id': 82,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:41:cf',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.2',
            'node_type': 'src_node',
            'egress': '32971131-e44c-4aad-85f9-7d9f10d07393',
            'next_group_id': 1,
            'host_id': 'test1',
            'nsp': 256,
            'portchain_id': 'd92114e8-56df-4bd7-9cf2-fce5ac01c94f',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    'b7c69625-9cde-48dd-8858-5d773b002e73'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': (
                    '32971131-e44c-4aad-85f9-7d9f10d07393')
            }],
            'id': u'44c469bf-6c48-4f8f-bb4f-de87b44b02b6'
        }, {
            'nsi': 253,
            'ingress': 'b7c69625-9cde-48dd-8858-5d773b002e73',
            'next_hops': None,
            'del_fcs': [],
            'segment_id': 82,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:36:e9',
            'network_type': 'gre',
            'local_endpoint': '10.0.0.3',
            'node_type': 'dst_node',
            'egress': None,
            'next_group_id': None,
            'host_id': 'test2',
            'nsp': 256,
            'portchain_id': 'd92114e8-56df-4bd7-9cf2-fce5ac01c94f',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    'b7c69625-9cde-48dd-8858-5d773b002e73'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': (
                    '32971131-e44c-4aad-85f9-7d9f10d07393')
            }],
            'id': '4a61e567-4210-41d9-af82-e01b9da47230'
        }, {
            'nsi': 253,
            'ingress': '2b7e8e42-b35d-4d49-8397-62088efe144f',
            'next_hops': None,
            'del_fcs': [],
            'segment_id': 82,
            'group_refcnt': 1,
            'mac_address': '12:34:56:78:51:9a',
            'network_type': 'gre',
            'local_endpoint': u'10.0.0.5',
            'node_type': 'dst_node',
            'egress': None,
            'next_group_id': None,
            'host_id': 'test4',
            'nsp': 256,
            'portchain_id': 'd92114e8-56df-4bd7-9cf2-fce5ac01c94f',
            'add_fcs': [{
                'source_port_range_min': None,
                'destination_ip_prefix': None,
                'protocol': None,
                'ethertype': 'IPv4',
                'l7_parameters': {},
                'source_port_range_max': None,
                'source_ip_prefix': None,
                'logical_destination_port': (
                    '2b7e8e42-b35d-4d49-8397-62088efe144f'),
                'destination_port_range_min': None,
                'destination_port_range_max': None,
                'logical_source_port': (
                    '7b718ad7-c2cc-4de0-9ac0-d5f4b6e975aa')
            }],
            'id': '4a61e567-4210-41d9-af82-e01b9da47230'
        }]
        self.init_agent()
        for port_id in self.port_mapping:
            self.agent.sfc_treat_devices_added_updated(port_id)
        self.assertItemsEqual(
            self.added_flows, [{
                'actions': 'resubmit(,5)',
                'dl_type': 34887,
                'priority': 10,
                'table': 0
            }, {
                'actions': 'resubmit(,30)',
                'dl_type': 34887,
                'priority': 10
            }, {
                'actions': 'output:1',
                'priority': 0,
                'table': 30
            }, {
                'actions': 'resubmit(,31)',
                'in_port': 1,
                'priority': 10,
                'table': 30
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:2'
                ),
                'dl_type': 2048,
                'in_port': 44,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'group:1',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 0,
                'table': 31
            }, {
                'actions': 'pop_mpls:0x0800,output:45',
                'dl_dst': '00:01:02:03:06:11',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:36:e9,'
                    'set_field:82->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65790,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 0,
                'table': 31,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65790,'
                    'set_mpls_ttl:254,output:2'
                ),
                'dl_type': 2048,
                'in_port': 43,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': (
                    'mod_dl_dst:12:34:56:78:51:9a,'
                    'set_field:82->tun_id,output:[]'
                ),
                'dl_type': 34887,
                'mpls_label': 65790,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 0,
                'table': 31,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }, {
                'actions': 'pop_mpls:0x0800,output:42',
                'dl_dst': '00:01:02:03:06:08',
                'dl_type': 34887,
                'mpls_label': 65791,
                'priority': 1,
                'table': 5
            }, {
                'actions': 'pop_mpls:0x0800,output:46',
                'dl_dst': '00:01:02:03:06:12',
                'dl_type': 34887,
                'mpls_label': 65790,
                'priority': 1,
                'table': 5
            }, {
                'actions': (
                    'push_mpls:0x8847,'
                    'set_mpls_label:65791,'
                    'set_mpls_ttl:255,output:2'
                ),
                'dl_type': 2048,
                'in_port': 6,
                'nw_dst': '0.0.0.0/0.0.0.0',
                'nw_src': '0.0.0.0/0.0.0.0',
                'priority': 10,
                'table': 0,
                'tp_dst': '0/0x0',
                'tp_src': '0/0x0'
            }]
        )
        self.assertEqual(
            self.group_mapping, {
                1: {
                    'buckets': (
                        'bucket=weight=1,'
                        'mod_dl_dst:12:34:56:78:52:39,'
                        'set_field:82->tun_id,output:[]'
                    ),
                    'group_id': 1,
                    'type': 'select'
                }
            }
        )
