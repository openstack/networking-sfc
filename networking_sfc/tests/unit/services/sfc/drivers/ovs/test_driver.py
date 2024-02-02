# Copyright 2015 Huawei.  All rights reserved.
# Copyright 2017 Intel Corporation.
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

from unittest import mock

from eventlet import greenthread
from neutron.api import extensions as api_ext
from neutron.common import config
from neutron.plugins.ml2.drivers import type_vxlan
from neutron_lib.api.definitions import portbindings
from neutron_lib import context
from neutron_lib import rpc as n_rpc
from oslo_utils import importutils

from networking_sfc.db import flowclassifier_db as fdb
from networking_sfc.db import sfc_db
from networking_sfc.extensions import flowclassifier
from networking_sfc.extensions import servicegraph
from networking_sfc.extensions import sfc
from networking_sfc.extensions import tap
from networking_sfc.services.sfc.common import context as sfc_ctx
from networking_sfc.services.sfc.common import exceptions as sfc_exc
from networking_sfc.services.sfc.drivers.ovs import driver
from networking_sfc.services.sfc.drivers.ovs import rpc
from networking_sfc.tests import base
from networking_sfc.tests.unit.db import test_flowclassifier_db
from networking_sfc.tests.unit.db import test_sfc_db


class OVSSfcDriverTestCase(
    test_sfc_db.SfcDbPluginTestCaseBase,
    test_flowclassifier_db.FlowClassifierDbPluginTestCaseBase,
    base.NeutronDbPluginV2TestCase
):

    resource_prefix_map = dict([
        (k, sfc.SFC_PREFIX)
        for k in sfc.RESOURCE_ATTRIBUTE_MAP.keys()
    ] + [
        (k, flowclassifier.FLOW_CLASSIFIER_PREFIX)
        for k in flowclassifier.RESOURCE_ATTRIBUTE_MAP.keys()
    ] + [
        (k, servicegraph.SG_PREFIX)
        for k in servicegraph.RESOURCE_ATTRIBUTE_MAP.keys()
    ])

    def record_rpc(self, method, data):
        self.rpc_calls[method].append(data)

    def ask_agent_to_update_flow_rules(self, context, flows):
        self.record_rpc('update_flow_rules', flows)

    def ask_agent_to_delete_flow_rules(self, context, flows):
        self.record_rpc('delete_flow_rules', flows)

    def ask_agent_to_update_src_node_flow_rules(self, context, flows):
        self.record_rpc('update_src_node_flow_rules', flows)

    def ask_agent_to_delete_src_node_flow_rules(self, context, flows):
        self.record_rpc('delete_src_node_flow_rules', flows)

    def spawn(self, function, *args, **kwargs):
        self.threads.append(self.backup_spawn(function, *args, **kwargs))

    def wait(self):
        for thread in self.threads:
            thread.wait()

    def get_endpoint_by_host(self, host):
        ip_address = self.host_endpoint_mapping.get(host)
        return {'host': host, 'ip_address': ip_address}

    def init_rpc_calls(self):
        self.rpc_calls = {
            'update_flow_rules': [], 'delete_flow_rules': [],
            'update_src_node_flow_rules': [],
            'delete_src_node_flow_rules': []
        }

    def setUp(self):
        sfc_plugin = test_sfc_db.DB_SFC_PLUGIN_CLASS
        flowclassifier_plugin = (
            test_flowclassifier_db.DB_FLOWCLASSIFIER_PLUGIN_CLASS)

        service_plugins = {
            sfc.SFC_EXT: sfc_plugin,
            flowclassifier.FLOW_CLASSIFIER_EXT: flowclassifier_plugin
        }
        sfc_db.SfcDbPlugin.supported_extension_aliases = [
            sfc.SFC_EXT, servicegraph.SG_EXT, tap.TAP_EXT]
        sfc_db.SfcDbPlugin.path_prefix = sfc.SFC_PREFIX
        fdb.FlowClassifierDbPlugin.supported_extension_aliases = [
            flowclassifier.FLOW_CLASSIFIER_EXT]
        fdb.FlowClassifierDbPlugin.path_prefix = (
            flowclassifier.FLOW_CLASSIFIER_PREFIX
        )
        super(OVSSfcDriverTestCase, self).setUp(
            ext_mgr=None,
            plugin=None,
            service_plugins=service_plugins
        )
        self.sfc_plugin = importutils.import_object(sfc_plugin)
        self.flowclassifier_plugin = importutils.import_object(
            flowclassifier_plugin)
        ext_mgr = api_ext.PluginAwareExtensionManager.get_instance()
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.init_rpc_calls()
        self.hostname = 'testhost'
        self.ctx = context.get_admin_context()
        self.backup_notifier_creator = rpc.SfcAgentRpcClient
        self.mocked_notifier = mock.Mock()
        self.mocked_notifier.ask_agent_to_update_flow_rules = mock.Mock(
            side_effect=self.ask_agent_to_update_flow_rules
        )
        self.mocked_notifier.ask_agent_to_delete_flow_rules = mock.Mock(
            side_effect=self.ask_agent_to_delete_flow_rules
        )
        self.mocked_notifier.ask_agent_to_delete_src_node_flow_rules = (
            mock.Mock(
                side_effect=self.ask_agent_to_delete_src_node_flow_rules
            )
        )
        self.mocked_notifier.ask_agent_to_update_src_node_flow_rules = (
            mock.Mock(
                side_effect=self.ask_agent_to_update_src_node_flow_rules
            )
        )
        rpc.SfcAgentRpcClient = mock.Mock(
            return_value=self.mocked_notifier)
        self.backup_conn_creator = n_rpc.Connection
        n_rpc.Connection = mock.Mock()
        n_rpc.Connection.return_value = mock.Mock()
        self.threads = []
        self.backup_spawn = greenthread.spawn
        greenthread.spawn = mock.Mock(
            side_effect=self.spawn)
        self.host_endpoint_mapping = {}
        self.backup_get_endpoint_by_host = (
            type_vxlan.VxlanTypeDriver.get_endpoint_by_host)
        type_vxlan.VxlanTypeDriver.get_endpoint_by_host = mock.Mock(
            side_effect=self.get_endpoint_by_host)
        self.driver = driver.OVSSfcDriver()
        self.driver.initialize()

    def tearDown(self):
        rpc.SfcAgentRpcClient = self.backup_notifier_creator
        n_rpc.Connection = self.backup_conn_creator
        greenthread.spawn = self.backup_spawn
        type_vxlan.VxlanTypeDriver.get_endpoint_by_host = (
            self.backup_get_endpoint_by_host)
        self.init_rpc_calls()
        super(OVSSfcDriverTestCase, self).tearDown()

    def map_flow_rules(self, flow_rules, *args):
        flow_rule_dict = {}
        for arg in args:
            if arg:
                flow_rules = flow_rules + arg
        for flow_rule in flow_rules:
            ingress = flow_rule['ingress'] or ''
            egress = flow_rule['egress'] or ''
            key = self.build_ingress_egress(
                flow_rule['portchain_id'], ingress, egress)
            if key in flow_rule_dict:
                flow_rule_by_key = flow_rule_dict[key]
                for flow_key, flow_value in flow_rule.items():
                    if flow_key not in flow_rule_by_key:
                        flow_rule_by_key[flow_key] = flow_value
                    elif isinstance(flow_value, list):
                        flow_rule_item = flow_rule_by_key[flow_key]
                        for flow_item in flow_value:
                            if flow_item not in flow_rule_item:
                                flow_rule_item.append(flow_item)
                    else:
                        flow_rule_by_key[flow_key] = flow_value
            else:
                flow_rule_dict[key] = flow_rule
        return flow_rule_dict

    def build_ingress_egress(self, pc_id, ingress, egress):
        return '%s:%s:%s' % (pc_id[:8] or '', ingress or '', egress or '')

    def build_ingress_egress_from_pp(self, pc_id, pp):
        # pp must be a dict of Port Pairs' attributes
        return '%s:%s:%s' % (pc_id[:8] or '', pp.get(
            'ingress') or '', pp.get('egress') or '')

    def next_hops_info(self, next_hops):
        info = {}
        if not next_hops:
            return info
        for next_hop in next_hops:
            if next_hop['in_mac_address'] is None:
                info[next_hop['mac_address']] = next_hop['local_endpoint']
            else:
                info[next_hop['in_mac_address']] = next_hop['local_endpoint']
        return info

    def test_create_port_chain(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1',
        }) as pg:
            pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pg['port_pair_group']
            )
            self.driver.create_port_pair_group(pg_context)
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg['port_pair_group']['id']]
            }) as pc:
                pc_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc['port_chain']
                )
                self.driver.create_port_chain(pc_context)
                self.wait()
                self.assertEqual(self.rpc_calls['update_flow_rules'], [])

    def test_create_port_chain_with_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']]
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'port_pair_groups': [pg['port_pair_group']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            pp['port_pair']['ingress'],
                            pp['port_pair']['egress'])
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1})
                        self.assertEqual(
                            update_flow_rules[flow1]['add_fcs'],
                            [])
                        self.assertEqual(
                            update_flow_rules[flow1]['del_fcs'],
                            [])
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'sf_node')
                        self.assertIsNone(
                            update_flow_rules[flow1].get('next_hops')
                        )
                        self.assertIsNone(
                            update_flow_rules[flow1]['next_group_id']
                        )

    def _test_create_port_chain_with_pp_fc_and_no_sfc_proxy(self, correlation):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id'],
                    'service_function_parameters': {'correlation': correlation}
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']],
                            'chain_parameters': {'correlation': correlation}
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            # flow1 - src_node
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port['port']['id'])
                            # flow2 - sf_node
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id']
                            )
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                set([flow1, flow2]))

                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow1]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')

                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow2]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'sf_node')

                            # src_node flow rule doesn't have pp_corr:
                            self.assertIsNone(
                                update_flow_rules[flow1]['pp_corr'])
                            # but the sf_node does:
                            self.assertEqual(
                                update_flow_rules[flow2]['pp_corr'],
                                correlation
                            )
                            # sf_node from src_node's next_hops:
                            self.assertEqual(
                                update_flow_rules[flow1][
                                    'next_hops'][0]['pp_corr'],
                                correlation
                            )
                            # pc_corr should be present in any kind of node
                            self.assertEqual(
                                update_flow_rules[flow1]['pc_corr'],
                                correlation
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['pc_corr'],
                                correlation
                            )

    def test_create_port_chain_with_pp_fc_and_no_sfc_proxy_mpls(self):
        self._test_create_port_chain_with_pp_fc_and_no_sfc_proxy('mpls')

    def test_create_port_chain_with_pp_fc_and_no_sfc_proxy_nsh(self):
        self._test_create_port_chain_with_pp_fc_and_no_sfc_proxy('nsh')

    def test_create_port_chain_with_flow_classifiers(self):
        with self.port(
            name='src',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': []
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'], None,
                            fc['flow_classifier']['logical_source_port'])
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1})
                        self.assertEqual(
                            len(update_flow_rules[flow1]['add_fcs']), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': '10.200.0.0/16',
                            'destination_port_range_max': 400,
                            'destination_port_range_min': 300,
                            'ethertype': 'IPv4',
                            'l7_parameters': {},
                            'protocol': u'tcp',
                            'source_ip_prefix': u'10.100.0.0/16',
                            'source_port_range_max': 200,
                            'source_port_range_min': 100
                        }, update_flow_rules[flow1]['add_fcs'][0])
                        self.assertEqual(
                            update_flow_rules[flow1]['del_fcs'],
                            [])
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'src_node')
                        self.assertIsNone(
                            update_flow_rules[flow1].get('next_hops')
                        )
                        self.assertIsNotNone(
                            update_flow_rules[flow1]['next_group_id']
                        )

    def test_create_port_chain_with_flow_classifiers_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id']
                            )
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow1]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow2]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'sf_node')

    def test_create_port_chain_with_fc_ppg_n_tuple_mapping(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']],
                        'port_pair_group_parameters': {
                            'ppg_n_tuple_mapping': {
                                'ingress_n_tuple': {},
                                'egress_n_tuple': {
                                    'source_ip_prefix': '10.300.0.10/16'}
                            }
                        }
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id']
                            )
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow1]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.300.0.10/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow2]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'sf_node')

    def test_create_port_chain_multi_port_groups_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='egress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='ingress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='egress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2, self.port(
            name='ingress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress3, self.port(
            name='egress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress3:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress1['port']['id'],
                    'egress': egress1['port']['id']
                }) as pp1, self.port_pair(port_pair={
                    'ingress': ingress2['port']['id'],
                    'egress': egress2['port']['id']
                }) as pp2, self.port_pair(port_pair={
                    'ingress': ingress3['port']['id'],
                    'egress': egress3['port']['id']
                }) as pp3:
                    pp1_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp1['port_pair']
                    )
                    self.driver.create_port_pair(pp1_context)
                    pp2_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp2['port_pair']
                    )
                    self.driver.create_port_pair(pp2_context)
                    pp3_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp3['port_pair']
                    )
                    self.driver.create_port_pair(pp3_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp1['port_pair']['id']]
                    }) as pg1, self.port_pair_group(port_pair_group={
                        'port_pairs': [pp2['port_pair']['id']]
                    }) as pg2, self.port_pair_group(port_pair_group={
                        'port_pairs': [pp3['port_pair']['id']]
                    }) as pg3:
                        pg1_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg1['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg1_context)
                        pg2_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg2['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg2_context)
                        pg3_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg3['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg3_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [
                                pg1['port_pair_group']['id'],
                                pg2['port_pair_group']['id'],
                                pg3['port_pair_group']['id']
                            ],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress1['port']['id'],
                                egress1['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress2['port']['id'],
                                egress2['port']['id'])
                            flow4 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress3['port']['id'],
                                egress3['port']['id'])
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2, flow3, flow4})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src = (
                                src_port['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops')
                            )
                            self.assertEqual(
                                next_hops, {
                                    ingress1['port']['mac_address']: '10.0.0.1'
                                }
                            )
                            self.assertIsNotNone(
                                update_flow_rules[flow1]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress2['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow2]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress3['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow3]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow3]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow4]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow4].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow4]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow4]['node_type'],
                                'sf_node')

    def test_create_port_chain_port_groups_multi_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='egress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='ingress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='egress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2, self.port(
            name='ingress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress3, self.port(
            name='egress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress3:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress1['port']['id'],
                    'egress': egress1['port']['id']
                }) as pp1, self.port_pair(port_pair={
                    'ingress': ingress2['port']['id'],
                    'egress': egress2['port']['id']
                }) as pp2, self.port_pair(port_pair={
                    'ingress': ingress3['port']['id'],
                    'egress': egress3['port']['id']
                }) as pp3:
                    pp1_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp1['port_pair']
                    )
                    self.driver.create_port_pair(pp1_context)
                    pp2_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp2['port_pair']
                    )
                    self.driver.create_port_pair(pp2_context)
                    pp3_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp3['port_pair']
                    )
                    self.driver.create_port_pair(pp3_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [
                            pp1['port_pair']['id'],
                            pp2['port_pair']['id'],
                            pp3['port_pair']['id']
                        ]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [
                                pg['port_pair_group']['id']
                            ],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress1['port']['id'],
                                egress1['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress2['port']['id'],
                                egress2['port']['id'])
                            flow4 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress3['port']['id'],
                                egress3['port']['id'])
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2, flow3, flow4})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src = (
                                src_port['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops')
                            )
                            self.assertEqual(next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                                ingress2['port']['mac_address']: '10.0.0.1',
                                ingress3['port']['mac_address']: '10.0.0.1'
                            })
                            self.assertIsNotNone(
                                update_flow_rules[flow1]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow2]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow3]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow3]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow4]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow4].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow4]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow4]['node_type'],
                                'sf_node')

    def test_create_port_chain_multi_port_groups_multi_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='egress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='ingress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='egress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2, self.port(
            name='ingress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress3, self.port(
            name='egress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress3, self.port(
            name='ingress4',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress4, self.port(
            name='egress4',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress4:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress1['port']['id'],
                    'egress': egress1['port']['id']
                }) as pp1, self.port_pair(port_pair={
                    'ingress': ingress2['port']['id'],
                    'egress': egress2['port']['id']
                }) as pp2, self.port_pair(port_pair={
                    'ingress': ingress3['port']['id'],
                    'egress': egress3['port']['id']
                }) as pp3, self.port_pair(port_pair={
                    'ingress': ingress4['port']['id'],
                    'egress': egress4['port']['id']
                }) as pp4:
                    pp1_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp1['port_pair']
                    )
                    self.driver.create_port_pair(pp1_context)
                    pp2_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp2['port_pair']
                    )
                    self.driver.create_port_pair(pp2_context)
                    pp3_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp3['port_pair']
                    )
                    self.driver.create_port_pair(pp3_context)
                    pp4_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp4['port_pair']
                    )
                    self.driver.create_port_pair(pp4_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [
                            pp1['port_pair']['id'],
                            pp2['port_pair']['id']
                        ]
                    }) as pg1, self.port_pair_group(port_pair_group={
                        'port_pairs': [
                            pp3['port_pair']['id'],
                            pp4['port_pair']['id']
                        ]
                    }) as pg2:
                        pg1_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg1['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg1_context)
                        pg2_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg2['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg2_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [
                                pg1['port_pair_group']['id'],
                                pg2['port_pair_group']['id']
                            ],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress1['port']['id'],
                                egress1['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress2['port']['id'],
                                egress2['port']['id'])
                            flow4 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress3['port']['id'],
                                egress3['port']['id'])
                            flow5 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress4['port']['id'],
                                egress4['port']['id'])
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2, flow3, flow4, flow5})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src = (
                                src_port['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops')
                            )
                            self.assertEqual(next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                                ingress2['port']['mac_address']: '10.0.0.1',
                            })
                            self.assertIsNotNone(
                                update_flow_rules[flow1]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(next_hops, {
                                ingress3['port']['mac_address']: '10.0.0.1',
                                ingress4['port']['mac_address']: '10.0.0.1'
                            })
                            self.assertIsNotNone(
                                update_flow_rules[flow2]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow3].get('next_hops'))
                            self.assertEqual(next_hops, {
                                ingress3['port']['mac_address']: '10.0.0.1',
                                ingress4['port']['mac_address']: '10.0.0.1'
                            })
                            self.assertIsNotNone(
                                update_flow_rules[flow3]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow3]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow4]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow4].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow4]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow4]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow5]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow5].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow5]['next_group_id']
                            )
                            self.assertEqual(
                                update_flow_rules[flow5]['node_type'],
                                'sf_node')

    def test_create_port_chain_with_multi_flow_classifiers_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port1, self.port(
            name='port3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port2, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port1['port']['id']
            }) as fc1, self.flow_classifier(flow_classifier={
                'logical_source_port': src_port2['port']['id']
            }) as fc2:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [
                                fc1['flow_classifier']['id'],
                                fc2['flow_classifier']['id']
                            ]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port1['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port2['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id'])
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2, flow3})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src1 = (
                                src_port1['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src1,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                    ingress['port']['mac_address']: '10.0.0.1'
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src2 = (
                                src_port2['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src2,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                    ingress['port']['mac_address']: '10.0.0.1'
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 2)
                            self._assert_flow_classifiers_match_subsets(
                                add_fcs,
                                [{
                                    'destination_ip_prefix': None,
                                    'destination_port_range_max': None,
                                    'destination_port_range_min': None,
                                    'ethertype': 'IPv4',
                                    'l7_parameters': {},
                                    'protocol': None,
                                    'source_ip_prefix': ip_src1,
                                    'source_port_range_max': None,
                                    'source_port_range_min': None
                                }, {
                                    'destination_ip_prefix': None,
                                    'destination_port_range_max': None,
                                    'destination_port_range_min': None,
                                    'ethertype': 'IPv4',
                                    'l7_parameters': {},
                                    'protocol': None,
                                    'source_ip_prefix': ip_src2,
                                    'source_port_range_max': None,
                                    'source_port_range_min': None
                                }],
                                'source_ip_prefix')
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow3]['node_type'],
                                'sf_node')

    def test_delete_port_chain(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1',
        }) as pg:
            pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pg['port_pair_group']
            )
            self.driver.create_port_pair_group(pg_context)
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg['port_pair_group']['id']]
            }) as pc:
                pc_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc['port_chain']
                )
                self.driver.create_port_chain(pc_context)
                self.wait()
                self.driver.delete_port_chain(pc_context)
                self.wait()
                self.assertEqual(
                    self.rpc_calls['delete_flow_rules'], [])

    def test_delete_port_chain_with_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']]
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'port_pair_groups': [pg['port_pair_group']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.driver.delete_port_chain(pc_context)
                        self.wait()
                        delete_flow_rules = self.map_flow_rules(
                            self.rpc_calls['delete_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            pp['port_pair']['ingress'],
                            pp['port_pair']['egress'])
                        self.assertEqual(
                            set(delete_flow_rules.keys()),
                            {flow1})
                        self.assertEqual(
                            delete_flow_rules[flow1]['add_fcs'],
                            [])
                        self.assertEqual(
                            delete_flow_rules[flow1]['del_fcs'],
                            [])
                        self.assertEqual(
                            delete_flow_rules[flow1]['node_type'],
                            'sf_node')

    def test_delete_port_chain_with_flow_classifiers(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': []
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.driver.delete_port_chain(pc_context)
                        self.wait()
                        delete_flow_rules = self.map_flow_rules(
                            self.rpc_calls['delete_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None,
                            src_port['port']['id'])
                        self.assertEqual(
                            set(delete_flow_rules.keys()),
                            {flow1})
                        self.assertEqual(
                            delete_flow_rules[flow1]['add_fcs'],
                            [])
                        del_fcs = delete_flow_rules[flow1]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': u'10.200.0.0/16',
                            'destination_port_range_max': 400,
                            'destination_port_range_min': 300,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': u'tcp',
                            'source_ip_prefix': u'10.100.0.0/16',
                            'source_port_range_max': 200,
                            'source_port_range_min': 100
                        }, del_fcs[0])
                        self.assertEqual(
                            delete_flow_rules[flow1]['node_type'],
                            'src_node')

    def test_delete_port_chain_with_flow_classifiers_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            self.init_rpc_calls()
                            self.driver.delete_port_chain(pc_context)
                            self.wait()
                            delete_flow_rules = self.map_flow_rules(
                                self.rpc_calls['delete_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port['port']['id']
                            )
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id']
                            )
                            self.assertEqual(
                                set(delete_flow_rules.keys()),
                                {flow1, flow2})
                            del_fcs = delete_flow_rules[flow1]['del_fcs']
                            self.assertEqual(len(del_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, del_fcs[0])
                            next_hops = self.next_hops_info(
                                delete_flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertEqual(
                                delete_flow_rules[flow1]['node_type'],
                                'src_node')
                            del_fcs = delete_flow_rules[flow2]['del_fcs']
                            self.assertEqual(len(del_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, del_fcs[0])
                            next_hops = self.next_hops_info(
                                delete_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertEqual(
                                delete_flow_rules[flow2]['node_type'],
                                'sf_node')

    def test_update_port_chain_add_port_pair(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='port4',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='port5',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='port6',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc, self.port_pair(port_pair={
                'ingress': ingress1['port']['id'],
                'egress': egress1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress2['port']['id'],
                'egress': egress2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id'],
                    ]
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.init_rpc_calls()
                        updates = {
                            'port_pairs': [
                                pp1['port_pair']['id'],
                                pp2['port_pair']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_pair_groups', {'port_pair_group': updates},
                            pg['port_pair_group']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pg2 = self.deserialize(
                            self.fmt, res
                        )
                        pg2['port_pair_group']['port_chains'] = [
                            pc['port_chain']['id']
                        ]
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg2['port_pair_group'],
                            original_portpairgroup=pg['port_pair_group']
                        )
                        self.driver.update_port_pair_group(pg_context)
                        self.wait()
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port['port']['id'])
                        flow2 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress2['port']['id'], egress2['port']['id'])
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1, flow2})
                        add_fcs = update_flow_rules[flow1]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        ip_src = (
                            src_port['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                                ingress2['port']['mac_address']: '10.0.0.1'
                            }
                        )
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'src_node')
                        add_fcs = update_flow_rules[flow2]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {}
                        )
                        self.assertEqual(
                            update_flow_rules[flow2]['node_type'],
                            'sf_node')

    def test_update_port_chain_delete_port_pair(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='port4',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='port5',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='port6',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc, self.port_pair(port_pair={
                'ingress': ingress1['port']['id'],
                'egress': egress1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress2['port']['id'],
                'egress': egress2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id'],
                        pp2['port_pair']['id']
                    ]
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.init_rpc_calls()
                        updates = {
                            'port_pairs': [
                                pp1['port_pair']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_pair_groups', {'port_pair_group': updates},
                            pg['port_pair_group']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pg2 = self.deserialize(
                            self.fmt, res
                        )
                        pg2['port_pair_group']['port_chains'] = [
                            pc['port_chain']['id']
                        ]
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg2['port_pair_group'],
                            original_portpairgroup=pg['port_pair_group']
                        )
                        self.driver.update_port_pair_group(pg_context)
                        self.wait()
                        delete_flow_rules = self.map_flow_rules(
                            self.rpc_calls['delete_flow_rules'])
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port['port']['id'])
                        flow2 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress2['port']['id'], egress2['port']['id'])
                        self.assertEqual(
                            set(delete_flow_rules.keys()),
                            {flow1, flow2})
                        del_fcs = delete_flow_rules[flow1]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        ip_src = (
                            src_port['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                                ingress2['port']['mac_address']: '10.0.0.1'
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow1]['node_type'],
                            'src_node')
                        del_fcs = delete_flow_rules[flow2]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow2]['node_type'],
                            'sf_node')
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1})
                        add_fcs = update_flow_rules[flow1]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {ingress1['port']['mac_address']: '10.0.0.1'}
                        )
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'src_node')

    def test_update_port_chain_replace_port_pair(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='port4',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='port5',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='port6',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc, self.port_pair(port_pair={
                'ingress': ingress1['port']['id'],
                'egress': egress1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress2['port']['id'],
                'egress': egress2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.init_rpc_calls()
                        updates = {
                            'port_pairs': [
                                pp2['port_pair']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_pair_groups', {'port_pair_group': updates},
                            pg['port_pair_group']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pg2 = self.deserialize(
                            self.fmt, res
                        )
                        pg2['port_pair_group']['port_chains'] = [
                            pc['port_chain']['id']
                        ]
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg2['port_pair_group'],
                            original_portpairgroup=pg['port_pair_group']
                        )
                        self.driver.update_port_pair_group(pg_context)
                        self.wait()
                        delete_flow_rules = self.map_flow_rules(
                            self.rpc_calls['delete_flow_rules'])
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port['port']['id'])
                        flow2 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress1['port']['id'], egress1['port']['id'])
                        flow3 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress2['port']['id'], egress2['port']['id'])
                        self.assertEqual(
                            set(delete_flow_rules.keys()),
                            {flow1, flow2})
                        del_fcs = delete_flow_rules[flow1]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        ip_src = (
                            src_port['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow1]['node_type'],
                            'src_node')
                        del_fcs = delete_flow_rules[flow2]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow2]['node_type'],
                            'sf_node')
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1, flow3})
                        add_fcs = update_flow_rules[flow1]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {ingress2['port']['mac_address']: '10.0.0.1'}
                        )
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'src_node')
                        add_fcs = update_flow_rules[flow3]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow3].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {}
                        )
                        self.assertEqual(
                            update_flow_rules[flow3]['node_type'],
                            'sf_node')

    def test_update_port_chain_replace_flow_classifier(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port1, self.port(
            name='port3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port2, self.port(
            name='port5',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='port6',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port1['port']['id']
            }) as fc1, self.flow_classifier(flow_classifier={
                'logical_source_port': src_port2['port']['id']
            }) as fc2, self.port_pair(port_pair={
                'ingress': ingress['port']['id'],
                'egress': egress['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp['port_pair']['id']
                    ]
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [
                            fc1['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.init_rpc_calls()
                        updates = {
                            'flow_classifiers': [
                                fc2['flow_classifier']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )
                        self.driver.update_port_chain(pc_context)
                        self.wait()
                        delete_flow_rules = self.map_flow_rules(
                            self.rpc_calls['delete_flow_rules'])
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port1['port']['id'])
                        flow2 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port2['port']['id'])
                        flow3 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress['port']['id'], egress['port']['id'])
                        self.assertEqual(
                            set(delete_flow_rules.keys()),
                            {flow1, flow3})
                        del_fcs = delete_flow_rules[flow1]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        ip_src1 = (
                            src_port1['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src1,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress['port']['mac_address']: '10.0.0.1',
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow1]['node_type'],
                            'src_node')
                        del_fcs = delete_flow_rules[flow3]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        ip_src2 = (
                            src_port2['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src1,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow3].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {}
                        )
                        self.assertEqual(
                            delete_flow_rules[flow3]['node_type'],
                            'sf_node')
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow2, flow3})
                        add_fcs = update_flow_rules[flow2]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src2,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {ingress['port']['mac_address']: '10.0.0.1'}
                        )
                        self.assertEqual(
                            update_flow_rules[flow2]['node_type'],
                            'src_node')
                        add_fcs = update_flow_rules[flow3]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src2,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow3].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {}
                        )
                        self.assertEqual(
                            update_flow_rules[flow3]['node_type'],
                            'sf_node')

    def test_update_port_chain_add_port_pair_group(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port5',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='port6',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='port7',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='port8',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc, self.port_pair(port_pair={
                'ingress': ingress1['port']['id'],
                'egress': egress1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress2['port']['id'],
                'egress': egress2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as pg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as pg2:
                    pg1_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg1['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg1_context)
                    pg2_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg2['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg2_context)
                    with self.port_chain(port_chain={
                        'port_pair_groups': [pg1['port_pair_group']['id']],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.init_rpc_calls()
                        updates = {
                            'port_pair_groups': [
                                pg1['port_pair_group']['id'],
                                pg2['port_pair_group']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )
                        self.driver.update_port_chain(pc_context)
                        self.wait()
                        delete_flow_rules = self.map_flow_rules(
                            self.rpc_calls['delete_flow_rules'])
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port['port']['id'])
                        flow2 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress1['port']['id'], egress1['port']['id'])
                        flow3 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress2['port']['id'], egress2['port']['id'])
                        self.assertEqual(
                            set(delete_flow_rules.keys()),
                            {flow1, flow2})
                        del_fcs = delete_flow_rules[flow1]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        ip_src = (
                            src_port['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow1]['node_type'],
                            'src_node')
                        del_fcs = delete_flow_rules[flow2]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow2]['node_type'],
                            'sf_node')
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1, flow2, flow3})
                        add_fcs = update_flow_rules[flow1]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1'
                            }
                        )
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'src_node')
                        add_fcs = update_flow_rules[flow2]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress2['port']['mac_address']: '10.0.0.1'
                            }
                        )
                        self.assertEqual(
                            update_flow_rules[flow2]['node_type'],
                            'sf_node')
                        add_fcs = update_flow_rules[flow3]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow3].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {}
                        )
                        self.assertEqual(
                            update_flow_rules[flow3]['node_type'],
                            'sf_node')

    def test_update_port_chain_delete_port_pair_group(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port5',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='port6',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='port7',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='port8',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc, self.port_pair(port_pair={
                'ingress': ingress1['port']['id'],
                'egress': egress1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress2['port']['id'],
                'egress': egress2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as pg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as pg2:
                    pg1_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg1['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg1_context)
                    pg2_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg2['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg2_context)
                    with self.port_chain(port_chain={
                        'port_pair_groups': [
                            pg1['port_pair_group']['id'],
                            pg2['port_pair_group']['id']
                        ],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.init_rpc_calls()
                        updates = {
                            'port_pair_groups': [
                                pg1['port_pair_group']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )
                        self.driver.update_port_chain(pc_context)
                        self.wait()
                        delete_flow_rules = self.map_flow_rules(
                            self.rpc_calls['delete_flow_rules'])
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port['port']['id'])
                        flow2 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress1['port']['id'], egress1['port']['id'])
                        flow3 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress2['port']['id'], egress2['port']['id'])
                        self.assertEqual(
                            set(delete_flow_rules.keys()),
                            {flow1, flow2, flow3})
                        del_fcs = delete_flow_rules[flow1]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        ip_src = (
                            src_port['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow1]['node_type'],
                            'src_node')
                        del_fcs = delete_flow_rules[flow2]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress2['port']['mac_address']: '10.0.0.1',
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow2]['node_type'],
                            'sf_node')
                        del_fcs = delete_flow_rules[flow3]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow3].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow3]['node_type'],
                            'sf_node')
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1, flow2})
                        add_fcs = update_flow_rules[flow1]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1'
                            }
                        )
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'src_node')
                        add_fcs = update_flow_rules[flow2]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                            }
                        )
                        self.assertEqual(
                            update_flow_rules[flow2]['node_type'],
                            'sf_node')

    def test_update_port_chain_replace_port_pair_group(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port5',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='port6',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='port7',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='port8',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc, self.port_pair(port_pair={
                'ingress': ingress1['port']['id'],
                'egress': egress1['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': ingress2['port']['id'],
                'egress': egress2['port']['id']
            }) as pp2:
                pp1_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp1['port_pair']
                )
                self.driver.create_port_pair(pp1_context)
                pp2_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp2['port_pair']
                )
                self.driver.create_port_pair(pp2_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as pg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as pg2:
                    pg1_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg1['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg1_context)
                    pg2_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg2['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg2_context)
                    with self.port_chain(port_chain={
                        'port_pair_groups': [pg1['port_pair_group']['id']],
                        'flow_classifiers': [
                            fc['flow_classifier']['id']
                        ]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        self.init_rpc_calls()
                        updates = {
                            'port_pair_groups': [
                                pg2['port_pair_group']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        pc2 = self.deserialize(
                            self.fmt, res
                        )
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc2['port_chain'],
                            original_portchain=pc['port_chain']
                        )
                        self.driver.update_port_chain(pc_context)
                        self.wait()
                        delete_flow_rules = self.map_flow_rules(
                            self.rpc_calls['delete_flow_rules'])
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port['port']['id'])
                        flow2 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress1['port']['id'], egress1['port']['id'])
                        flow3 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            ingress2['port']['id'], egress2['port']['id'])
                        self.assertEqual(
                            set(delete_flow_rules.keys()),
                            {flow1, flow2})
                        del_fcs = delete_flow_rules[flow1]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        ip_src = (
                            src_port['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow1]['node_type'],
                            'src_node')
                        del_fcs = delete_flow_rules[flow2]['del_fcs']
                        self.assertEqual(len(del_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, del_fcs[0])
                        next_hops = self.next_hops_info(
                            delete_flow_rules[flow2].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                            }
                        )
                        self.assertEqual(
                            delete_flow_rules[flow2]['node_type'],
                            'sf_node')
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1, flow3})
                        add_fcs = update_flow_rules[flow1]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow1].get('next_hops'))
                        self.assertEqual(
                            next_hops, {
                                ingress2['port']['mac_address']: '10.0.0.1'
                            }
                        )
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'src_node')
                        add_fcs = update_flow_rules[flow3]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        next_hops = self.next_hops_info(
                            update_flow_rules[flow3].get('next_hops'))
                        self.assertEqual(
                            next_hops,
                            {}
                        )
                        self.assertEqual(
                            update_flow_rules[flow3]['node_type'],
                            'sf_node')

    def test_agent_init_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='port2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']]
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'port_pair_groups': [pg['port_pair_group']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        flow_rules = []
                        flow_rules_by_portid = {}
                        for host, portid in [(
                            src_port['port']['binding:host_id'],
                            src_port['port']['id']
                        ), (
                            dst_port['port']['binding:host_id'],
                            dst_port['port']['id']
                        )]:
                            flow_rules_by_portid[
                                portid
                            ] = self.driver.get_flowrules_by_host_portid(
                                self.ctx, host=host, port_id=portid
                            )
                        flow_rules = self.map_flow_rules(
                            flow_rules, *(flow_rules_by_portid.values())
                        )
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            pp['port_pair']['ingress'],
                            pp['port_pair']['egress'])
                        self.assertEqual(
                            set(flow_rules.keys()),
                            {flow1})
                        self.assertEqual(
                            flow_rules[flow1]['add_fcs'],
                            [])
                        self.assertEqual(
                            flow_rules[flow1]['del_fcs'],
                            [])
                        self.assertEqual(
                            flow_rules[flow1]['node_type'],
                            'sf_node')

    def test_agent_init_flow_classifiers(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': []
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']]
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        flow_rules = []
                        flow_rules_by_portid = {}
                        for host, portid in [(
                            src_port['port']['binding:host_id'],
                            src_port['port']['id']
                        )]:
                            flow_rules_by_portid[
                                portid
                            ] = self.driver.get_flowrules_by_host_portid(
                                self.ctx, host=host, port_id=portid
                            )
                        flow_rules = self.map_flow_rules(
                            flow_rules, *(flow_rules_by_portid.values())
                        )
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None, src_port['port']['id'])
                        self.assertEqual(
                            set(flow_rules.keys()),
                            {flow1})
                        add_fcs = flow_rules[flow1]['add_fcs']
                        self.assertEqual(len(add_fcs), 1)
                        ip_src = (
                            src_port['port']['fixed_ips'][0]['ip_address']
                        )
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': None,
                            'destination_port_range_max': None,
                            'destination_port_range_min': None,
                            'ethertype': u'IPv4',
                            'l7_parameters': {},
                            'protocol': None,
                            'source_ip_prefix': ip_src,
                            'source_port_range_max': None,
                            'source_port_range_min': None
                        }, add_fcs[0])
                        self.assertEqual(
                            flow_rules[flow1]['del_fcs'],
                            [])
                        self.assertEqual(
                            flow_rules[flow1]['node_type'],
                            'src_node')
                        self.assertIsNone(
                            flow_rules[flow1].get('next_hops')
                        )
                        self.assertIsNotNone(
                            flow_rules[flow1]['next_group_id']
                        )

    def test_agent_init_flow_classifiers_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            flow_rules = []
                            flow_rules_by_portid = {}
                            for host, portid in [(
                                src_port['port']['binding:host_id'],
                                src_port['port']['id']
                            ), (
                                ingress['port']['binding:host_id'],
                                ingress['port']['id']
                            ), (
                                egress['port']['binding:host_id'],
                                egress['port']['id']
                            )]:
                                flow_rules_by_portid[
                                    portid
                                ] = self.driver.get_flowrules_by_host_portid(
                                    self.ctx, host=host, port_id=portid
                                )
                            flow_rules = self.map_flow_rules(
                                flow_rules, *(flow_rules_by_portid.values())
                            )
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port['port']['id']
                            )
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id']
                            )
                            self.assertEqual(
                                set(flow_rules.keys()),
                                {flow1, flow2})
                            add_fcs = flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src = (
                                src_port['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertEqual(
                                flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertEqual(
                                flow_rules[flow2]['node_type'],
                                'sf_node')

    def test_agent_init_multi_port_groups_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='egress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='ingress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='egress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2, self.port(
            name='ingress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress3, self.port(
            name='egress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress3:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress1['port']['id'],
                    'egress': egress1['port']['id']
                }) as pp1, self.port_pair(port_pair={
                    'ingress': ingress2['port']['id'],
                    'egress': egress2['port']['id']
                }) as pp2, self.port_pair(port_pair={
                    'ingress': ingress3['port']['id'],
                    'egress': egress3['port']['id']
                }) as pp3:
                    pp1_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp1['port_pair']
                    )
                    self.driver.create_port_pair(pp1_context)
                    pp2_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp2['port_pair']
                    )
                    self.driver.create_port_pair(pp2_context)
                    pp3_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp3['port_pair']
                    )
                    self.driver.create_port_pair(pp3_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp1['port_pair']['id']]
                    }) as pg1, self.port_pair_group(port_pair_group={
                        'port_pairs': [pp2['port_pair']['id']]
                    }) as pg2, self.port_pair_group(port_pair_group={
                        'port_pairs': [pp3['port_pair']['id']]
                    }) as pg3:
                        pg1_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg1['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg1_context)
                        pg2_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg2['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg2_context)
                        pg3_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg3['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg3_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [
                                pg1['port_pair_group']['id'],
                                pg2['port_pair_group']['id'],
                                pg3['port_pair_group']['id']
                            ],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            flow_rules = []
                            flow_rules_by_portid = {}
                            for host, portid in [(
                                src_port['port']['binding:host_id'],
                                src_port['port']['id']
                            ), (
                                ingress1['port']['binding:host_id'],
                                ingress1['port']['id']
                            ), (
                                egress1['port']['binding:host_id'],
                                egress1['port']['id']
                            ), (
                                ingress2['port']['binding:host_id'],
                                ingress2['port']['id']
                            ), (
                                egress2['port']['binding:host_id'],
                                egress2['port']['id']
                            ), (
                                ingress3['port']['binding:host_id'],
                                ingress3['port']['id']
                            ), (
                                egress3['port']['binding:host_id'],
                                egress3['port']['id']
                            )]:
                                flow_rules_by_portid[
                                    portid
                                ] = self.driver.get_flowrules_by_host_portid(
                                    self.ctx, host=host, port_id=portid
                                )
                            flow_rules = self.map_flow_rules(
                                flow_rules, *(flow_rules_by_portid.values())
                            )
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress1['port']['id'],
                                egress1['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress2['port']['id'],
                                egress2['port']['id'])
                            flow4 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress3['port']['id'],
                                egress3['port']['id'])
                            self.assertEqual(
                                set(flow_rules.keys()),
                                {flow1, flow2, flow3, flow4})
                            add_fcs = flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src = (
                                src_port['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow1].get('next_hops')
                            )
                            self.assertEqual(
                                next_hops,
                                {ingress1['port']['mac_address']: '10.0.0.1'})
                            self.assertEqual(
                                flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress2['port']['mac_address']: '10.0.0.1'})
                            self.assertEqual(
                                flow_rules[flow2]['node_type'],
                                'sf_node')
                            add_fcs = flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress3['port']['mac_address']: '10.0.0.1'})
                            self.assertEqual(
                                flow_rules[flow3]['node_type'],
                                'sf_node')
                            add_fcs = flow_rules[flow4]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow4].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertEqual(
                                flow_rules[flow3]['node_type'],
                                'sf_node')

    def test_agent_init_port_groups_multi_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='egress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='ingress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2, self.port(
            name='egress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress2, self.port(
            name='ingress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress3, self.port(
            name='egress3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress3:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress1['port']['id'],
                    'egress': egress1['port']['id']
                }) as pp1, self.port_pair(port_pair={
                    'ingress': ingress2['port']['id'],
                    'egress': egress2['port']['id']
                }) as pp2, self.port_pair(port_pair={
                    'ingress': ingress3['port']['id'],
                    'egress': egress3['port']['id']
                }) as pp3:
                    pp1_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp1['port_pair']
                    )
                    self.driver.create_port_pair(pp1_context)
                    pp2_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp2['port_pair']
                    )
                    self.driver.create_port_pair(pp2_context)
                    pp3_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp3['port_pair']
                    )
                    self.driver.create_port_pair(pp3_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [
                            pp1['port_pair']['id'],
                            pp2['port_pair']['id'],
                            pp3['port_pair']['id']
                        ]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [
                                pg['port_pair_group']['id']
                            ],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            flow_rules = []
                            flow_rules_by_portid = {}
                            for host, portid in [(
                                src_port['port']['binding:host_id'],
                                src_port['port']['id']
                            ), (
                                ingress1['port']['binding:host_id'],
                                ingress1['port']['id']
                            ), (
                                egress1['port']['binding:host_id'],
                                egress1['port']['id']
                            ), (
                                ingress2['port']['binding:host_id'],
                                ingress2['port']['id']
                            ), (
                                egress2['port']['binding:host_id'],
                                egress2['port']['id']
                            ), (
                                ingress3['port']['binding:host_id'],
                                ingress3['port']['id']
                            ), (
                                egress3['port']['binding:host_id'],
                                egress3['port']['id']
                            )]:
                                flow_rules_by_portid[
                                    portid
                                ] = self.driver.get_flowrules_by_host_portid(
                                    self.ctx, host=host, port_id=portid
                                )
                            flow_rules = self.map_flow_rules(
                                flow_rules, *(flow_rules_by_portid.values())
                            )
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress1['port']['id'],
                                egress1['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress2['port']['id'],
                                egress2['port']['id'])
                            flow4 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress3['port']['id'],
                                egress3['port']['id'])
                            self.assertEqual(
                                set(flow_rules.keys()),
                                {flow1, flow2, flow3, flow4})
                            add_fcs = flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src = (
                                src_port['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow1].get('next_hops')
                            )
                            self.assertEqual(next_hops, {
                                ingress1['port']['mac_address']: '10.0.0.1',
                                ingress2['port']['mac_address']: '10.0.0.1',
                                ingress3['port']['mac_address']: '10.0.0.1'
                            })
                            self.assertEqual(
                                flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertEqual(
                                flow_rules[flow2]['node_type'],
                                'sf_node')
                            add_fcs = flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertEqual(
                                flow_rules[flow3]['node_type'],
                                'sf_node')
                            add_fcs = flow_rules[flow4]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow4].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertEqual(
                                flow_rules[flow4]['node_type'],
                                'sf_node')

    def test_agent_init_multi_flow_classifiers_port_pairs(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port1, self.port(
            name='port3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port2, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port1['port']['id']
            }) as fc1, self.flow_classifier(flow_classifier={
                'logical_source_port': src_port2['port']['id']
            }) as fc2:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [
                                fc1['flow_classifier']['id'],
                                fc2['flow_classifier']['id']
                            ]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            flow_rules = []
                            flow_rules_by_portid = {}
                            for host, portid in [(
                                src_port1['port']['binding:host_id'],
                                src_port1['port']['id']
                            ), (
                                src_port2['port']['binding:host_id'],
                                src_port2['port']['id']
                            ), (
                                ingress['port']['binding:host_id'],
                                ingress['port']['id']
                            ), (
                                egress['port']['binding:host_id'],
                                egress['port']['id']
                            )]:
                                flow_rules_by_portid[
                                    portid
                                ] = self.driver.get_flowrules_by_host_portid(
                                    self.ctx, host=host, port_id=portid
                                )
                            flow_rules = self.map_flow_rules(
                                flow_rules, *(flow_rules_by_portid.values())
                            )
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port1['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port2['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id'])
                            self.assertEqual(
                                set(flow_rules.keys()),
                                {flow1, flow2, flow3})
                            add_fcs = flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src1 = (
                                src_port1['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src1,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'}
                            )
                            self.assertEqual(
                                flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src2 = (
                                src_port2['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': None,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': u'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src2,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'}
                            )
                            self.assertEqual(
                                flow_rules[flow2]['node_type'],
                                'src_node')
                            add_fcs = flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 2)
                            self._assert_flow_classifiers_match_subsets(
                                add_fcs,
                                [{
                                    'destination_ip_prefix': None,
                                    'destination_port_range_max': None,
                                    'destination_port_range_min': None,
                                    'ethertype': u'IPv4',
                                    'l7_parameters': {},
                                    'protocol': None,
                                    'source_ip_prefix': ip_src1,
                                    'source_port_range_max': None,
                                    'source_port_range_min': None
                                }, {
                                    'destination_ip_prefix': None,
                                    'destination_port_range_max': None,
                                    'destination_port_range_min': None,
                                    'ethertype': u'IPv4',
                                    'l7_parameters': {},
                                    'protocol': None,
                                    'source_ip_prefix': ip_src2,
                                    'source_port_range_max': None,
                                    'source_port_range_min': None
                                }],
                                'source_ip_prefix')
                            next_hops = self.next_hops_info(
                                flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {}
                            )
                            self.assertEqual(
                                flow_rules[flow3]['node_type'],
                                'sf_node')

    def _test_agent_init_service_graphs_end(
            self, lsport, pc1port, pc2port1, pc2port2, pc3port, pc4port,
            pc1fc, pc2fc, pc3fc, pc4fc, pc1pp, pc2pp1, pc2pp2, pc3pp, pc4pp,
            correlation):
        pc1pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc1pp['port_pair'])
        pc2pp1_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                 self.ctx,
                                                 pc2pp1['port_pair'])
        pc2pp2_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                 self.ctx,
                                                 pc2pp2['port_pair'])
        pc3pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc3pp['port_pair'])
        pc4pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc4pp['port_pair'])
        self.driver.create_port_pair(pc1pp_context)
        self.driver.create_port_pair(pc2pp1_context)
        self.driver.create_port_pair(pc2pp2_context)
        self.driver.create_port_pair(pc3pp_context)
        self.driver.create_port_pair(pc4pp_context)

        with self.port_pair_group(port_pair_group={
            'port_pairs': [pc1pp['port_pair']['id']]}
        ) as pc1pg, self.port_pair_group(port_pair_group={
            'port_pairs': [pc2pp1['port_pair']['id']]}
        ) as pc2pg1, self.port_pair_group(port_pair_group={
            'port_pairs': [pc2pp2['port_pair']['id']]}
        ) as pc2pg2, self.port_pair_group(port_pair_group={
            'port_pairs': [pc3pp['port_pair']['id']]}
        ) as pc3pg, self.port_pair_group(port_pair_group={
            'port_pairs': [pc4pp['port_pair']['id']]}
        ) as pc4pg:

            pc1pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc1pg['port_pair_group']
            )
            pc2pg1_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc2pg1['port_pair_group']
            )
            pc2pg2_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc2pg2['port_pair_group']
            )
            pc3pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc3pg['port_pair_group']
            )
            pc4pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc4pg['port_pair_group']
            )
            self.driver.create_port_pair_group(pc1pg_context)
            self.driver.create_port_pair_group(pc2pg1_context)
            self.driver.create_port_pair_group(pc2pg2_context)
            self.driver.create_port_pair_group(pc3pg_context)
            self.driver.create_port_pair_group(pc4pg_context)

            with self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc1pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc1fc['flow_classifier']['id']]}
            ) as pc1, self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    # different amount of PPGs for pc2 just to complicate
                    pc2pg1['port_pair_group']['id'],
                    pc2pg2['port_pair_group']['id']],
                'flow_classifiers': [
                    pc2fc['flow_classifier']['id']]}
            ) as pc2, self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc3pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc3fc['flow_classifier']['id']]}
            ) as pc3, self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc4pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc4fc['flow_classifier']['id']]}
            ) as pc4:

                pc1_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc1['port_chain']
                )
                pc2_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc2['port_chain']
                )
                pc3_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc3['port_chain']
                )
                pc4_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc4['port_chain']
                )
                self.driver.create_port_chain(pc1_context)
                self.driver.create_port_chain(pc2_context)
                self.driver.create_port_chain(pc3_context)
                self.driver.create_port_chain(pc4_context)

                with self.service_graph(service_graph={
                    'name': 'graph',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id'],
                                                  pc3['port_chain']['id']],
                        pc2['port_chain']['id']: [pc4['port_chain']['id']],
                        pc3['port_chain']['id']: [pc4['port_chain']['id']]}}
                ) as g:

                    all_ports = [lsport, pc1port, pc2port1,
                                 pc2port2, pc3port, pc4port]

                    g_context = sfc_ctx.ServiceGraphContext(
                        self.sfc_plugin, self.ctx,
                        g['service_graph']
                    )
                    self.driver.create_service_graph_postcommit(
                        g_context)
                    self.wait()

                    flow_rules = []
                    flow_rules_by_portid = {}
                    for host, portid in [(
                        p['port']['binding:host_id'], p['port']['id'],
                    ) for p in all_ports]:
                        flow_rules_by_portid[
                            portid
                        ] = self.driver.get_flowrules_by_host_portid(
                            self.ctx, host=host, port_id=portid
                        )
                    flow_rules = self.map_flow_rules(
                        flow_rules, *(flow_rules_by_portid.values())
                    )
                    # verify fr count: 2 in pc1, 3 in pc2, 2 in pc3, 2 in pc4:
                    self.assertEqual(len(flow_rules), 9)
                    pc1_flow_rules = [key for key in flow_rules if key.split(
                        ':')[0] == pc1['port_chain']['id'][:8]]
                    pc2_flow_rules = [key for key in flow_rules if key.split(
                        ':')[0] == pc2['port_chain']['id'][:8]]
                    pc3_flow_rules = [key for key in flow_rules if key.split(
                        ':')[0] == pc3['port_chain']['id'][:8]]
                    pc4_flow_rules = [key for key in flow_rules if key.split(
                        ':')[0] == pc4['port_chain']['id'][:8]]
                    self.assertEqual(len(pc1_flow_rules), 2)
                    self.assertEqual(len(pc2_flow_rules), 3)
                    self.assertEqual(len(pc3_flow_rules), 2)
                    self.assertEqual(len(pc4_flow_rules), 2)

                    # verify pc1's branching flow rule (last sf_node):
                    key = self.build_ingress_egress_from_pp(
                        pc1['port_chain']['id'], pc1pp['port_pair'])
                    self.assertEqual(flow_rules[key]['nsp'], 1)
                    self.assertEqual(flow_rules[key]['nsi'], 254)
                    self.assertEqual(flow_rules[key]['node_type'], 'sf_node')
                    self.assertIsNone(flow_rules[key]['next_group_id'])
                    self.assertIsNone(flow_rules[key]['next_hop'])
                    self.assertNotIn('branch_info', flow_rules[key])
                    self.assertTrue(flow_rules[key]['branch_point'])
                    # verify pc2's matching flow rule (src_node):
                    key = self.build_ingress_egress(
                        pc2['port_chain']['id'], None, lsport['port']['id'])
                    self.assertEqual(flow_rules[key]['nsp'], 2)
                    self.assertEqual(flow_rules[key]['nsi'], 255)
                    self.assertEqual(flow_rules[key]['node_type'], 'src_node')
                    self.assertIsNotNone(flow_rules[key]['next_group_id'])
                    self.assertIsNotNone(flow_rules[key]['next_hop'])
                    self.assertIn('branch_info', flow_rules[key])
                    branch_matches = flow_rules[key]['branch_info']['matches']
                    self.assertEqual(len(branch_matches), 1)
                    self.assertIn((1, 254,), branch_matches)
                    self.assertNotIn('branch_point', flow_rules[key])
                    # verify pc2's branching flow rule (last sf_node):
                    key = self.build_ingress_egress_from_pp(
                        pc2['port_chain']['id'], pc2pp2['port_pair'])
                    self.assertEqual(flow_rules[key]['nsp'], 2)
                    self.assertEqual(flow_rules[key]['nsi'], 253)
                    self.assertEqual(flow_rules[key]['node_type'], 'sf_node')
                    self.assertIsNone(flow_rules[key]['next_group_id'])
                    self.assertIsNone(flow_rules[key]['next_hop'])
                    self.assertNotIn('branch_info', flow_rules[key])
                    self.assertTrue(flow_rules[key]['branch_point'])
                    # verify pc3's matching flow rule (src_node):
                    key = self.build_ingress_egress(
                        pc3['port_chain']['id'], None, lsport['port']['id'])
                    self.assertEqual(flow_rules[key]['nsp'], 3)
                    self.assertEqual(flow_rules[key]['nsi'], 255)
                    self.assertEqual(flow_rules[key]['node_type'], 'src_node')
                    self.assertIsNotNone(flow_rules[key]['next_group_id'])
                    self.assertIsNotNone(flow_rules[key]['next_hop'])
                    self.assertIn('branch_info', flow_rules[key])
                    branch_matches = flow_rules[key]['branch_info']['matches']
                    self.assertEqual(len(branch_matches), 1)
                    self.assertIn((1, 254,), branch_matches)
                    self.assertNotIn('branch_point', flow_rules[key])
                    # verify pc3's branching flow rule (last sf_node):
                    key = self.build_ingress_egress_from_pp(
                        pc3['port_chain']['id'], pc3pp['port_pair'])
                    self.assertEqual(flow_rules[key]['nsp'], 3)
                    self.assertEqual(flow_rules[key]['nsi'], 254)
                    self.assertEqual(flow_rules[key]['node_type'], 'sf_node')
                    self.assertIsNone(flow_rules[key]['next_group_id'])
                    self.assertIsNone(flow_rules[key]['next_hop'])
                    self.assertNotIn('branch_info', flow_rules[key])
                    self.assertTrue(flow_rules[key]['branch_point'])
                    # verify pc4's matching flow rule (last sf_node):
                    key = self.build_ingress_egress(
                        pc4['port_chain']['id'], None, lsport['port']['id'])
                    self.assertEqual(flow_rules[key]['nsp'], 4)
                    self.assertEqual(flow_rules[key]['nsi'], 255)
                    self.assertEqual(flow_rules[key]['node_type'], 'src_node')
                    self.assertIsNotNone(flow_rules[key]['next_group_id'])
                    self.assertIsNotNone(flow_rules[key]['next_hop'])
                    self.assertIn('branch_info', flow_rules[key])
                    branch_matches = flow_rules[key]['branch_info']['matches']
                    self.assertEqual(len(branch_matches), 2)
                    self.assertIn((2, 253,), branch_matches)
                    self.assertIn((3, 254,), branch_matches)
                    self.assertNotIn('branch_point', flow_rules[key])
                    # verify that all other flow rules are normal:
                    key = self.build_ingress_egress(
                        pc1['port_chain']['id'], None, lsport['port']['id'])
                    self.assertNotIn('branch_info', flow_rules[key])
                    self.assertNotIn('branch_point', flow_rules[key])
                    key = self.build_ingress_egress_from_pp(
                        pc2['port_chain']['id'], pc2pp1['port_pair'])
                    self.assertNotIn('branch_info', flow_rules[key])
                    self.assertNotIn('branch_point', flow_rules[key])
                    key = self.build_ingress_egress_from_pp(
                        pc4['port_chain']['id'], pc4pp['port_pair'])
                    self.assertNotIn('branch_info', flow_rules[key])
                    self.assertNotIn('branch_point', flow_rules[key])

    # this test will create a graph with both normal/forking branches
    # and joining branches, using 4 port chains in total, and will verify
    # that the driver is able to provide the newly-started agent with
    # the correct flow rules so that the latter can restore the flows.
    def _test_agent_init_service_graphs(self, correlation):
        with self.port(
            name='lsport',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as lsport, self.port(
            name='pc1port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc1port, self.port(
            name='pc2port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc2port1, self.port(
            name='pc2port2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc2port2, self.port(
            name='pc3port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc3port, self.port(
            name='pc4port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc4port:

            self.host_endpoint_mapping = {'test': '10.0.0.1'}
            with self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.1/32'}
            ) as pc1fc, self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.2/32'}
            ) as pc2fc, self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.3/32'}
            ) as pc3fc, self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.4/32'}
            ) as pc4fc, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc1port['port']['id'],
                'egress': pc1port['port']['id']}
            ) as pc1pp, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc2port1['port']['id'],
                'egress': pc2port1['port']['id']}
            ) as pc2pp1, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc2port2['port']['id'],
                'egress': pc2port2['port']['id']}
            ) as pc2pp2, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc3port['port']['id'],
                'egress': pc3port['port']['id']}
            ) as pc3pp, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc4port['port']['id'],
                'egress': pc4port['port']['id']}
            ) as pc4pp:
                # main reason for splitting this method in 2 is having
                # more than 20 contexts
                self._test_agent_init_service_graphs_end(
                    lsport, pc1port, pc2port1, pc2port2, pc3port, pc4port,
                    pc1fc, pc2fc, pc3fc, pc4fc, pc1pp, pc2pp1, pc2pp2,
                    pc3pp, pc4pp, correlation)

    def test_agent_init_service_graphs_mpls(self):
        self._test_agent_init_service_graphs('mpls')

    def test_agent_init_service_graphs_nsh(self):
        self._test_agent_init_service_graphs('nsh')

    def test_create_port_chain_cross_subnet_ppg(self):
        with self.subnet(
            gateway_ip='10.0.0.10',
            cidr='10.0.0.0/24'
        ) as subnet1, self.subnet(
            gateway_ip='10.0.1.10',
            cidr='10.0.1.0/24'
        ) as subnet2:
            with self.port(
                name='port1',
                device_owner='compute',
                device_id='test',
                subnet=subnet1,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            ) as src_port, self.port(
                name='ingress1',
                device_owner='compute',
                device_id='test',
                subnet=subnet1,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            ) as ingress1, self.port(
                name='egress1',
                device_owner='compute',
                device_id='test',
                subnet=subnet1,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            )as egress1, self.port(
                name='ingress2',
                device_owner='compute',
                device_id='test',
                subnet=subnet2,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            ) as ingress2, self.port(
                name='egress2',
                device_owner='compute',
                device_id='test',
                subnet=subnet2,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            )as egress2:
                self.host_endpoint_mapping = {
                    'test': '10.0.0.1'
                }
                with self.flow_classifier(flow_classifier={
                    'logical_source_port': src_port['port']['id']
                }) as fc:
                    with self.port_pair(port_pair={
                        'ingress': ingress1['port']['id'],
                        'egress': egress1['port']['id']
                    }) as pp1, self.port_pair(port_pair={
                        'ingress': ingress2['port']['id'],
                        'egress': egress2['port']['id']
                    }) as pp2:
                        pp1_context = sfc_ctx.PortPairContext(
                            self.sfc_plugin, self.ctx,
                            pp1['port_pair']
                        )
                        self.driver.create_port_pair(pp1_context)
                        pp2_context = sfc_ctx.PortPairContext(
                            self.sfc_plugin, self.ctx,
                            pp2['port_pair']
                        )
                        self.driver.create_port_pair(pp2_context)
                        with self.port_pair_group(port_pair_group={
                            'port_pairs': [pp1['port_pair']['id']]
                        }) as pg1, self.port_pair_group(port_pair_group={
                            'port_pairs': [pp2['port_pair']['id']]
                        }) as pg2:
                            pg1_context = sfc_ctx.PortPairGroupContext(
                                self.sfc_plugin, self.ctx,
                                pg1['port_pair_group']
                            )
                            self.driver.create_port_pair_group(pg1_context)
                            pg2_context = sfc_ctx.PortPairGroupContext(
                                self.sfc_plugin, self.ctx,
                                pg2['port_pair_group']
                            )
                            self.driver.create_port_pair_group(pg2_context)
                            with self.port_chain(port_chain={
                                'name': 'test1',
                                'port_pair_groups': [
                                    pg1['port_pair_group']['id'],
                                    pg2['port_pair_group']['id']],
                                'flow_classifiers':
                                    [fc['flow_classifier']['id']]
                            }) as pc:
                                pc_context = sfc_ctx.PortChainContext(
                                    self.sfc_plugin, self.ctx,
                                    pc['port_chain']
                                )
                                result = self.driver.create_port_chain(
                                    pc_context)
                                self.assertIsNone(result)

    def test_create_port_chain_cross_subnet_source(self):
        with self.subnet(
            gateway_ip='10.0.0.10',
            cidr='10.0.0.0/24'
        )as subnet1, self.subnet(
            gateway_ip='10.0.1.10',
            cidr='10.0.1.0/24'
        )as subnet2:
            with self.port(
                name='port1',
                device_owner='compute',
                device_id='test',
                subnet=subnet1,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            ) as src_port, self.port(
                name='ingress1',
                device_owner='compute',
                device_id='test',
                subnet=subnet2,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            ) as ingress1, self.port(
                name='egress1',
                device_owner='compute',
                device_id='test',
                subnet=subnet2,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            ) as egress1, self.port(
                name='ingress2',
                device_owner='compute',
                device_id='test',
                subnet=subnet2,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            ) as ingress2, self.port(
                name='egress2',
                device_owner='compute',
                device_id='test',
                subnet=subnet2,
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
            ) as egress2:
                self.host_endpoint_mapping = {
                    'test': '10.0.0.1'
                }
                with self.flow_classifier(flow_classifier={
                    'ethertype': 'IPv4',
                    'l7_parameters': {},
                    'protocol': 'tcp',
                    'logical_source_port': src_port['port']['id']
                }) as fc:
                    with self.port_pair(port_pair={
                        'ingress': ingress1['port']['id'],
                        'egress': egress1['port']['id']
                    }) as pp1, self.port_pair(port_pair={
                        'ingress': ingress2['port']['id'],
                        'egress': egress2['port']['id']
                    }) as pp2:
                        pp1_context = sfc_ctx.PortPairContext(
                            self.sfc_plugin, self.ctx,
                            pp1['port_pair']
                        )
                        self.driver.create_port_pair(pp1_context)
                        pp2_context = sfc_ctx.PortPairContext(
                            self.sfc_plugin, self.ctx,
                            pp2['port_pair']
                        )
                        self.driver.create_port_pair(pp2_context)
                        with self.port_pair_group(port_pair_group={
                            'port_pairs': [pp1['port_pair']['id']]
                        }) as pg1, self.port_pair_group(port_pair_group={
                            'port_pairs': [pp2['port_pair']['id']]
                        }) as pg2:
                            pg1_context = sfc_ctx.PortPairGroupContext(
                                self.sfc_plugin, self.ctx,
                                pg1['port_pair_group']
                            )
                            self.driver.create_port_pair_group(pg1_context)
                            pg2_context = sfc_ctx.PortPairGroupContext(
                                self.sfc_plugin, self.ctx,
                                pg2['port_pair_group']
                            )
                            self.driver.create_port_pair_group(pg2_context)
                            with self.port_chain(port_chain={
                                'name': 'test1',
                                'port_pair_groups': [
                                    pg1['port_pair_group']['id'],
                                    pg2['port_pair_group']['id']
                                ],
                                'flow_classifiers':
                                    [fc['flow_classifier']['id']]
                            }) as pc:
                                pc_context = sfc_ctx.PortChainContext(
                                    self.sfc_plugin, self.ctx,
                                    pc['port_chain']
                                )
                                result = self.driver.create_port_chain(
                                    pc_context)
                                self.assertIsNone(result)

    def test_create_port_chain_with_symmetric(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1',
        }) as pg:
            pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pg['port_pair_group']
            )
            self.driver.create_port_pair_group(pg_context)
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg['port_pair_group']['id']],
                'chain_parameters': {'symmetric': True}
            }) as pc:
                pc_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc['port_chain']
                )
                self.driver.create_port_chain(pc_context)
                self.wait()
                self.assertEqual(self.rpc_calls['update_flow_rules'], [])

    def test_create_port_chain_precommit_symmetric_no_logical_dst_port(self):
        with self.port(
            name='src',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': []
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']],
                        'chain_parameters': {'symmetric': True}
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.assertRaises(
                            sfc_exc.SfcBadRequest,
                            self.driver.create_port_chain_precommit,
                            pc_context
                        )

    def test_create_port_chain_with_flow_classifiers_with_symmetric(self):
        with self.port(
            name='src',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='dst',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id'],
                'logical_destination_port': dst_port['port']['id']
            }) as fc:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': []
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']],
                        'chain_parameters': {'symmetric': True}
                    }) as pc:
                        pc_context = sfc_ctx.PortChainContext(
                            self.sfc_plugin, self.ctx,
                            pc['port_chain']
                        )
                        self.driver.create_port_chain(pc_context)
                        self.wait()
                        update_flow_rules = self.map_flow_rules(
                            self.rpc_calls['update_flow_rules'])
                        flow1 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None,
                            fc['flow_classifier']['logical_source_port'])
                        flow2 = self.build_ingress_egress(
                            pc['port_chain']['id'],
                            None,
                            fc['flow_classifier']['logical_destination_port'])
                        self.assertEqual(
                            set(update_flow_rules.keys()),
                            {flow1, flow2})
                        self.assertEqual(
                            len(update_flow_rules[flow1]['add_fcs']),
                            1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': '10.200.0.0/16',
                            'destination_port_range_max': 400,
                            'destination_port_range_min': 300,
                            'ethertype': 'IPv4',
                            'l7_parameters': {},
                            'protocol': u'tcp',
                            'source_ip_prefix': u'10.100.0.0/16',
                            'source_port_range_max': 200,
                            'source_port_range_min': 100
                        }, update_flow_rules[flow1]['add_fcs'][0])
                        self.assertEqual(
                            update_flow_rules[flow1]['del_fcs'],
                            [])
                        self.assertEqual(
                            update_flow_rules[flow1]['node_type'],
                            'src_node')
                        self.assertIsNone(
                            update_flow_rules[flow1].get('next_hops')
                        )
                        self.assertIsNotNone(
                            update_flow_rules[flow1]['next_group_id']
                        )
                        self.assertEqual(
                            len(update_flow_rules[flow2]['add_fcs']),
                            1)
                        self.assertDictContainsSubset({
                            'destination_ip_prefix': '10.200.0.0/16',
                            'destination_port_range_max': 400,
                            'destination_port_range_min': 300,
                            'ethertype': 'IPv4',
                            'l7_parameters': {},
                            'protocol': u'tcp',
                            'source_ip_prefix': u'10.100.0.0/16',
                            'source_port_range_max': 200,
                            'source_port_range_min': 100
                        }, update_flow_rules[flow2]['add_fcs'][0])
                        self.assertEqual(
                            update_flow_rules[flow2]['del_fcs'],
                            [])
                        self.assertEqual(
                            update_flow_rules[flow2]['node_type'],
                            'src_node')
                        self.assertIsNone(
                            update_flow_rules[flow2].get('next_hops')
                        )
                        self.assertIsNotNone(
                            update_flow_rules[flow2]['next_group_id']
                        )

    def test_create_port_chain_with_fcs_port_pairs_with_symmetric(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress, self.port(
            name='port2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id'],
                'logical_destination_port': dst_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']],
                            'chain_parameters': {'symmetric': True}
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, dst_port['port']['id'])
                            flow4 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id'])
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2, flow3, flow4})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow1]['next_group_id'])
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 2)
                            self._assert_flow_classifiers_match_subsets(
                                add_fcs,
                                [{
                                    'destination_ip_prefix': '10.200.0.0/16',
                                    'destination_port_range_max': 400,
                                    'destination_port_range_min': 300,
                                    'ethertype': 'IPv4',
                                    'l7_parameters': {},
                                    'protocol': 'tcp',
                                    'source_ip_prefix': '10.100.0.0/16',
                                    'source_port_range_max': 200,
                                    'source_port_range_min': 100
                                }] * 2)
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow2]['next_group_id'])
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow3]['next_group_id'])
                            self.assertEqual(
                                update_flow_rules[flow3]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow4]['add_fcs']
                            self.assertEqual(len(add_fcs), 2)
                            self._assert_flow_classifiers_match_subsets(
                                add_fcs,
                                [{
                                    'destination_ip_prefix': '10.200.0.0/16',
                                    'destination_port_range_max': 400,
                                    'destination_port_range_min': 300,
                                    'ethertype': 'IPv4',
                                    'l7_parameters': {},
                                    'protocol': 'tcp',
                                    'source_ip_prefix': '10.100.0.0/16',
                                    'source_port_range_max': 200,
                                    'source_port_range_min': 100
                                }] * 2)
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow4].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow4]['next_group_id'])
                            self.assertEqual(
                                update_flow_rules[flow4]['node_type'],
                                'sf_node')

    def test_create_port_chain_with_multi_fcs_port_pairs_with_symmetric(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port1, self.port(
            name='port3',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port2, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress, self.port(
            name='port2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port1, self.port(
            name='port4',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port2:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                'logical_source_port': src_port1['port']['id'],
                'logical_destination_port': dst_port1['port']['id']
            }) as fc1, self.flow_classifier(flow_classifier={
                'logical_source_port': src_port2['port']['id'],
                'logical_destination_port': dst_port2['port']['id']
            }) as fc2:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']]
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [
                                fc1['flow_classifier']['id'],
                                fc2['flow_classifier']['id']
                            ],
                            'chain_parameters': {'symmetric': True}
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port1['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port2['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id'])
                            flow4 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, dst_port1['port']['id'])
                            flow5 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, dst_port2['port']['id'])
                            flow6 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id'])
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2, flow3, flow4, flow5, flow6})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src1 = (
                                src_port1['port']['fixed_ips'][0]['ip_address']
                            )
                            ip_dst1 = (
                                dst_port1['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': ip_dst1,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src1,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                    ingress['port']['mac_address']: '10.0.0.1'
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src2 = (
                                src_port2['port']['fixed_ips'][0]['ip_address']
                            )
                            ip_dst2 = (
                                dst_port2['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': ip_dst2,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src2,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                    ingress['port']['mac_address']: '10.0.0.1'
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 4)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': ip_dst1,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src1,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': ip_dst2,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src2,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[1])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow3]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow4]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src1 = (
                                src_port1['port']['fixed_ips'][0]['ip_address']
                            )
                            ip_dst1 = (
                                dst_port1['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': ip_dst1,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src1,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow4].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                    ingress['port']['mac_address']: '10.0.0.1'
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow4]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow5]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            ip_src2 = (
                                src_port2['port']['fixed_ips'][0]['ip_address']
                            )
                            ip_dst2 = (
                                dst_port2['port']['fixed_ips'][0]['ip_address']
                            )
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': ip_dst2,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src2,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow5].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                    ingress['port']['mac_address']: '10.0.0.1'
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow5]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow6]['add_fcs']
                            self.assertEqual(len(add_fcs), 4)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': ip_dst1,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src1,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[0])
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': ip_dst2,
                                'destination_port_range_max': None,
                                'destination_port_range_min': None,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': None,
                                'source_ip_prefix': ip_src2,
                                'source_port_range_max': None,
                                'source_port_range_min': None
                            }, add_fcs[1])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow6].get('next_hops'))
                            self.assertEqual(
                                next_hops, {
                                }
                            )
                            self.assertEqual(
                                update_flow_rules[flow6]['node_type'],
                                'sf_node')

    def test_create_port_chain_fcs_port_pairs_ppg_n_tuple_symmetric(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress, self.port(
            name='egress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress, self.port(
            name='port2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as dst_port:
            self.host_endpoint_mapping = {'test': '10.0.0.1'}
            with self.flow_classifier(flow_classifier={
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'destination_port_range_min': 300,
                'destination_port_range_max': 400,
                'ethertype': 'IPv4',
                'source_ip_prefix': '10.100.0.0/16',
                'destination_ip_prefix': '10.200.0.0/16',
                'l7_parameters': {},
                'protocol': 'tcp',
                'logical_source_port': src_port['port']['id'],
                'logical_destination_port': dst_port['port']['id']
            }) as fc:
                with self.port_pair(port_pair={
                    'ingress': ingress['port']['id'],
                    'egress': egress['port']['id']
                }) as pp:
                    pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pp['port_pair']
                    )
                    self.driver.create_port_pair(pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pp['port_pair']['id']],
                        'port_pair_group_parameters': {
                            'ppg_n_tuple_mapping': {
                                'ingress_n_tuple': {
                                    'source_ip_prefix': '10.100.0.0/16'},
                                'egress_n_tuple': {
                                    'source_ip_prefix': '10.300.0.0/16'}
                            }
                        }
                    }) as pg:
                        pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pg_context)
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']],
                            'chain_parameters': {'symmetric': True}
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id'])
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None, dst_port['port']['id'])
                            flow4 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                egress['port']['id'])
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2, flow3, flow4})
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.100.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow1].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow1]['next_group_id'])
                            self.assertEqual(
                                update_flow_rules[flow1]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow2]['add_fcs']
                            self.assertEqual(len(add_fcs), 2)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.300.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow2].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow2]['next_group_id'])
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                'sf_node')
                            add_fcs = update_flow_rules[flow3]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.300.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow3].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {ingress['port']['mac_address']: '10.0.0.1'})
                            self.assertIsNotNone(
                                update_flow_rules[flow3]['next_group_id'])
                            self.assertEqual(
                                update_flow_rules[flow3]['node_type'],
                                'src_node')
                            add_fcs = update_flow_rules[flow4]['add_fcs']
                            self.assertEqual(len(add_fcs), 2)
                            self.assertDictContainsSubset({
                                'destination_ip_prefix': '10.200.0.0/16',
                                'destination_port_range_max': 400,
                                'destination_port_range_min': 300,
                                'ethertype': 'IPv4',
                                'l7_parameters': {},
                                'protocol': 'tcp',
                                'source_ip_prefix': '10.300.0.0/16',
                                'source_port_range_max': 200,
                                'source_port_range_min': 100
                            }, add_fcs[0])
                            next_hops = self.next_hops_info(
                                update_flow_rules[flow4].get('next_hops'))
                            self.assertEqual(
                                next_hops,
                                {})
                            self.assertIsNone(
                                update_flow_rules[flow4]['next_group_id'])
                            self.assertEqual(
                                update_flow_rules[flow4]['node_type'],
                                'sf_node')

    # this test will create the simplest possible graph, from a port chain
    # with a single pp/ppg, to another port chain with a single pp/ppg,
    # in the same host and using trivial flow classifiers.
    def _test_create_service_graph(self, correlation):
        with self.port(
            name='pc1port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc1sourceport, self.port(
            name='pc2port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc2sourceport, self.port(
            name='pc2port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc1port, self.port(
            name='pc2port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc2port:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1'
            }
            with self.flow_classifier(flow_classifier={
                    'logical_source_port': pc1sourceport['port']['id'],
                    'protocol': 'tcp'}
            ) as pc1fc, self.flow_classifier(flow_classifier={
                    # when attached to the graph, this LSP gets ignored
                    'logical_source_port': pc2sourceport['port']['id'],
                    'protocol': 'udp'}
            ) as pc2fc:
                with self.port_pair(port_pair={
                    'service_function_parameters': {
                        'correlation': correlation},
                    'ingress': pc1port['port']['id'],
                    'egress': pc1port['port']['id']}
                ) as pc1pp, self.port_pair(port_pair={
                    'service_function_parameters': {
                        'correlation': correlation},
                    'ingress': pc2port['port']['id'],
                    'egress': pc2port['port']['id']}
                ) as pc2pp:
                    pc1pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pc1pp['port_pair']
                    )
                    pc2pp_context = sfc_ctx.PortPairContext(
                        self.sfc_plugin, self.ctx,
                        pc2pp['port_pair']
                    )
                    self.driver.create_port_pair(pc1pp_context)
                    self.driver.create_port_pair(pc2pp_context)
                    with self.port_pair_group(port_pair_group={
                        'port_pairs': [pc1pp['port_pair']['id']]}
                    ) as pc1pg, self.port_pair_group(port_pair_group={
                        'port_pairs': [pc2pp['port_pair']['id']]}
                    ) as pc2pg:
                        pc1pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pc1pg['port_pair_group']
                        )
                        pc2pg_context = sfc_ctx.PortPairGroupContext(
                            self.sfc_plugin, self.ctx,
                            pc2pg['port_pair_group']
                        )
                        self.driver.create_port_pair_group(pc1pg_context)
                        self.driver.create_port_pair_group(pc2pg_context)
                        with self.port_chain(port_chain={
                            'chain_parameters': {
                                'correlation': correlation},
                            'port_pair_groups': [
                                pc1pg['port_pair_group']['id']],
                            'flow_classifiers': [
                                pc1fc['flow_classifier']['id']]}
                        ) as pc1, self.port_chain(port_chain={
                            'chain_parameters': {
                                'correlation': correlation},
                            'port_pair_groups': [
                                pc2pg['port_pair_group']['id']],
                            'flow_classifiers': [
                                pc2fc['flow_classifier']['id']]}
                        ) as pc2:
                            pc1_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc1['port_chain']
                            )
                            pc2_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc2['port_chain']
                            )
                            self.driver.create_port_chain(pc1_context)
                            self.driver.create_port_chain(pc2_context)
                            # original port-chains' flow rules
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])

                            # flow rule for the end of the src chain (PPG)
                            flow1_end = self.build_ingress_egress(
                                pc1['port_chain']['id'],
                                pc1port['port']['id'],
                                pc1port['port']['id'])
                            # flow rule for the start of the dst chain (PPG)
                            flow2_sta = self.build_ingress_egress(
                                pc2['port_chain']['id'],
                                None,
                                pc2fc['flow_classifier']['logical_source_port']
                            )

                            # old_add1 is the original add_fcs of the src PPG
                            old_add1 = update_flow_rules[flow1_end]['add_fcs']
                            # old_add2 is the original add_fcs of the dst PPG
                            old_add2 = update_flow_rules[flow2_sta]['add_fcs']

                            # clear port-chains' flow rules to focus on graph
                            self.init_rpc_calls()

                            with self.service_graph(service_graph={
                                'name': 'test1',
                                'port_chains': {
                                    pc1['port_chain']['id']:
                                        [pc2['port_chain']['id']]}}
                            ) as g:
                                g_context = sfc_ctx.ServiceGraphContext(
                                    self.sfc_plugin, self.ctx,
                                    g['service_graph']
                                )
                                self.driver.create_service_graph_postcommit(
                                    g_context)
                                self.wait()

                                ufr = self.map_flow_rules(
                                    self.rpc_calls['update_flow_rules'])
                                # assert that the common "nodes" of linked
                                # chains have had their flow rules replaced
                                self.assertEqual(set(ufr.keys()),
                                                 set([flow1_end, flow2_sta]))
                                self.assertEqual(
                                    ufr[flow1_end]['node_type'],
                                    'sf_node'
                                )
                                self.assertEqual(
                                    ufr[flow2_sta]['node_type'],
                                    'src_node'
                                )

                                self.assertDictContainsSubset({
                                    'branch_point': True
                                }, ufr[flow1_end])

                                # dependent chain must match on dependency
                                # chain and have the expected identifiers
                                self.assertEqual(ufr[flow2_sta][
                                    'branch_info']['matches'][0][0], 1)
                                self.assertEqual(ufr[flow2_sta][
                                    'branch_info']['matches'][0][1], 254)
                                self.assertEqual(ufr[
                                    flow2_sta]['branch_info']['matches'][0][0],
                                    ufr[flow1_end]['nsp'])
                                self.assertEqual(ufr[
                                    flow2_sta]['branch_info']['matches'][0][1],
                                    ufr[flow1_end]['nsi'])
                                # we are creating the graph:
                                self.assertEqual(ufr[
                                    flow2_sta]['branch_info']['on_add'], True)

                                # next_hops should be present in the src_node
                                self.assertIn('next_hops', ufr[flow2_sta])

                                add_fcs = ufr[flow2_sta]['add_fcs']
                                del_fcs = ufr[flow2_sta]['del_fcs']
                                # dst PPG del_fcs must equal pre-graph add_fcs
                                self.assertEqual(del_fcs, old_add2)

                                self.assertEqual(len(add_fcs), 1)
                                self.assertEqual(len(del_fcs), 1)
                                for add_fc in add_fcs:
                                    # no LSPs for destination chain src_node
                                    self.assertDictContainsSubset({
                                        'logical_source_port': None
                                    }, add_fc)

                                add_fcs = ufr[flow1_end]['add_fcs']
                                del_fcs = ufr[flow1_end]['del_fcs']
                                # src PPG del_fcs must equal pre-graph add_fcs
                                self.assertEqual(del_fcs, old_add1)
                                self.assertEqual(len(add_fcs), 1)
                                self.assertEqual(len(del_fcs), 1)

    def test_create_service_graph_mpls(self):
        self._test_create_service_graph('mpls')

    def test_create_service_graph_nsh(self):
        self._test_create_service_graph('nsh')

    # post-graph-creation testing of test_create_service_graph_complex()
    def _test_create_service_graph_complex(self, g, sta_nodes, end_nodes,
                                           old_add1, old_add2, nsp, nsi):
        g_context = sfc_ctx.ServiceGraphContext(
            self.sfc_plugin, self.ctx,
            g['service_graph']
        )
        self.driver.create_service_graph_postcommit(g_context)
        self.wait()

        ufr = self.map_flow_rules(self.rpc_calls['update_flow_rules'])

        # assert that the common "nodes" of linked
        # chains have had their flow rules replaced
        self.assertEqual(set(ufr.keys()), set(sta_nodes + end_nodes))

        for node in sta_nodes:
            # start nodes of dependent chains are src_node
            self.assertEqual(ufr[node]['node_type'], 'src_node')

            add_fcs = ufr[node]['add_fcs']
            del_fcs = ufr[node]['del_fcs']
            # dst PPG del_fcs must equal pre-graph add_fcs
            self.assertEqual(del_fcs, old_add2[node])
            self.assertEqual(len(add_fcs), 1)
            self.assertEqual(len(del_fcs), 1)
            for add_fc in add_fcs:
                # no LSPs for destination chain src_node
                self.assertDictContainsSubset({
                    'logical_source_port': None
                }, add_fc)

            # next_hops should be present in src_node
            self.assertIn('next_hops', ufr[node])
            # no LSPs for destination chain src_node
            self.assertDictContainsSubset({
                'logical_source_port': None},
                ufr[node]['add_fcs'][0])

            # the graph will be created, so use matches together with add_fcs:
            self.assertEqual(ufr[node]['branch_info']['on_add'], True)

        # end nodes of dependency chains are sf_node
        for node in end_nodes:
            self.assertEqual(ufr[node]['node_type'], 'sf_node')
            self.assertDictContainsSubset({'branch_point': True}, ufr[node])

            add_fcs = ufr[node]['add_fcs']
            del_fcs = ufr[node]['del_fcs']
            # src PPG del_fcs must equal pre-graph add_fcs
            self.assertEqual(del_fcs, old_add1[node])
            self.assertEqual(len(add_fcs), 1)
            self.assertEqual(len(del_fcs), 1)

        # "joining" branches from pc4 and pc5 into pc6:
        ufr[sta_nodes[4]]['branch_info'][
            'matches'] = sorted(ufr[sta_nodes[4]][
                'branch_info']['matches'], key=(
                    lambda m: m[0]))  # sort by nsp

        # assert that each branch matches correctly
        self.assertEqual((nsp[end_nodes[0]], nsi[
            end_nodes[0]],), ufr[sta_nodes[0]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[0]], nsi[
            end_nodes[0]],), ufr[sta_nodes[1]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[1]], nsi[
            end_nodes[1]],), ufr[sta_nodes[2]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[2]], nsi[
            end_nodes[2]],), ufr[sta_nodes[3]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[3]], nsi[
            end_nodes[3]],), ufr[sta_nodes[4]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[4]], nsi[
            end_nodes[4]],), ufr[sta_nodes[4]]['branch_info']['matches'][1])

    # post-graph-creation testing of test_delete_service_graph_complex()
    def _test_delete_service_graph_complex(self, g, sta_nodes, end_nodes,
                                           old_add1, old_add2, nsp, nsi):
        g_context = sfc_ctx.ServiceGraphContext(
            self.sfc_plugin, self.ctx,
            g['service_graph']
        )
        self.driver.delete_service_graph_postcommit(g_context)
        self.wait()

        ufr = self.map_flow_rules(self.rpc_calls['update_flow_rules'])

        # assert that the common "nodes" of linked
        # chains have had their flow rules replaced
        self.assertEqual(set(ufr.keys()),
                         set(sta_nodes + end_nodes))

        for node in sta_nodes:
            # start nodes of dependent chains are src_node
            self.assertEqual(ufr[node]['node_type'], 'src_node')
            self.assertEqual(len(ufr[node]['del_fcs']), 1)
            self.assertEqual(len(ufr[node]['del_fcs']), 1)
            # dst PPG add_fcs is the same as pre-graph add_fcs
            self.assertEqual(ufr[node]['add_fcs'], old_add2[node])
            # next_hops should be present in src_node
            self.assertIn('next_hops', ufr[node])
            # no LSPs for destination chain src_node (del_fcs)
            self.assertDictContainsSubset({
                'logical_source_port': None},
                ufr[node]['del_fcs'][0])
            self.assertDictContainsSubset({
                'logical_source_port': node.split(':')[2]},  # egress port
                ufr[node]['add_fcs'][0])

            # the graph will be deleted, so use matches together with del_fcs:
            self.assertEqual(ufr[node]['branch_info']['on_add'], False)

        # end nodes of dependency chains are sf_node
        for node in end_nodes:
            self.assertEqual(ufr[node]['node_type'], 'sf_node')
            self.assertDictContainsSubset({
                'branch_point': False
            }, ufr[node])
            # src PPG add_fcs is the same as pre-graph add_fcs
            self.assertEqual(ufr[node]['add_fcs'], old_add1[node])

        # "joining" branches from pc4 and pc5 into pc6:
        ufr[sta_nodes[4]]['branch_info']['matches'] = sorted(ufr[sta_nodes[4]][
            'branch_info']['matches'], key=(
                lambda m: m[0]))  # sort by nsp

        # assert that each branch matches correctly
        self.assertEqual((nsp[end_nodes[0]], nsi[
            end_nodes[0]],), ufr[sta_nodes[0]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[0]], nsi[
            end_nodes[0]],), ufr[sta_nodes[1]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[1]], nsi[
            end_nodes[1]],), ufr[sta_nodes[2]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[2]], nsi[
            end_nodes[2]],), ufr[sta_nodes[3]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[3]], nsi[
            end_nodes[3]],), ufr[sta_nodes[4]]['branch_info']['matches'][0])
        self.assertEqual((nsp[end_nodes[4]], nsi[
            end_nodes[4]],), ufr[sta_nodes[4]]['branch_info']['matches'][1])

    # this test will create a very complex graph, that initially branches
    # (after pc1), and later joins back into a single service function path
    # this test will create a very complex graph, that initially branches
    # (after pc1), and later joins back into a single service function path
    # (on pc6), in the same host and using trivial flow classifiers.
    def _test_service_graph_complex(self, create, correlation):
        with self.port(
            name='lsport',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
            # even though this will be set as the LSP of every PC,
            # it will be ignored on non-initial PCs (pc2-pc7),
            # this results in the FCs being lumped together in the same
            # "egress" flow rule, but with match_nsp/nsi in there, which
            # can be used by the OVS agent to decide how to match on traffic
        ) as lsport, self.port(
            name='pc1port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc1port, self.port(
            name='pc2port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc2port, self.port(
            name='pc3port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc3port, self.port(
            name='pc4port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc4port, self.port(
            name='pc5port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc5port, self.port(
            name='pc6port',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as pc6port:
            self.host_endpoint_mapping = {'test': '10.0.0.1'}
            with self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.1/32'}
            ) as pc1fc, self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.2/32'}
            ) as pc2fc, self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.3/32'}
            ) as pc3fc, self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.4/32'}
            ) as pc4fc, self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.5/32'}
            ) as pc5fc, self.flow_classifier(flow_classifier={
                'logical_source_port': lsport['port']['id'],
                'destination_ip_prefix': '192.0.2.6/32'}
            ) as pc6fc, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc1port['port']['id'],
                'egress': pc1port['port']['id']}
            ) as pc1pp, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc2port['port']['id'],
                'egress': pc2port['port']['id']}
            ) as pc2pp, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc3port['port']['id'],
                'egress': pc3port['port']['id']}
            ) as pc3pp, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc4port['port']['id'],
                'egress': pc4port['port']['id']}
            ) as pc4pp, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc5port['port']['id'],
                'egress': pc5port['port']['id']}
            ) as pc5pp, self.port_pair(port_pair={
                'service_function_parameters': {'correlation': correlation},
                'ingress': pc6port['port']['id'],
                'egress': pc6port['port']['id']}
            ) as pc6pp:
                # main reason for splitting this method in 2 is having
                # more than 20 contexts
                self._test_service_graph_complex_end(
                    create, pc1fc, pc2fc, pc3fc, pc4fc, pc5fc, pc6fc,
                    pc1pp, pc2pp, pc3pp, pc4pp, pc5pp, pc6pp, correlation)

    def _test_service_graph_complex_end(
            self, create, pc1fc, pc2fc, pc3fc, pc4fc, pc5fc, pc6fc,
            pc1pp, pc2pp, pc3pp, pc4pp, pc5pp, pc6pp, correlation):
        pc1pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc1pp['port_pair'])
        pc2pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc2pp['port_pair'])
        pc3pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc3pp['port_pair'])
        pc4pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc4pp['port_pair'])
        pc5pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc5pp['port_pair'])
        pc6pp_context = sfc_ctx.PortPairContext(self.sfc_plugin,
                                                self.ctx,
                                                pc6pp['port_pair'])
        self.driver.create_port_pair(pc1pp_context)
        self.driver.create_port_pair(pc2pp_context)
        self.driver.create_port_pair(pc3pp_context)
        self.driver.create_port_pair(pc4pp_context)
        self.driver.create_port_pair(pc5pp_context)
        self.driver.create_port_pair(pc6pp_context)

        with self.port_pair_group(port_pair_group={
            'port_pairs': [pc1pp['port_pair']['id']]}
        ) as pc1pg, self.port_pair_group(port_pair_group={
            'port_pairs': [pc2pp['port_pair']['id']]}
        ) as pc2pg, self.port_pair_group(port_pair_group={
            'port_pairs': [pc3pp['port_pair']['id']]}
        ) as pc3pg, self.port_pair_group(port_pair_group={
            'port_pairs': [pc4pp['port_pair']['id']]}
        ) as pc4pg, self.port_pair_group(port_pair_group={
            'port_pairs': [pc5pp['port_pair']['id']]}
        ) as pc5pg, self.port_pair_group(port_pair_group={
            'port_pairs': [pc6pp['port_pair']['id']]}
        ) as pc6pg:

            pc1pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc1pg['port_pair_group']
            )
            pc2pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc2pg['port_pair_group']
            )
            pc3pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc3pg['port_pair_group']
            )
            pc4pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc4pg['port_pair_group']
            )
            pc5pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc5pg['port_pair_group']
            )
            pc6pg_context = sfc_ctx.PortPairGroupContext(
                self.sfc_plugin, self.ctx,
                pc6pg['port_pair_group']
            )
            self.driver.create_port_pair_group(pc1pg_context)
            self.driver.create_port_pair_group(pc2pg_context)
            self.driver.create_port_pair_group(pc3pg_context)
            self.driver.create_port_pair_group(pc4pg_context)
            self.driver.create_port_pair_group(pc5pg_context)
            self.driver.create_port_pair_group(pc6pg_context)

            with self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc1pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc1fc['flow_classifier']['id']]}
            ) as pc1, self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc2pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc2fc['flow_classifier']['id']]}
            ) as pc2, self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc3pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc3fc['flow_classifier']['id']]}
            ) as pc3, self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc4pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc4fc['flow_classifier']['id']]}
            ) as pc4, self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc5pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc5fc['flow_classifier']['id']]}
            ) as pc5, self.port_chain(port_chain={
                'chain_parameters': {
                    'correlation': correlation},
                'port_pair_groups': [
                    pc6pg['port_pair_group']['id']],
                'flow_classifiers': [
                    pc6fc['flow_classifier']['id']]}
            ) as pc6:

                pc1_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc1['port_chain']
                )
                pc2_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc2['port_chain']
                )
                pc3_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc3['port_chain']
                )
                pc4_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc4['port_chain']
                )
                pc5_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc5['port_chain']
                )
                pc6_context = sfc_ctx.PortChainContext(
                    self.sfc_plugin, self.ctx,
                    pc6['port_chain']
                )
                self.driver.create_port_chain(pc1_context)
                self.driver.create_port_chain(pc2_context)
                self.driver.create_port_chain(pc3_context)
                self.driver.create_port_chain(pc4_context)
                self.driver.create_port_chain(pc5_context)
                self.driver.create_port_chain(pc6_context)

                # original port-chains' update_flow_rules (ufr)
                ufr = self.map_flow_rules(
                    self.rpc_calls['update_flow_rules'])

                # flow rule for the end of pc1
                pc1_end = self.build_ingress_egress(
                    pc1['port_chain']['id'],
                    pc1pp['port_pair']['ingress'],
                    pc1pp['port_pair']['egress'])
                # flow rule for the start of pc2
                pc2_sta = self.build_ingress_egress(
                    pc2['port_chain']['id'],
                    None,
                    pc2fc['flow_classifier']['logical_source_port']
                )
                # flow rule for the start of pc3
                pc3_sta = self.build_ingress_egress(
                    pc3['port_chain']['id'],
                    None,
                    pc3fc['flow_classifier']['logical_source_port']
                )
                # flow rule for the end of pc2
                pc2_end = self.build_ingress_egress(
                    pc2['port_chain']['id'],
                    pc2pp['port_pair']['ingress'],
                    pc2pp['port_pair']['egress'])
                # flow rule for the end of pc3
                pc3_end = self.build_ingress_egress(
                    pc3['port_chain']['id'],
                    pc3pp['port_pair']['ingress'],
                    pc3pp['port_pair']['egress'])
                # flow rule for the start of pc4
                pc4_sta = self.build_ingress_egress(
                    pc4['port_chain']['id'],
                    None,
                    pc4fc['flow_classifier']['logical_source_port']
                )
                # flow rule for the start of pc5
                pc5_sta = self.build_ingress_egress(
                    pc5['port_chain']['id'],
                    None,
                    pc5fc['flow_classifier']['logical_source_port']
                )
                # flow rule for the end of pc4
                pc4_end = self.build_ingress_egress(
                    pc4['port_chain']['id'],
                    pc4pp['port_pair']['ingress'],
                    pc4pp['port_pair']['egress'])
                # flow rule for the end of pc5
                pc5_end = self.build_ingress_egress(
                    pc5['port_chain']['id'],
                    pc5pp['port_pair']['ingress'],
                    pc5pp['port_pair']['egress'])
                # flow rule for the start of pc6
                pc6_sta = self.build_ingress_egress(
                    pc6['port_chain']['id'],
                    None,
                    pc6fc['flow_classifier']['logical_source_port']
                )

                sta_nodes = [pc2_sta, pc3_sta, pc4_sta, pc5_sta, pc6_sta]
                end_nodes = [pc1_end, pc2_end, pc3_end, pc4_end, pc5_end]

                self.assertEqual(len(set(sta_nodes)), 5)
                self.assertEqual(len(set(end_nodes)), 5)

                nsp = {}
                nsi = {}
                old_add1 = {}
                for node in end_nodes:
                    # there should only be 1 FC per flow rule
                    self.assertEqual(len(ufr[node]['add_fcs']), 1)
                    # save each source chain's NSP/NSI for later
                    nsp[node] = ufr[node]['nsp']
                    nsi[node] = ufr[node]['nsi']
                    # save add_fcs to later compare with del_fcs
                    old_add1[node] = ufr[node]['add_fcs']

                old_add2 = {}
                for node in sta_nodes:
                    # there should only be 1 FC per flow rule
                    self.assertEqual(len(ufr[node]['add_fcs']), 1)
                    # save add_fcs to later compare with del_fcs
                    old_add2[node] = ufr[node]['add_fcs']

                with self.service_graph(service_graph={
                    'name': 'graph',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id'],
                                                  pc3['port_chain']['id']],
                        pc2['port_chain']['id']: [pc4['port_chain']['id']],
                        pc3['port_chain']['id']: [pc5['port_chain']['id']],
                        pc4['port_chain']['id']: [pc6['port_chain']['id']],
                        pc5['port_chain']['id']: [pc6['port_chain']['id']]}}
                ) as g:
                    # clear port-chains' flow rules
                    self.init_rpc_calls()
                    if create:
                        self._test_create_service_graph_complex(
                            g, sta_nodes, end_nodes,
                            old_add1, old_add2, nsp, nsi)
                    else:
                        self._test_delete_service_graph_complex(
                            g, sta_nodes, end_nodes,
                            old_add1, old_add2, nsp, nsi)

    def test_create_service_graph_complex_mpls(self):
        self._test_service_graph_complex(True, 'mpls')

    def test_create_service_graph_complex_nsh(self):
        self._test_service_graph_complex(True, 'nsh')

    def test_delete_service_graph_complex_mpls(self):
        self._test_service_graph_complex(False, 'mpls')

    def test_delete_service_graph_complex_nsh(self):
        self._test_service_graph_complex(False, 'nsh')

    def test_create_port_chain_with_tap_enabled_ppg_only(self):
        with self.port(
                name='port1',
                device_owner='compute',
                device_id='test',
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.port_pair(port_pair={
                'ingress': ingress['port']['id'],
                'egress': ingress['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']],
                    'tap_enabled': True
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': '10.100.0.0/16',
                        'destination_ip_prefix': '10.200.0.0/16',
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc:
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])
                            # proxy
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port['port']['id'])
                            # flow2 - sf_node
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                None
                            )
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2})
                            self.assertIn('skip_ingress_flow_config',
                                          update_flow_rules[flow1])
                            self.assertIsNone(
                                update_flow_rules[flow2]['egress']
                            )
                            self.assertEqual(
                                update_flow_rules[flow2]['node_type'],
                                update_flow_rules[flow1]['node_type']
                            )
                            self.assertTrue(
                                update_flow_rules[flow2]['tap_enabled'])

    def test_create_port_chain_with_default_and_tap_enabled_ppg(self):
        with self.port(
                name='port1',
                device_owner='compute',
                device_id='test',
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress1, self.port(
            name='egress1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as egress1, self.port(
            name='ingress2',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress2:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.port_pair(port_pair={
                'ingress': ingress1['port']['id'],
                'egress': egress1['port']['id']
            }) as default_pp, self.port_pair(port_pair={
                'ingress': ingress2['port']['id'],
                'egress': ingress2['port']['id']
            }) as tap_pp:
                default_pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx, default_pp['port_pair']
                )
                self.driver.create_port_pair(default_pp_context)
                tap_pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx, tap_pp['port_pair']
                )
                self.driver.create_port_pair(tap_pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [default_pp['port_pair']['id']]
                }) as default_ppg, self.port_pair_group(port_pair_group={
                    'port_pairs': [tap_pp['port_pair']['id']],
                    'tap_enabled': True
                }) as tap_ppg:
                    default_ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        default_ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(default_ppg_context)
                    tap_ppg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        tap_ppg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(tap_ppg_context)
                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': '10.100.0.0/16',
                        'destination_ip_prefix': '10.200.0.0/16',
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc:
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [
                                default_ppg['port_pair_group']['id'],
                                tap_ppg['port_pair_group']['id']
                            ],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            update_flow_rules = self.map_flow_rules(
                                self.rpc_calls['update_flow_rules'])

                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port['port']['id']
                            )
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress1['port']['id'],
                                egress1['port']['id']
                            )
                            flow3 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress2['port']['id'],
                                None
                            )
                            self.assertEqual(
                                set(update_flow_rules.keys()),
                                {flow1, flow2, flow3}
                            )
                            add_fcs = update_flow_rules[flow1]['add_fcs']
                            self.assertEqual(len(add_fcs), 1)
                            self.assertIsNone(
                                update_flow_rules[flow3]['egress'])
                            # egress mac of previous node as src mac for tap
                            #  flow
                            self.assertEqual(
                                update_flow_rules[flow2]['mac_address'],
                                update_flow_rules[flow3]['mac_address']
                            )
                            self.assertEqual(
                                update_flow_rules[flow3]['node_type'],
                                update_flow_rules[flow2]['node_type']
                            )

    def test_delete_port_chain_of_tap_enabled_ppg(self):
        with self.port(
                name='port1',
                device_owner='compute',
                device_id='test',
                arg_list=(
                    portbindings.HOST_ID,
                ),
                **{portbindings.HOST_ID: 'test'}
        ) as src_port, self.port(
            name='ingress',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as ingress:
            self.host_endpoint_mapping = {
                'test': '10.0.0.1',
            }
            with self.port_pair(port_pair={
                'ingress': ingress['port']['id'],
                'egress': ingress['port']['id']
            }) as pp:
                pp_context = sfc_ctx.PortPairContext(
                    self.sfc_plugin, self.ctx,
                    pp['port_pair']
                )
                self.driver.create_port_pair(pp_context)
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']],
                    'tap_enabled': True
                }) as pg:
                    pg_context = sfc_ctx.PortPairGroupContext(
                        self.sfc_plugin, self.ctx,
                        pg['port_pair_group']
                    )
                    self.driver.create_port_pair_group(pg_context)
                    with self.flow_classifier(flow_classifier={
                        'source_port_range_min': 100,
                        'source_port_range_max': 200,
                        'destination_port_range_min': 300,
                        'destination_port_range_max': 400,
                        'ethertype': 'IPv4',
                        'source_ip_prefix': '10.100.0.0/16',
                        'destination_ip_prefix': '10.200.0.0/16',
                        'l7_parameters': {},
                        'protocol': 'tcp',
                        'logical_source_port': src_port['port']['id']
                    }) as fc:
                        with self.port_chain(port_chain={
                            'name': 'test1',
                            'port_pair_groups': [pg['port_pair_group']['id']],
                            'flow_classifiers': [fc['flow_classifier']['id']]
                        }) as pc:
                            pc_context = sfc_ctx.PortChainContext(
                                self.sfc_plugin, self.ctx,
                                pc['port_chain']
                            )
                            self.driver.create_port_chain(pc_context)
                            self.wait()
                            self.driver.delete_port_chain(pc_context)
                            delete_flow_rules = self.map_flow_rules(
                                self.rpc_calls['delete_flow_rules'])
                            flow1 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                None,
                                src_port['port']['id'])
                            flow2 = self.build_ingress_egress(
                                pc['port_chain']['id'],
                                ingress['port']['id'],
                                None
                            )
                            self.assertEqual(
                                set(delete_flow_rules.keys()),
                                {flow1, flow2})
