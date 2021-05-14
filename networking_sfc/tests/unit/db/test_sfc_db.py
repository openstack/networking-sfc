# Copyright 2017 Futurewei. All rights reserved.
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

import contextlib
import logging
from unittest import mock

from neutron.api import extensions as api_ext
from neutron.common import config
import neutron.extensions as nextensions
from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import uuidutils
import webob.exc

from networking_sfc.db import flowclassifier_db as fdb
from networking_sfc.db import sfc_db
from networking_sfc import extensions
from networking_sfc.extensions import flowclassifier as fc_ext
from networking_sfc.extensions import servicegraph as sg_ext
from networking_sfc.extensions import sfc
from networking_sfc.extensions import tap as tap_ext
from networking_sfc.tests import base
from networking_sfc.tests.unit.db import test_flowclassifier_db


DB_SFC_PLUGIN_CLASS = (
    "networking_sfc.db.sfc_db.SfcDbPlugin"
)
extensions_path = ':'.join(extensions.__path__ + nextensions.__path__)


class SfcDbPluginTestCaseBase(
    base.BaseTestCase
):
    def _assert_port_chain_equal(self, res_port_chain, expected):
        # Flow classifiers are stored in a list, only check items for them
        for k, v in expected.items():
            if type(v) is list:
                self.assertCountEqual(res_port_chain[k], v)
            else:
                self.assertEqual(res_port_chain[k], v)

    def _create_port_chain(
        self, fmt, port_chain=None, expected_res_status=None, **kwargs
    ):
        ctx = kwargs.get('context', None)
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'port_chain': port_chain or {}}
        if ctx is None:
            data['port_chain'].update({'tenant_id': tenant_id})
        req = self.new_create_request(
            'port_chains', data, fmt, context=ctx
        )
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        return res

    @contextlib.contextmanager
    def port_chain(self, fmt=None, port_chain=None, do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_port_chain(fmt, port_chain, **kwargs)
        if res.status_int >= 400:
            logging.error('create port chain result: %s', res)
            raise webob.exc.HTTPClientError(code=res.status_int)
        port_chain = self.deserialize(fmt or self.fmt, res)
        yield port_chain
        if do_delete:
            self._delete('port_chains', port_chain['port_chain']['id'])

    def _create_port_pair_group(
        self, fmt, port_pair_group=None, expected_res_status=None, **kwargs
    ):
        ctx = kwargs.get('context', None)
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'port_pair_group': port_pair_group or {}}
        if ctx is None:
            data['port_pair_group'].update({'tenant_id': tenant_id})
        req = self.new_create_request(
            'port_pair_groups', data, fmt, context=ctx
        )
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        return res

    @contextlib.contextmanager
    def port_pair_group(
        self, fmt=None, port_pair_group=None, do_delete=True, **kwargs
    ):
        if not fmt:
            fmt = self.fmt
        res = self._create_port_pair_group(fmt, port_pair_group, **kwargs)
        if res.status_int >= 400:
            logging.error('create port pair group result: %s', res)
            raise webob.exc.HTTPClientError(code=res.status_int)
        port_pair_group = self.deserialize(fmt or self.fmt, res)
        yield port_pair_group
        if do_delete:
            self._delete(
                'port_pair_groups',
                port_pair_group['port_pair_group']['id'])

    def _create_port_pair(
        self, fmt, port_pair=None, expected_res_status=None, **kwargs
    ):
        ctx = kwargs.get('context', None)
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'port_pair': port_pair or {}}
        if ctx is None:
            data['port_pair'].update({'tenant_id': tenant_id})
        req = self.new_create_request(
            'port_pairs', data, fmt, context=ctx
        )
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        return res

    @contextlib.contextmanager
    def port_pair(self, fmt=None, port_pair=None, do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt
        res = self._create_port_pair(fmt, port_pair, **kwargs)
        if res.status_int >= 400:
            logging.error('create port pair result: %s', res)
            raise webob.exc.HTTPClientError(code=res.status_int)
        port_pair = self.deserialize(fmt or self.fmt, res)
        yield port_pair
        if do_delete:
            self._delete('port_pairs', port_pair['port_pair']['id'])

    def _create_service_graph(
        self, fmt, service_graph=None, expected_res_status=None, **kwargs
    ):
        ctx = kwargs.get('context', None)
        project_id = kwargs.get('project_id', self._tenant_id)
        data = {'service_graph': service_graph or {}}
        if ctx is None:
            data['service_graph'].update({'project_id': project_id})

        req = self.new_create_request(
            'service_graphs', data, fmt, context=ctx
        )
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(expected_res_status, res.status_int)
        return res

    @contextlib.contextmanager
    def service_graph(self, fmt=None,
                      service_graph=None, do_delete=True, **kwargs):
        if not fmt:
            fmt = self.fmt

        res = self._create_service_graph(fmt, service_graph, **kwargs)
        if res.status_int >= 400:
            logging.error('create Service Graph result: %s', res)
            raise webob.exc.HTTPClientError(code=res.status_int)
        service_graph = self.deserialize(fmt or self.fmt, res)
        yield service_graph
        if do_delete:
            self._delete('service_graphs', service_graph[
                'service_graph']['id'])

    def _get_expected_port_pair(self, port_pair):
        return {
            'name': port_pair.get('name') or '',
            'description': port_pair.get('description') or '',
            'egress': port_pair.get('egress'),
            'ingress': port_pair.get('ingress'),
            'service_function_parameters': port_pair.get(
                'service_function_parameters') or {
                'correlation': None, 'weight': 1
            }
        }

    def _test_create_port_pair(self, port_pair, expected_port_pair=None):
        if expected_port_pair is None:
            expected_port_pair = self._get_expected_port_pair(port_pair)
        with self.port_pair(port_pair=port_pair) as pp:
            for k, v in expected_port_pair.items():
                self.assertEqual(pp['port_pair'][k], v)

    def _test_create_port_pairs(
        self, port_pairs, expected_port_pairs=None
    ):
        if port_pairs:
            port_pair = port_pairs.pop()
            if expected_port_pairs:
                expected_port_pair = expected_port_pairs.pop()
            else:
                expected_port_pair = self._get_expected_port_pair(port_pair)
            with self.port_pair(port_pair=port_pair) as pp:
                for k, v in expected_port_pair.items():
                    self.assertEqual(pp['port_pair'][k], v)

    def _get_expected_port_pair_group(self, port_pair_group):
        ret = {
            'name': port_pair_group.get('name') or '',
            'description': port_pair_group.get('description') or '',
            'port_pairs': port_pair_group.get('port_pairs') or [],
            'port_pair_group_parameters': port_pair_group.get(
                'port_pair_group_parameters'
            ) or {'lb_fields': [],
                  'ppg_n_tuple_mapping': {'ingress_n_tuple': {},
                                          'egress_n_tuple': {}}}
        }
        if port_pair_group.get('group_id'):
            ret['group_id'] = port_pair_group['group_id']
        return ret

    def _test_create_port_pair_group(
        self, port_pair_group, expected_port_pair_group=None
    ):
        if expected_port_pair_group is None:
            expected_port_pair_group = self._get_expected_port_pair_group(
                port_pair_group)
        with self.port_pair_group(port_pair_group=port_pair_group) as pg:
            for k, v in expected_port_pair_group.items():
                self.assertEqual(pg['port_pair_group'][k], v)

    def _test_create_port_pair_groups(
        self, port_pair_groups, expected_port_pair_groups=None
    ):
        if port_pair_groups:
            port_pair_group = port_pair_groups.pop()
            if expected_port_pair_groups:
                expected_port_pair_group = expected_port_pair_groups.pop()
            else:
                expected_port_pair_group = self._get_expected_port_pair_group(
                    port_pair_group)
            with self.port_pair_group(port_pair_group=port_pair_group) as pg:
                for k, v in expected_port_pair_group.items():
                    self.assertEqual(pg['port_pair_group'][k], v)

    @staticmethod
    def _get_expected_port_chain(port_chain):
        chain_params = port_chain.get('chain_parameters') or dict()
        chain_params.setdefault('correlation', 'mpls')
        chain_params.setdefault('symmetric', False)
        ret = {
            'name': port_chain.get('name') or '',
            'description': port_chain.get('description') or '',
            'port_pair_groups': port_chain['port_pair_groups'],
            'flow_classifiers': port_chain.get('flow_classifiers') or [],
            'chain_parameters': chain_params
        }
        if port_chain.get('chain_id'):
            ret['chain_id'] = port_chain['chain_id']
        return ret

    def _test_create_port_chain(self, port_chain, expected_port_chain=None):
        if expected_port_chain is None:
            expected_port_chain = self._get_expected_port_chain(port_chain)
        with self.port_chain(port_chain=port_chain) as pc:
            for k, v in expected_port_chain.items():
                self.assertEqual(pc['port_chain'][k], v)

    def _test_create_port_chains(
        self, port_chains, expected_port_chains=None
    ):
        if port_chains:
            port_chain = port_chains.pop()
            if expected_port_chains:
                expected_port_chain = expected_port_chains.pop()
            else:
                expected_port_chain = self._get_expected_port_chain(
                    port_chain)
            with self.port_chain(port_chain=port_chain) as pc:
                for k, v in expected_port_chain.items():
                    self.assertEqual(pc['port_chain'][k], v)

    @staticmethod
    def _get_expected_graph(service_graph):
        ret = {
            'name': service_graph.get('name') or '',
            'description': service_graph.get('description') or '',
            'port_chains': service_graph.get('port_chains')
        }
        return ret

    def _test_create_service_graph(self, service_graph, expected_graph=None):
        if expected_graph is None:
            expected_graph = self._get_expected_graph(service_graph)
        with self.service_graph(service_graph=service_graph) as graph:
            for k, v in expected_graph.items():
                self.assertEqual(graph['service_graph'][k], v)


class SfcDbPluginTestCase(
    base.NeutronDbPluginV2TestCase,
    test_flowclassifier_db.FlowClassifierDbPluginTestCaseBase,
    SfcDbPluginTestCaseBase
):
    resource_prefix_map = dict([
        (k, sfc.SFC_PREFIX)
        for k in sfc.RESOURCE_ATTRIBUTE_MAP.keys()
    ] + [
        (k, fc_ext.FLOW_CLASSIFIER_PREFIX)
        for k in fc_ext.RESOURCE_ATTRIBUTE_MAP.keys()
    ] + [
        (k, sg_ext.SG_PREFIX)
        for k in sg_ext.RESOURCE_ATTRIBUTE_MAP.keys()
    ])

    def setUp(self, core_plugin=None, sfc_plugin=None,
              flowclassifier_plugin=None, ext_mgr=None):
        mock_log_p = mock.patch.object(sfc_db, 'LOG')
        self.mock_log = mock_log_p.start()
        cfg.CONF.register_opts(sfc.sfc_quota_opts, 'QUOTAS')
        if not sfc_plugin:
            sfc_plugin = DB_SFC_PLUGIN_CLASS
        if not flowclassifier_plugin:
            flowclassifier_plugin = (
                test_flowclassifier_db.DB_FLOWCLASSIFIER_PLUGIN_CLASS)

        service_plugins = {
            sfc.SFC_EXT: sfc_plugin,
            fc_ext.FLOW_CLASSIFIER_EXT: flowclassifier_plugin
        }
        sfc_db.SfcDbPlugin.supported_extension_aliases = [
            sfc.SFC_EXT, sg_ext.SG_EXT, tap_ext.TAP_EXT]
        sfc_db.SfcDbPlugin.path_prefix = sfc.SFC_PREFIX
        fdb.FlowClassifierDbPlugin.supported_extension_aliases = [
            fc_ext.FLOW_CLASSIFIER_EXT]
        fdb.FlowClassifierDbPlugin.path_prefix = (
            fc_ext.FLOW_CLASSIFIER_PREFIX
        )
        super(SfcDbPluginTestCase, self).setUp(
            ext_mgr=ext_mgr,
            plugin=core_plugin,
            service_plugins=service_plugins
        )
        if not ext_mgr:
            self.sfc_plugin = importutils.import_object(sfc_plugin)
            self.flowclassifier_plugin = importutils.import_object(
                flowclassifier_plugin)
            # Note (vks1): Auto-load extensions.
            ext_mgr = api_ext.PluginAwareExtensionManager.get_instance()
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)

    def test_create_port_chain(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'port_pair_groups': [pg['port_pair_group']['id']]})

    def test_quota_create_port_chain(self):
        cfg.CONF.set_override('quota_port_chain', 3, group='QUOTAS')
        with self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg2, self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg3, self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg4:
            self._create_port_chain(
                self.fmt, {
                    'port_pair_groups': [pg1['port_pair_group']['id']]
                }, expected_res_status=201)
            self._create_port_chain(
                self.fmt, {
                    'port_pair_groups': [pg2['port_pair_group']['id']]
                }, expected_res_status=201)
            self._create_port_chain(
                self.fmt, {
                    'port_pair_groups': [pg3['port_pair_group']['id']]
                }, expected_res_status=201)
            self._create_port_chain(
                self.fmt, {
                    'port_pair_groups': [pg4['port_pair_group']['id']]
                }, expected_res_status=409)

    def test_create_port_chain_all_fields(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'port_pair_groups': [pg['port_pair_group']['id']],
                'flow_classifiers': [],
                'name': 'abc',
                'description': 'def',
                'chain_parameters': {'symmetric': False, 'correlation': 'mpls'}
            })

    def test_create_port_chain_all_fields_with_chain_id(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'port_pair_groups': [pg['port_pair_group']['id']],
                'flow_classifiers': [],
                'name': 'abc',
                'description': 'def',
                'chain_parameters': {'symmetric': False,
                                     'correlation': 'mpls'},
                'chain_id': 99
            })

    def test_create_port_chain_all_fields_with_symmetric(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'port_pair_groups': [pg['port_pair_group']['id']],
                'flow_classifiers': [],
                'name': 'abc',
                'description': 'def',
                'chain_parameters': {'symmetric': True, 'correlation': 'mpls'}
            })

    def test_create_port_chain_multi_port_pair_groups(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            self._test_create_port_chain({
                'port_pair_groups': [
                    pg1['port_pair_group']['id'],
                    pg2['port_pair_group']['id']
                ]
            })

    def test_create_port_chain_shared_port_pair_groups(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2, self.port_pair_group(
            port_pair_group={}
        ) as pg3:
            self._test_create_port_chains([{
                'port_pair_groups': [
                    pg1['port_pair_group']['id'],
                    pg2['port_pair_group']['id']
                ]
            }, {
                'port_pair_groups': [
                    pg1['port_pair_group']['id'],
                    pg3['port_pair_group']['id']
                ]
            }])

    def test_create_port_chain_shared_port_pair_groups_different_order(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            self._test_create_port_chains([{
                'port_pair_groups': [
                    pg1['port_pair_group']['id'],
                    pg2['port_pair_group']['id']
                ]
            }, {
                'port_pair_groups': [
                    pg2['port_pair_group']['id'],
                    pg1['port_pair_group']['id']
                ]
            }])

    def test_create_port_chain_with_empty_chain_parameters(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'chain_parameters': {},
                'port_pair_groups': [pg['port_pair_group']['id']]
            })

    def test_create_port_chain_with_none_chain_parameters(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'chain_parameters': None,
                'port_pair_groups': [pg['port_pair_group']['id']]
            })

    def test_create_port_chain_with_default_chain_parameters(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'chain_parameters': {'symmetric': False,
                                     'correlation': 'mpls'},
                'port_pair_groups': [pg['port_pair_group']['id']]
            })

    def test_create_port_chain_with_nsh_correlation(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'chain_parameters': {'symmetric': False,
                                     'correlation': 'nsh'},
                'port_pair_groups': [pg['port_pair_group']['id']]
            })

    def test_create_port_chain_with_nsh_correlation_incompatible_ppg_fail(
            self):
        with self.port(
            name='port1',
            device_id='default'
        ) as port1, self.port(
            name='port2',
            device_id='default'
        ) as port2:
            with self.port_pair(port_pair={
                'ingress': port1['port']['id'],
                'egress': port1['port']['id'],
                'service_function_parameters': {'correlation': 'nsh'}
            }) as pp1, self.port_pair(port_pair={
                'ingress': port2['port']['id'],
                'egress': port2['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }) as pp2:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as ppg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as ppg2:
                    self._create_port_chain(
                        self.fmt, {
                            'chain_parameters': {'symmetric': False,
                                                 'correlation': 'nsh'},
                            'port_pair_groups': [
                                ppg1['port_pair_group']['id'],
                                ppg2['port_pair_group']['id']],
                        }, expected_res_status=400)

    def test_create_port_chains_with_conflicting_chain_ids(self):
        with self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg2:
            self._create_port_chain(
                self.fmt, {
                    'port_pair_groups': [pg1['port_pair_group']['id']],
                    'chain_id': 88
                }, expected_res_status=201)
            self._create_port_chain(
                self.fmt, {
                    'port_pair_groups': [pg2['port_pair_group']['id']],
                    'chain_id': 88
                }, expected_res_status=400
            )

    def test_create_port_chain_with_none_flow_classifiers(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'flow_classifiers': None,
                'port_pair_groups': [pg['port_pair_group']['id']]
            })

    def test_create_port_chain_with_empty_flow_classifiers(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._test_create_port_chain({
                'flow_classifiers': [],
                'port_pair_groups': [pg['port_pair_group']['id']]
            })

    def test_create_port_chain_with_flow_classifiers(self):
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(flow_classifier={
                'logical_source_port': port['port']['id']
            }) as fc:
                with self.port_pair_group(port_pair_group={}) as pg:
                    self._test_create_port_chain({
                        'flow_classifiers': [fc['flow_classifier']['id']],
                        'port_pair_groups': [pg['port_pair_group']['id']]
                    })

    def test_create_port_chain_with_multi_flow_classifiers(self):
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.100.0/24',
                'logical_source_port': port['port']['id']
            }) as fc1, self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.101.0/24',
                'logical_source_port': port['port']['id']
            }) as fc2:
                with self.port_pair_group(port_pair_group={}) as pg:
                    self._test_create_port_chain({
                        'flow_classifiers': [
                            fc1['flow_classifier']['id'],
                            fc2['flow_classifier']['id']
                        ],
                        'port_pair_groups': [pg['port_pair_group']['id']]
                    })

    def test_create_port_chain_with_flow_classifiers_basic_the_same(self):
        with self.port(
            name='test1'
        ) as port1, self.port(
            name='test2'
        ) as port2:
            with self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.100.0/24',
                'logical_source_port': port1['port']['id']
            }) as fc1, self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.100.0/24',
                'logical_source_port': port2['port']['id']
            }) as fc2:
                with self.port_pair_group(port_pair_group={}) as pg:
                    self._test_create_port_chain({
                        'flow_classifiers': [
                            fc1['flow_classifier']['id'],
                            fc2['flow_classifier']['id']
                        ],
                        'port_pair_groups': [pg['port_pair_group']['id']]
                    })

    def test_create_multi_port_chain_with_flow_classifiers(self):
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.100.0/24',
                'logical_source_port': port['port']['id']
            }) as fc1, self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.101.0/24',
                'logical_source_port': port['port']['id']
            }) as fc2:
                with self.port_pair_group(
                    port_pair_group={}
                ) as pg1, self.port_pair_group(
                    port_pair_group={}
                ) as pg2:
                    with self.port_chain(
                        port_chain={
                            'flow_classifiers': [
                                fc1['flow_classifier']['id']
                            ],
                            'port_pair_groups': [
                                pg1['port_pair_group']['id']
                            ]
                        }
                    ):
                        self._test_create_port_chain({
                            'flow_classifiers': [
                                fc2['flow_classifier']['id']
                            ],
                            'port_pair_groups': [pg2['port_pair_group']['id']]
                        })

    def test_create_multi_port_chain_with_conflict_flow_classifiers(self):
        with self.port(
            name='test1'
        ) as port1, self.port(
            name='test2'
        ) as port2:
            with self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.100.0/24',
                'logical_source_port': port1['port']['id']
            }) as fc1, self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.100.0/24',
                'logical_source_port': port2['port']['id']
            }) as fc2:
                with self.port_pair_group(
                    port_pair_group={}
                ) as pg1, self.port_pair_group(
                    port_pair_group={}
                ) as pg2:
                    with self.port_chain(
                        port_chain={
                            'flow_classifiers': [
                                fc1['flow_classifier']['id']
                            ],
                            'port_pair_groups': [
                                pg1['port_pair_group']['id']
                            ]
                        }
                    ):
                        self._create_port_chain(
                            self.fmt, {
                                'flow_classifiers': [
                                    fc2['flow_classifier']['id']
                                ],
                                'port_pair_groups': [
                                    pg2['port_pair_group']['id']
                                ]
                            },
                            expected_res_status=400
                        )

    def test_create_multi_port_chain_with_same_flow_classifier(self):
        with self.port(
            name='test1'
        ) as port1:
            with self.flow_classifier(flow_classifier={
                'source_ip_prefix': '192.168.100.0/24',
                'logical_source_port': port1['port']['id']
            }) as fc:
                with self.port_pair_group(
                    port_pair_group={}
                ) as pg1, self.port_pair_group(
                    port_pair_group={}
                ) as pg2:
                    with self.port_chain(
                        port_chain={
                            'flow_classifiers': [
                                fc['flow_classifier']['id']
                            ],
                            'port_pair_groups': [
                                pg1['port_pair_group']['id']
                            ]
                        }
                    ):
                        self._create_port_chain(
                            self.fmt, {
                                'flow_classifiers': [
                                    fc['flow_classifier']['id']
                                ],
                                'port_pair_groups': [
                                    pg2['port_pair_group']['id']
                                ]
                            },
                            expected_res_status=409
                        )

    def test_create_port_chain_with_port_pairs(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id']
            }) as pp2:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp1['port_pair']['id']
                    ]
                }) as pg1, self.port_pair_group(port_pair_group={
                    'port_pairs': [
                        pp2['port_pair']['id']
                    ]
                }) as pg2:
                    self._test_create_port_chain({
                        'port_pair_groups': [
                            pg1['port_pair_group']['id'],
                            pg2['port_pair_group']['id']
                        ]
                    })

    def test_create_port_chain_with_empty_port_pair_groups(self):
        self._create_port_chain(
            self.fmt, {'port_pair_groups': []},
            expected_res_status=400
        )

    def test_create_port_chain_with_nonuuid_port_pair_group_id(self):
        self._create_port_chain(
            self.fmt, {'port_pair_groups': ['unknown']},
            expected_res_status=400
        )

    def test_create_port_chain_with_unknown_port_pair_group_id(self):
        self._create_port_chain(
            self.fmt, {'port_pair_groups': [uuidutils.generate_uuid()]},
            expected_res_status=404
        )

    def test_create_port_chain_with_same_port_pair_groups(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg:
            with self.port_chain(
                port_chain={
                    'port_pair_groups': [pg['port_pair_group']['id']]
                }
            ):
                self._create_port_chain(
                    self.fmt, {
                        'port_pair_groups': [pg['port_pair_group']['id']]
                    }, expected_res_status=409
                )

    def test_create_port_chain_with_no_port_pair_groups(self):
        self._create_port_chain(
            self.fmt, {}, expected_res_status=400
        )

    def test_create_port_chain_with_consecutive_tap_port_pair_groups(self):
        with self.port(
            name='port1',
            device_id='tap_device1'
        ) as tap_port1, self.port(
            name='port2',
            device_id='tap_device2'
        ) as tap_port2:
            with self.port_pair(
                port_pair={
                    'ingress': tap_port1['port']['id'],
                    'egress': tap_port1['port']['id']
                }
            ) as tap_pp1, self.port_pair(
                port_pair={
                    'ingress': tap_port2['port']['id'],
                    'egress': tap_port2['port']['id']
                }
            ) as tap_pp2:
                with self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [tap_pp1['port_pair']['id']],
                        'tap_enabled': True
                    }
                ) as pg1, self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [tap_pp2['port_pair']['id']],
                        'tap_enabled': True
                    }
                ) as pg2:
                    self._create_port_chain(
                        self.fmt,
                        {
                            'port_pair_groups': [
                                pg1['port_pair_group']['id'],
                                pg2['port_pair_group']['id']
                            ]
                        },
                        expected_res_status=400
                    )

    def test_create_port_chain_with_non_consecutive_tap_port_pair_groups(self):
        with self.port(
            name='port1',
            device_id='tap_device1'
        ) as tap_port1, self.port(
            name='port2',
            device_id='default_device'
        ) as ingress_default, self.port(
            name='port3',
            device_id='default_device'
        ) as egress_default, self.port(
            name='port4',
            device_id='tap_device2'
        ) as tap_port2:
            with self.port_pair(
                port_pair={
                    'ingress': tap_port1['port']['id'],
                    'egress': tap_port1['port']['id']
                }
            ) as tap_pp1, self.port_pair(
                port_pair={
                    'ingress': ingress_default['port']['id'],
                    'egress': egress_default['port']['id']
                }
            ) as default_pp, self.port_pair(
                port_pair={
                    'ingress': tap_port2['port']['id'],
                    'egress': tap_port2['port']['id']
                }
            ) as tap_pp2:
                with self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [tap_pp1['port_pair']['id']],
                        'tap_enabled': True,
                        'port_pair_group_parameters': {
                            'lb_fields': [],
                            'ppg_n_tuple_mapping': {'ingress_n_tuple': {},
                                                    'egress_n_tuple': {}}}
                    }
                ) as tap_pg1, self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [default_pp['port_pair']['id']],
                        'tap_enabled': False,
                        'port_pair_group_parameters': {
                            'lb_fields': [],
                            'ppg_n_tuple_mapping': {'ingress_n_tuple': {},
                                                    'egress_n_tuple': {}}
                        }
                    }
                ) as default_pg, self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [tap_pp2['port_pair']['id']],
                        'tap_enabled': True,
                        'port_pair_group_parameters': {
                            'lb_fields': [],
                            'ppg_n_tuple_mapping': {'ingress_n_tuple': {},
                                                    'egress_n_tuple': {}
                                                    }
                        }
                    }
                ) as tap_pg2:
                    self._test_create_port_chain(
                        {
                            'port_pair_groups': [
                                tap_pg1['port_pair_group']['id'],
                                default_pg['port_pair_group']['id'],
                                tap_pg2['port_pair_group']['id']
                            ]
                        }
                    )

    def test_create_port_chain_with_invalid_chain_parameters(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._create_port_chain(
                self.fmt, {
                    'chain_parameters': {'correlation': 'unknown'},
                    'port_pair_groups': [pg['port_pair_group']['id']]
                }, expected_res_status=400
            )

    def test_create_port_chain_with_invalid_chain_parameters_symmetric(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._create_port_chain(
                self.fmt, {
                    'chain_parameters': {'symmetric': 'abc'},
                    'port_pair_groups': [pg['port_pair_group']['id']]
                }, expected_res_status=400
            )

    def test_create_port_chain_unknown_flow_classifiers(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._create_port_chain(
                self.fmt, {
                    'flow_classifiers': [uuidutils.generate_uuid()],
                    'port_pair_groups': [pg['port_pair_group']['id']]
                }, expected_res_status=404
            )

    def test_create_port_chain_nouuid_flow_classifiers(self):
        with self.port_pair_group(port_pair_group={}) as pg:
            self._create_port_chain(
                self.fmt, {
                    'flow_classifiers': ['unknown'],
                    'port_pair_groups': [pg['port_pair_group']['id']]
                }, expected_res_status=400
            )

    def test_list_port_chains(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg1['port_pair_group']['id']]
            }) as pc1, self.port_chain(port_chain={
                'port_pair_groups': [pg2['port_pair_group']['id']]
            }) as pc2:
                port_chains = [pc1, pc2]
                self._test_list_resources(
                    'port_chain', port_chains
                )

    def test_list_port_chains_with_params(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg1['port_pair_group']['id']]
            }) as pc1, self.port_chain(port_chain={
                'name': 'test2',
                'port_pair_groups': [pg2['port_pair_group']['id']]
            }) as pc2:
                self._test_list_resources(
                    'port_chain', [pc1],
                    query_params='name=test1'
                )
                self._test_list_resources(
                    'port_chain', [pc2],
                    query_params='name=test2'
                )
                self._test_list_resources(
                    'port_chain', [],
                    query_params='name=test3'
                )

    def test_list_port_chains_with_unknown_params(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg1['port_pair_group']['id']]
            }) as pc1, self.port_chain(port_chain={
                'name': 'test2',
                'port_pair_groups': [pg2['port_pair_group']['id']]
            }) as pc2:
                self._test_list_resources(
                    'port_chain', [pc1, pc2],
                    query_params='hello=test3'
                )

    def test_show_port_chain(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg:
            with self.port_chain(port_chain={
                'name': 'test1',
                'description': 'portchain',
                'port_pair_groups': [pg['port_pair_group']['id']]
            }) as pc:
                req = self.new_show_request(
                    'port_chains', pc['port_chain']['id']
                )
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api)
                )
                expected = self._get_expected_port_chain(pc['port_chain'])
                self._assert_port_chain_equal(res['port_chain'], expected)

    def test_show_port_chain_noexist(self):
        req = self.new_show_request(
            'port_chains', '1'
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(404, res.status_int)

    def test_update_port_chain_add_flow_classifiers(self):
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.100.0/24',
                    'logical_source_port': port['port']['id']
                }
            ) as fc1, self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.101.0/24',
                    'logical_source_port': port['port']['id']
                }
            ) as fc2:
                with self.port_pair_group(
                    port_pair_group={}
                ) as pg:
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'description': 'desc1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc1['flow_classifier']['id']]
                    }) as pc:
                        updates = {
                            'name': 'test2',
                            'description': 'desc2',
                            'flow_classifiers': [
                                fc1['flow_classifier']['id'],
                                fc2['flow_classifier']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = self.deserialize(
                            self.fmt,
                            req.get_response(self.ext_api)
                        )
                        expected = pc['port_chain']
                        expected.update(updates)
                        self._assert_port_chain_equal(
                            res['port_chain'], expected
                        )
                        req = self.new_show_request(
                            'port_chains', pc['port_chain']['id']
                        )
                        res = self.deserialize(
                            self.fmt, req.get_response(self.ext_api)
                        )
                        self._assert_port_chain_equal(
                            res['port_chain'], expected
                        )

    def test_update_port_chain_remove_flow_classifiers(self):
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.100.0/24',
                    'logical_source_port': port['port']['id']
                }
            ) as fc1, self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.101.0/24',
                    'logical_source_port': port['port']['id']
                }
            ) as fc2:
                with self.port_pair_group(
                    port_pair_group={}
                ) as pg:
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'description': 'desc1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [
                            fc1['flow_classifier']['id'],
                            fc2['flow_classifier']['id']
                        ]
                    }) as pc:
                        updates = {
                            'name': 'test2',
                            'description': 'desc2',
                            'flow_classifiers': [
                                fc1['flow_classifier']['id']
                            ]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = self.deserialize(
                            self.fmt,
                            req.get_response(self.ext_api)
                        )
                        expected = pc['port_chain']
                        expected.update(updates)
                        self._assert_port_chain_equal(
                            res['port_chain'], expected
                        )
                        req = self.new_show_request(
                            'port_chains', pc['port_chain']['id']
                        )
                        res = self.deserialize(
                            self.fmt, req.get_response(self.ext_api)
                        )
                        self._assert_port_chain_equal(
                            res['port_chain'], expected
                        )

    def test_update_port_chain_replace_flow_classifiers(self):
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.100.0/24',
                    'logical_source_port': port['port']['id']
                }
            ) as fc1, self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.101.0/24',
                    'logical_source_port': port['port']['id']
                }
            ) as fc2:
                with self.port_pair_group(
                    port_pair_group={}
                ) as pg:
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'description': 'desc1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc1['flow_classifier']['id']]
                    }) as pc:
                        updates = {
                            'name': 'test2',
                            'description': 'desc2',
                            'flow_classifiers': [fc2['flow_classifier']['id']]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = self.deserialize(
                            self.fmt,
                            req.get_response(self.ext_api)
                        )
                        expected = pc['port_chain']
                        expected.update(updates)
                        self._assert_port_chain_equal(
                            res['port_chain'], expected
                        )
                        req = self.new_show_request(
                            'port_chains', pc['port_chain']['id']
                        )
                        res = self.deserialize(
                            self.fmt, req.get_response(self.ext_api)
                        )
                        self._assert_port_chain_equal(
                            res['port_chain'], expected
                        )

    def test_update_port_chain_flow_classifiers_basic_the_same(self):
        with self.port(
            name='test1'
        ) as port1, self.port(
            name='test2'
        ) as port2:
            with self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.100.0/24',
                    'logical_source_port': port1['port']['id']
                }
            ) as fc1, self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.100.0/24',
                    'logical_source_port': port2['port']['id']
                }
            ) as fc2:
                with self.port_pair_group(
                    port_pair_group={}
                ) as pg:
                    with self.port_chain(port_chain={
                        'name': 'test1',
                        'description': 'desc1',
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc1['flow_classifier']['id']]
                    }) as pc:
                        updates = {
                            'name': 'test2',
                            'description': 'desc2',
                            'flow_classifiers': [fc2['flow_classifier']['id']]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc['port_chain']['id']
                        )
                        res = self.deserialize(
                            self.fmt,
                            req.get_response(self.ext_api)
                        )
                        expected = pc['port_chain']
                        expected.update(updates)
                        self._assert_port_chain_equal(
                            res['port_chain'], expected
                        )
                        req = self.new_show_request(
                            'port_chains', pc['port_chain']['id']
                        )
                        res = self.deserialize(
                            self.fmt, req.get_response(self.ext_api)
                        )
                        self._assert_port_chain_equal(
                            res['port_chain'], expected
                        )

    def test_update_port_chain_conflict_flow_classifiers(self):
        with self.port(
            name='test1'
        ) as port1, self.port(
            name='test2'
        ) as port2:
            with self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.100.0/24',
                    'logical_source_port': port1['port']['id']
                }
            ) as fc1, self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.101.0/24',
                    'logical_source_port': port1['port']['id']
                }
            ) as fc2, self.flow_classifier(
                flow_classifier={
                    'source_ip_prefix': '192.168.100.0/24',
                    'logical_source_port': port2['port']['id']
                }
            ) as fc3:
                with self.port_pair_group(
                    port_pair_group={}
                ) as pg1, self.port_pair_group(
                    port_pair_group={}
                ) as pg2:
                    with self.port_chain(port_chain={
                        'port_pair_groups': [pg1['port_pair_group']['id']],
                        'flow_classifiers': [fc1['flow_classifier']['id']]
                    }), self.port_chain(port_chain={
                        'name': 'test2',
                        'port_pair_groups': [pg2['port_pair_group']['id']],
                        'flow_classifiers': [fc2['flow_classifier']['id']]
                    }) as pc2:
                        updates = {
                            'flow_classifiers': [fc3['flow_classifier']['id']]
                        }
                        req = self.new_update_request(
                            'port_chains', {'port_chain': updates},
                            pc2['port_chain']['id']
                        )
                        res = req.get_response(self.ext_api)
                        self.assertEqual(400, res.status_int)

    def test_update_port_chain_add_port_pair_groups(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg1['port_pair_group']['id']],
            }) as pc:
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
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                expected = pc['port_chain']
                expected.update(updates)
                self._assert_port_chain_equal(res['port_chain'], expected)
                req = self.new_show_request(
                    'port_chains', pc['port_chain']['id']
                )
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api)
                )
                self._assert_port_chain_equal(res['port_chain'], expected)

    def test_update_port_chain_remove_port_pair_groups(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(port_chain={
                'port_pair_groups': [
                    pg1['port_pair_group']['id'],
                    pg2['port_pair_group']['id'],
                ],
            }) as pc:
                updates = {
                    'port_pair_groups': [
                        pg1['port_pair_group']['id']
                    ]
                }
                req = self.new_update_request(
                    'port_chains', {'port_chain': updates},
                    pc['port_chain']['id']
                )
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                expected = pc['port_chain']
                expected.update(updates)
                self._assert_port_chain_equal(res['port_chain'], expected)
                req = self.new_show_request(
                    'port_chains', pc['port_chain']['id']
                )
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api)
                )
                self._assert_port_chain_equal(res['port_chain'], expected)

    def test_update_port_chain_replace_port_pair_groups(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg1['port_pair_group']['id']],
            }) as pc:
                updates = {
                    'port_pair_groups': [pg2['port_pair_group']['id']]
                }
                req = self.new_update_request(
                    'port_chains', {'port_chain': updates},
                    pc['port_chain']['id']
                )
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                expected = pc['port_chain']
                expected.update(updates)
                self._assert_port_chain_equal(res['port_chain'], expected)
                req = self.new_show_request(
                    'port_chains', pc['port_chain']['id']
                )
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api)
                )
                self._assert_port_chain_equal(res['port_chain'], expected)

    def test_update_port_chain_chain_parameters(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg['port_pair_group']['id']],
            }) as pc:
                updates = {
                    'chain_parameters': {'correlation': 'mpls'}
                }
                req = self.new_update_request(
                    'port_chains', {'port_chain': updates},
                    pc['port_chain']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(400, res.status_int)

    def test_update_port_chain_part_of_graph_fail(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg1['port_pair_group']['id']]
            }) as pc1, self.port_chain(port_chain={
                'port_pair_groups': [pg2['port_pair_group']['id']]
            }) as pc2:
                with self.service_graph(service_graph={
                    'name': 'test1',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]}
                }):
                    updates = {
                        'port_pair_groups': [uuidutils.generate_uuid()]
                    }
                    req = self.new_update_request(
                        'port_chains', {'port_chain': updates},
                        pc1['port_chain']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(409, res.status_int)
                    updates = {
                        'flow_classifiers': [uuidutils.generate_uuid()]
                    }
                    req = self.new_update_request(
                        'port_chains', {'port_chain': updates},
                        pc2['port_chain']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(409, res.status_int)
                    updates = {
                        'name': 'new name',
                        'description': 'new description'
                    }
                    req = self.new_update_request(
                        'port_chains', {'port_chain': updates},
                        pc1['port_chain']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(200, res.status_int)

    def test_update_port_chain_consistency_with_consecutive_tap_ppg(self):
        with self.port(
            name='port1',
            device_id='tap_device1'
        ) as tap_port1, self.port(
            name='port2',
            device_id='tap_device2'
        ) as tap_port2:
            with self.port_pair(
                port_pair={
                    'ingress': tap_port1['port']['id'],
                    'egress': tap_port1['port']['id']
                }
            ) as tap_pp1, self.port_pair(
                port_pair={
                    'ingress': tap_port2['port']['id'],
                    'egress': tap_port2['port']['id']
                }
            ) as tap_pp2:
                with self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [tap_pp1['port_pair']['id']],
                        'tap_enabled': True
                    }
                ) as pg1, self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [tap_pp2['port_pair']['id']],
                        'tap_enabled': True
                    }
                ) as pg2:
                    with self.port_chain(
                            port_chain={
                                'port_pair_groups': [
                                    pg1['port_pair_group']['id']
                                ]
                            }
                    ) as pc:
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
                        self.assertEqual(400, res.status_int)

    def test_update_tap_port_chain_consistency(self):
        with self.port(
            name='port1',
            device_id='tap_device1'
        ) as tap_port1, self.port(
            name='port2',
            device_id='tap_device2'
        ) as tap_port2:
            with self.port_pair(
                port_pair={
                    'ingress': tap_port1['port']['id'],
                    'egress': tap_port1['port']['id']
                }
            ) as tap_pp1, self.port_pair(
                port_pair={
                    'ingress': tap_port2['port']['id'],
                    'egress': tap_port2['port']['id']
                }
            ) as tap_pp2:
                with self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [tap_pp1['port_pair']['id']],
                        'tap_enabled': True
                    }
                ) as pg1, self.port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [tap_pp2['port_pair']['id']],
                        'tap_enabled': False
                    }
                ) as pg2:
                    with self.port_chain(
                            port_chain={
                                'port_pair_groups': [
                                    pg1['port_pair_group']['id']
                                ]
                            }
                    ) as pc:
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
                        resp = req.get_response(self.ext_api)
                        self.assertEqual(200, resp.status_int)
                        res = self.deserialize(self.fmt, resp)
                        expected = pc['port_chain']
                        expected.update(updates)
                        self._assert_port_chain_equal(res['port_chain'],
                                                      expected)

    def test_delete_port_chain(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg['port_pair_group']['id']]
            }, do_delete=False) as pc:
                req = self.new_delete_request(
                    'port_chains', pc['port_chain']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(204, res.status_int)
                req = self.new_show_request(
                    'port_chains', pc['port_chain']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(404, res.status_int)
                req = self.new_show_request(
                    'port_pair_groups', pg['port_pair_group']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(200, res.status_int)

    def test_delete_port_chain_noexist(self):
        req = self.new_delete_request(
            'port_chains', '1'
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(404, res.status_int)

    def test_delete_port_chain_part_of_graph_fail(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg1['port_pair_group']['id']]
            }) as pc1, self.port_chain(port_chain={
                'port_pair_groups': [pg2['port_pair_group']['id']]
            }) as pc2:
                with self.service_graph(service_graph={
                    'name': 'test1',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]}
                }):
                    req = self.new_delete_request(
                        'port_chains', pc1['port_chain']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(409, res.status_int)
                    req = self.new_delete_request(
                        'port_chains', pc2['port_chain']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(409, res.status_int)

    def test_delete_flow_classifier_port_chain_exist(self):
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(flow_classifier={
                'logical_source_port': port['port']['id']
            }) as fc:
                with self.port_pair_group(port_pair_group={
                }) as pg:
                    with self.port_chain(port_chain={
                        'port_pair_groups': [pg['port_pair_group']['id']],
                        'flow_classifiers': [fc['flow_classifier']['id']]
                    }):
                        req = self.new_delete_request(
                            'flow_classifiers', fc['flow_classifier']['id']
                        )
                        res = req.get_response(self.ext_api)
                        self.assertEqual(409, res.status_int)

    def test_create_port_pair_group(self):
        self._test_create_port_pair_group({})

    def test_quota_create_port_pair_group_quota(self):
        cfg.CONF.set_override('quota_port_pair_group', 3, group='QUOTAS')
        self._create_port_pair_group(
            self.fmt, {'port_pairs': []}, expected_res_status=201
        )
        self._create_port_pair_group(
            self.fmt, {'port_pairs': []}, expected_res_status=201
        )
        self._create_port_pair_group(
            self.fmt, {'port_pairs': []}, expected_res_status=201
        )
        self._create_port_pair_group(
            self.fmt, {'port_pairs': []}, expected_res_status=409
        )

    def test_create_port_pair_group_all_fields(self):
        self._test_create_port_pair_group({
            'name': 'test1',
            'description': 'desc1',
            'port_pairs': [],
            'tap_enabled': False,
            'port_pair_group_parameters': {
                'lb_fields': ['ip_src', 'ip_dst'],
                'ppg_n_tuple_mapping': {
                    'ingress_n_tuple': {'source_ip_prefix': None},
                    'egress_n_tuple': {'destination_ip_prefix': None}}
            }
        })

    def test_create_port_pair_group_with_empty_parameters(self):
        self._test_create_port_pair_group({
            'name': 'test1',
            'description': 'desc1',
            'port_pairs': [],
            'port_pair_group_parameters': {}
        })

    def test_create_port_pair_group_with_none_parameters(self):
        self._test_create_port_pair_group({
            'name': 'test1',
            'description': 'desc1',
            'port_pairs': [],
            'port_pair_group_parameters': None
        })

    def test_create_port_pair_group_with_default_parameters(self):
        self._test_create_port_pair_group({
            'name': 'test1',
            'description': 'desc1',
            'port_pairs': [],
            'tap_enabled': False,
            'port_pair_group_parameters': {
                'lb_fields': [],
                'ppg_n_tuple_mapping': {}
            }
        })

    def test_create_port_pair_group_with_tap_enabled_parameter_true(self):
        self._test_create_port_pair_group(
            {
                'name': 'test1',
                'description': 'desc1',
                'port_pairs': [],
                'tap_enabled': True,
                'port_pair_group_parameters': {}
            },
            expected_port_pair_group={
                'name': 'test1',
                'description': 'desc1',
                'port_pairs': [],
                'tap_enabled': True,
                'port_pair_group_parameters': {
                    'lb_fields': [],
                    'ppg_n_tuple_mapping': {u'egress_n_tuple': {},
                                            u'ingress_n_tuple': {}},
                }
            }
        )

    def test_create_ppg_with_all_params_and_tap_enabled_parameter_true(self):
        self._create_port_pair_group(
            self.fmt,
            {
                'name': 'test1',
                'description': 'desc1',
                'port_pairs': [],
                'tap_enabled': True,
                'port_pair_group_parameters': {
                    'lb_fields': ['ip_src', 'ip_dst'],
                    'ppg_n_tuple_mapping': {
                        'ingress_n_tuple': {'source_ip_prefix': None},
                        'egress_n_tuple': {'destination_ip_prefix': None}}
                }
            })

    def test_create_port_pair_group_with_port_pairs(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id']
            }) as pp2:
                self._test_create_port_pair_group({
                    'port_pairs': [
                        pp1['port_pair']['id'],
                        pp2['port_pair']['id']
                    ]
                })

    def test_create_tap_port_pair_group_with_single_port_pair(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp1:
                self._test_create_port_pair_group(
                    {
                        'port_pairs': [
                            pp1['port_pair']['id'],
                        ],
                        'tap_enabled': True
                    }
                )

    def test_create_tap_pair_group_with_multiple_port_pairs(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id']
            }) as pp2:
                self._create_port_pair_group(
                    self.fmt,
                    {
                        'port_pairs': [
                            pp1['port_pair']['id'],
                            pp2['port_pair']['id']
                        ],
                        'tap_enabled': True
                    },
                    expected_res_status=400
                )

    def test_create_port_pair_group_consistent_correlations(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }) as pp1, self.port_pair(port_pair={
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }) as pp2:
                self._test_create_port_pair_group({
                    'port_pairs': [
                        pp1['port_pair']['id'],
                        pp2['port_pair']['id']
                    ]
                })

    def test_create_port_pair_group_inconsistent_correlations(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }) as pp1, self.port_pair(port_pair={
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id'],
                'service_function_parameters': {'correlation': None}
            }) as pp2:
                self._create_port_pair_group(
                    self.fmt,
                    {'port_pairs': [
                        pp1['port_pair']['id'],
                        pp2['port_pair']['id']
                    ]},
                    expected_res_status=400)

    def test_create_port_pair_group_with_nouuid_port_pair_id(self):
        self._create_port_pair_group(
            self.fmt, {'port_pairs': ['unknown']},
            expected_res_status=400
        )

    def test_create_port_pair_group_with_unknown_port_pair_id(self):
        self._create_port_pair_group(
            self.fmt, {'port_pairs': [uuidutils.generate_uuid()]},
            expected_res_status=404
        )

    def test_create_port_pair_group_share_port_pair_id(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']]
                }):
                    self._create_port_pair_group(
                        self.fmt, {'port_pairs': [pp['port_pair']['id']]},
                        expected_res_status=409
                    )

    def test_list_port_pair_groups(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }) as pc1, self.port_pair_group(port_pair_group={
            'name': 'test2'
        }) as pc2:
            port_pair_groups = [pc1, pc2]
            self._test_list_resources(
                'port_pair_group', port_pair_groups
            )

    def test_list_port_pair_groups_with_params(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }) as pc1, self.port_pair_group(port_pair_group={
            'name': 'test2'
        }) as pc2:
            self._test_list_resources(
                'port_pair_group', [pc1],
                query_params='name=test1'
            )
            self._test_list_resources(
                'port_pair_group', [pc2],
                query_params='name=test2'
            )
            self._test_list_resources(
                'port_pair_group', [],
                query_params='name=test3'
            )

    def test_list_port_pair_groups_with_unknown_params(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }) as pc1, self.port_pair_group(port_pair_group={
            'name': 'test2'
        }) as pc2:
            self._test_list_resources(
                'port_pair_group', [pc1, pc2],
                query_params='hello=test3'
            )

    def test_show_port_pair_group(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }) as pc:
            req = self.new_show_request(
                'port_pair_groups', pc['port_pair_group']['id']
            )
            res = self.deserialize(
                self.fmt, req.get_response(self.ext_api)
            )
            for k, v in pc['port_pair_group'].items():
                self.assertEqual(res['port_pair_group'][k], v)

    def test_show_port_pair_group_noexist(self):
        req = self.new_show_request(
            'port_pair_groups', '1'
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(404, res.status_int)

    def test_update_port_pair_group(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id']
            }) as pp2:
                with self.port_pair_group(port_pair_group={
                    'name': 'test1',
                    'description': 'desc1',
                    'port_pairs': [pp1['port_pair']['id']]
                }) as pg:
                    updates = {
                        'name': 'test2',
                        'description': 'desc2',
                        'port_pairs': [pp2['port_pair']['id']]
                    }
                    req = self.new_update_request(
                        'port_pair_groups', {'port_pair_group': updates},
                        pg['port_pair_group']['id']
                    )
                    res = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )
                    expected = pg['port_pair_group']
                    expected.update(updates)
                    for k, v in expected.items():
                        self.assertEqual(res['port_pair_group'][k], v)
                    req = self.new_show_request(
                        'port_pair_groups', pg['port_pair_group']['id']
                    )
                    res = self.deserialize(
                        self.fmt, req.get_response(self.ext_api)
                    )
                    for k, v in expected.items():
                        self.assertEqual(res['port_pair_group'][k], v)

    def test_update_port_pair_group_consistency_checks(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as port1, self.port(
            name='port2',
            device_id='default'
        ) as port2, self.port(
            name='port3',
            device_id='default'
        ) as port3, self.port(
            name='port4',
            device_id='default'
        ) as port4:
            with self.port_pair(port_pair={
                'ingress': port1['port']['id'],
                'egress': port2['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }) as pp1, self.port_pair(port_pair={
                'ingress': port2['port']['id'],
                'egress': port3['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }) as pp2, self.port_pair(port_pair={
                'ingress': port3['port']['id'],
                'egress': port4['port']['id'],
                'service_function_parameters': {'correlation': None}
            }) as pp3, self.port_pair(port_pair={
                'ingress': port4['port']['id'],
                'egress': port1['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }) as pp4:
                with self.port_pair_group(port_pair_group={
                    'name': 'test1',
                    'description': 'desc1',
                    'port_pairs': [pp1['port_pair']['id'],
                                   pp2['port_pair']['id']]
                }) as pg:
                    updates = {
                        'name': 'test2',
                        'description': 'desc2',
                        'port_pairs': [pp1['port_pair']['id'],
                                       pp2['port_pair']['id'],
                                       pp3['port_pair']['id']]
                    }
                    req = self.new_update_request(
                        'port_pair_groups', {'port_pair_group': updates},
                        pg['port_pair_group']['id']
                    )
                    resp = req.get_response(self.ext_api)
                    self.assertEqual(400, resp.status_int)

                    updates = {
                        'name': 'test3',
                        'description': 'desc3',
                        'port_pairs': [pp1['port_pair']['id'],
                                       pp2['port_pair']['id'],
                                       pp4['port_pair']['id']]
                    }
                    req = self.new_update_request(
                        'port_pair_groups', {'port_pair_group': updates},
                        pg['port_pair_group']['id']
                    )
                    resp = req.get_response(self.ext_api)
                    res = self.deserialize(self.fmt, resp)
                    expected = pg['port_pair_group']
                    expected.update(updates)
                    for k, v in expected.items():
                        self.assertEqual(res['port_pair_group'][k], v)
                    req = self.new_show_request(
                        'port_pair_groups', pg['port_pair_group']['id']
                    )
                    res = self.deserialize(
                        self.fmt, req.get_response(self.ext_api)
                    )
                    for k, v in expected.items():
                        self.assertEqual(res['port_pair_group'][k], v)

    def test_update_tap_port_pair_group_consistency(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp1, self.port_pair(port_pair={
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id']
            }) as pp2:
                with self.port_pair_group(port_pair_group={
                    'name': 'test1',
                    'description': 'desc1',
                    'port_pairs': [pp1['port_pair']['id']],

                }) as pg:
                    updates = {
                        'name': 'test2',
                        'description': 'desc2',
                        'port_pairs': [pp1['port_pair']['id'],
                                       pp2['port_pair']['id']],
                        'tap_enabled': True
                    }
                    req = self.new_update_request(
                        'port_pair_groups', {'port_pair_group': updates},
                        pg['port_pair_group']['id']
                    )
                    resp = req.get_response(self.ext_api)
                    self.assertEqual(400, resp.status_int)

    def test_delete_port_pair_group(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }, do_delete=False) as pc:
            req = self.new_delete_request(
                'port_pair_groups', pc['port_pair_group']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(204, res.status_int)
            req = self.new_show_request(
                'port_pair_groups', pc['port_pair_group']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(404, res.status_int)

    def test_delete_port_pair_group_port_chain_exist(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }) as pg:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg['port_pair_group']['id']]
            }):
                req = self.new_delete_request(
                    'port_pair_groups', pg['port_pair_group']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(409, res.status_int)

    def test_delete_port_pair_group_noexist(self):
        req = self.new_delete_request(
            'port_pair_groups', '1'
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(404, res.status_int)

    def test_create_port_pair(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            self._test_create_port_pair({
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            })

    def test_quota_create_port_pair_quota(self):
        cfg.CONF.set_override('quota_port_pair', 3, group='QUOTAS')
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port1, self.port(
            name='port2',
            device_id='default'
        ) as dst_port1, self.port(
            name='port3',
            device_id='default'
        ) as src_port2, self.port(
            name='port4',
            device_id='default'
        ) as dst_port2, self.port(
            name='port5',
            device_id='default'
        ) as src_port3, self.port(
            name='port6',
            device_id='default'
        ) as dst_port3, self.port(
            name='port7',
            device_id='default'
        ) as src_port4, self.port(
            name='port8',
            device_id='default'
        ) as dst_port4:
            self._create_port_pair(
                self.fmt, {
                    'ingress': src_port1['port']['id'],
                    'egress': dst_port1['port']['id']
                }, expected_res_status=201)
            self._create_port_pair(
                self.fmt, {
                    'ingress': src_port2['port']['id'],
                    'egress': dst_port2['port']['id']
                }, expected_res_status=201)
            self._create_port_pair(
                self.fmt, {
                    'ingress': src_port3['port']['id'],
                    'egress': dst_port3['port']['id']
                }, expected_res_status=201)
            self._create_port_pair(
                self.fmt, {
                    'ingress': src_port4['port']['id'],
                    'egress': dst_port4['port']['id']
                }, expected_res_status=409)

    def test_create_port_pair_all_fields(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            self._test_create_port_pair({
                'name': 'test1',
                'description': 'desc1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id'],
                'service_function_parameters': {
                    'correlation': None, 'weight': 2}
            })

    def test_create_port_pair_none_service_function_parameters(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            self._test_create_port_pair({
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id'],
                'service_function_parameters': None
            })

    def test_create_port_pair_empty_service_function_parameters(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            self._test_create_port_pair({
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id'],
                'service_function_parameters': {}
            })

    def test_create_port_pair_with_src_dst_same_port(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_dst_port:
            self._test_create_port_pair({
                'ingress': src_dst_port['port']['id'],
                'egress': src_dst_port['port']['id']
            })

    def test_create_port_pair_empty_input(self):
        self._create_port_pair(self.fmt, {}, expected_res_status=400)

    def test_create_port_pair_with_no_ingress(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'egress': dst_port['port']['id']
                },
                expected_res_status=400
            )

    def test_create_port_pair_with_no_egress(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_port['port']['id']
                },
                expected_res_status=400
            )

    def test_create_port_pair_with_nouuid_ingress(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': '1',
                    'egress': dst_port['port']['id']
                },
                expected_res_status=400
            )

    def test_create_port_pair_with_unknown_ingress(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': uuidutils.generate_uuid(),
                    'egress': dst_port['port']['id']
                },
                expected_res_status=404
            )

    def test_create_port_pair_with_nouuid_egress(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_port['port']['id'],
                    'egress': '1'
                },
                expected_res_status=400
            )

    def test_create_port_pair_with_unknown_egress(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_port['port']['id'],
                    'egress': uuidutils.generate_uuid()
                },
                expected_res_status=404
            )

    def test_create_port_pair_ingress_egress_different_hosts(self):
        with self.port(
            name='port1',
            device_id='device1'
        ) as src_port, self.port(
            name='port2',
            device_id='device2'
        ) as dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_port['port']['id'],
                    'egress': dst_port['port']['id']
                },
                expected_res_status=400
            )

    def test_create_port_pair_with_invalid_service_function_parameters(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_dst_port['port']['id'],
                    'egress': src_dst_port['port']['id'],
                    'service_function_parameters': {'abc': 'def'}
                },
                expected_res_status=400
            )

    def test_create_port_pair_with_invalid_correlation(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_dst_port['port']['id'],
                    'egress': src_dst_port['port']['id'],
                    'service_function_parameters': {'correlation': 'def'}
                },
                expected_res_status=400
            )

    def test_create_port_pair_with_invalid_weight(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_dst_port['port']['id'],
                    'egress': src_dst_port['port']['id'],
                    'service_function_parameters': {'weight': -1}
                },
                expected_res_status=400
            )

    def test_list_port_pairs(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc1, self.port_pair(port_pair={
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id']
            }) as pc2:
                port_pairs = [pc1, pc2]
                self._test_list_resources(
                    'port_pair', port_pairs
                )

    def test_list_port_pairs_with_params(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc1, self.port_pair(port_pair={
                'name': 'test2',
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id']
            }) as pc2:
                self._test_list_resources(
                    'port_pair', [pc1],
                    query_params='name=test1'
                )
                self._test_list_resources(
                    'port_pair', [pc2],
                    query_params='name=test2'
                )
                self._test_list_resources(
                    'port_pair', [],
                    query_params='name=test3'
                )

    def test_list_port_pairs_with_unknown_params(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc1, self.port_pair(port_pair={
                'name': 'test2',
                'ingress': dst_port['port']['id'],
                'egress': src_port['port']['id']
            }) as pc2:
                port_pairs = [pc1, pc2]
                self._test_list_resources(
                    'port_pair', port_pairs,
                    query_params='hello=test3'
                )

    def test_show_port_pair(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc:
                req = self.new_show_request(
                    'port_pairs', pc['port_pair']['id']
                )
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api)
                )
                for k, v in pc['port_pair'].items():
                    self.assertEqual(res['port_pair'][k], v)

    def test_show_port_pair_noexist(self):
        req = self.new_show_request(
            'port_pairs', '1'
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(404, res.status_int)

    def test_update_port_pair(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'description': 'desc1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc:
                updates = {
                    'name': 'test2',
                    'description': 'desc2'
                }
                req = self.new_update_request(
                    'port_pairs', {'port_pair': updates},
                    pc['port_pair']['id']
                )
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                expected = pc['port_pair']
                expected.update(updates)
                for k, v in expected.items():
                    self.assertEqual(res['port_pair'][k], v)
                req = self.new_show_request(
                    'port_pairs', pc['port_pair']['id']
                )
                res = self.deserialize(
                    self.fmt, req.get_response(self.ext_api)
                )
                for k, v in expected.items():
                    self.assertEqual(res['port_pair'][k], v)

    def test_update_port_pair_service_function_parameters(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'description': 'desc1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc:
                updates = {
                    'service_function_parameters': {
                        'correlation': None, 'weight': 2,
                    }
                }
                req = self.new_update_request(
                    'port_pairs', {'port_pair': updates},
                    pc['port_pair']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(400, res.status_int)

    def test_update_port_pair_ingress(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'description': 'desc1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc:
                updates = {
                    'ingress': dst_port['port']['id']
                }
                req = self.new_update_request(
                    'port_pairs', {'port_pair': updates},
                    pc['port_pair']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(400, res.status_int)

    def test_update_port_pair_egress(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'description': 'desc1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc:
                updates = {
                    'egress': src_port['port']['id']
                }
                req = self.new_update_request(
                    'port_pairs', {'port_pair': updates},
                    pc['port_pair']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(400, res.status_int)

    def test_delete_port_pair(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }, do_delete=False) as pc:
                req = self.new_delete_request(
                    'port_pairs', pc['port_pair']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(204, res.status_int)
                req = self.new_show_request(
                    'port_pairs', pc['port_pair']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(404, res.status_int)

    def test_delete_port_pair_noexist(self):
        req = self.new_delete_request(
            'port_pairs', '1'
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(404, res.status_int)

    def test_delete_port_pair_port_pair_group_exist(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pp:
                with self.port_pair_group(port_pair_group={
                    'port_pairs': [pp['port_pair']['id']]
                }):
                    req = self.new_delete_request(
                        'port_pairs', pp['port_pair']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(409, res.status_int)

    def test_delete_ingress_port_pair_exist(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }):
                req = self.new_delete_request(
                    'ports', src_port['port']['id']
                )
                res = req.get_response(self.api)
                self.assertEqual(500, res.status_int)

    def test_delete_egress_port_pair_exist(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }):
                req = self.new_delete_request(
                    'ports', dst_port['port']['id']
                )
                res = req.get_response(self.api)
                self.assertEqual(500, res.status_int)

    def _test_create_service_graph_branching_ppg(
            self, src_corr, dst_corr, status):
        with self.port(
            name='port1',
            device_id='default'
        ) as port1, self.port(
            name='port2',
            device_id='default'
        ) as port2, self.port(
            name='port3',
            device_id='default'
        ) as port3, self.port(
            name='port4',
            device_id='default'
        ) as port4:
            with self.port_pair(port_pair={
                'ingress': port1['port']['id'],
                'egress': port1['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }, do_delete=False) as pp1, self.port_pair(port_pair={
                'ingress': port2['port']['id'],
                'egress': port2['port']['id'],
                'service_function_parameters': {'correlation': src_corr}
            }, do_delete=False) as pp2, self.port_pair(port_pair={
                'ingress': port3['port']['id'],
                'egress': port3['port']['id'],
                'service_function_parameters': {'correlation': dst_corr}
            }, do_delete=False) as pp3, self.port_pair(port_pair={
                'ingress': port4['port']['id'],
                'egress': port4['port']['id'],
                'service_function_parameters': {'correlation': 'mpls'}
            }, do_delete=False) as pp4:
                with self.port_pair_group(
                    port_pair_group={'port_pairs': [pp1['port_pair']['id']]},
                    do_delete=False
                ) as pg1, self.port_pair_group(
                    port_pair_group={'port_pairs': [pp2['port_pair']['id']]},
                    do_delete=False
                ) as pg2, self.port_pair_group(
                    port_pair_group={'port_pairs': [pp3['port_pair']['id']]},
                    do_delete=False
                ) as pg3, self.port_pair_group(
                    port_pair_group={'port_pairs': [pp4['port_pair']['id']]},
                    do_delete=False
                ) as pg4:
                    with self.port_chain(
                        do_delete=False,
                        port_chain={'port_pair_groups': [
                            pg1['port_pair_group']['id'],
                            pg2['port_pair_group']['id']]}
                    ) as pc1, self.port_chain(
                        do_delete=False,
                        port_chain={'port_pair_groups': [
                            pg3['port_pair_group']['id'],
                            pg4['port_pair_group']['id']]}
                    ) as pc2:
                        self._create_service_graph(self.fmt, {
                            'port_chains': {
                                pc1['port_chain']['id']: [
                                    pc2['port_chain']['id']]
                            },
                            'name': 'abc',
                            'description': 'def'
                        }, expected_res_status=status)

    def test_create_service_graph_branching_ppg_no_src_corr_fail(self):
        self._test_create_service_graph_branching_ppg(None, 'mpls', 400)

    def test_create_service_graph_branching_ppg_no_dst_corr_fail(self):
        self._test_create_service_graph_branching_ppg('mpls', None, 400)

    def test_create_service_graph_branching_ppg_both_corrs_ok(self):
        self._test_create_service_graph_branching_ppg('mpls', 'mpls', 201)

    def test_create_service_graph_linear_dependency_only(self):
        # this test will create a graph consisting of 1 port chain being
        # dependent on 1 other port chain, thus with no branching.
        with self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg2:
            with self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=201)

    def test_create_service_graph_branching_no_class(self):
        # this test will create a graph where 1 port chain will act
        # as a dependency to 2 other port chains, effectively
        # creating a branching service function chain.
        with self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg2, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg3:
            with self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg3['port_pair_group']['id']]}
            ) as pc3:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [
                            pc2['port_chain']['id'],
                            pc3['port_chain']['id']
                        ]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=201)

    def test_create_service_graph_same_chain_fail(self):
        # this test will attempt to create a graph with a single branching
        # point having 2 port chains - which are actually the same port chain.
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={
                    'port_pair_groups': [pg1['port_pair_group']['id']]
                }
            ) as pc1, self.port_chain(
                port_chain={
                    'port_pair_groups': [pg2['port_pair_group']['id']]
                }
            ) as pc2:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [
                            pc2['port_chain']['id'],
                            pc2['port_chain']['id']
                        ]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=400)

    def test_create_service_graph_with_already_used_pcs_fail(self):
        # this test will attempt to create a graph that maps
        # port-chains which have already been mapped to other graphs.
        with self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg2, self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg3:
            with self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg3['port_pair_group']['id']]}
            ) as pc3:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [
                            pc2['port_chain']['id']
                        ]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=201)
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc3['port_chain']['id']: [
                            pc1['port_chain']['id']
                        ]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=409)

    def test_create_service_graph_with_multiple_starts(self):
        # this test will create a graph with multiple starting chains (tails)
        with self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg2, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg3, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg4:
            with self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg3['port_pair_group']['id']]}
            ) as pc3, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg4['port_pair_group']['id']]}
            ) as pc4:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']],
                        pc3['port_chain']['id']: [pc4['port_chain']['id']],
                        pc4['port_chain']['id']: [pc2['port_chain']['id']]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=201)

    def _test_create_service_graph_single_branching_two_fcs_each(
            self, fc1_dict, fc2_dict, fc3_dict, fc4_dict, expected_res_status
    ):
        with self.flow_classifier(
            flow_classifier=fc1_dict, do_delete=False
        ) as fc1, self.flow_classifier(
            flow_classifier=fc2_dict, do_delete=False
        ) as fc2, self.flow_classifier(
            flow_classifier=fc3_dict, do_delete=False
        ) as fc3, self.flow_classifier(
            flow_classifier=fc4_dict, do_delete=False
        ) as fc4:
            with self.port_pair_group(
                port_pair_group={}, do_delete=False
            ) as pg1, self.port_pair_group(
                port_pair_group={}, do_delete=False
            ) as pg2, self.port_pair_group(
                port_pair_group={}, do_delete=False
            ) as pg3:
                with self.port_chain(
                    port_chain={
                        'port_pair_groups': [pg1['port_pair_group']['id']]
                    },
                    do_delete=False
                ) as pc1, self.port_chain(
                    port_chain={
                        'port_pair_groups': [pg2['port_pair_group']['id']],
                        'flow_classifiers': [
                            fc1['flow_classifier']['id'],
                            fc2['flow_classifier']['id']
                        ]
                    },
                    do_delete=False
                ) as pc2, self.port_chain(
                    port_chain={
                        'port_pair_groups': [pg3['port_pair_group']['id']],
                        'flow_classifiers': [
                            fc3['flow_classifier']['id'],
                            fc4['flow_classifier']['id']
                        ]
                    },
                    do_delete=False
                ) as pc3:
                    self._create_service_graph(self.fmt, {
                        'port_chains': {
                            pc1['port_chain']['id']: [
                                pc2['port_chain']['id'],
                                pc3['port_chain']['id']
                            ]
                        },
                        'name': 'abc',
                        'description': 'def'
                    }, expected_res_status=expected_res_status)

    def test_create_service_graph_unambiguous_branch(self):
        # this test will create a graph where 1 port chain will act
        # as a dependency to 2 other port chains, using different
        # classifications for the dependent chains, which must succeed.
        with self.port(
            name='test1', do_delete=False
        ) as port1, self.port(
            name='test2', do_delete=False
        ) as port2, self.port(
            name='test3', do_delete=False
        ) as port3, self.port(
            name='test4', do_delete=False
        ) as port4:
            fc1_dict = {
                'name': 'fc1',
                'ethertype': 'IPv4',
                'protocol': 'tcp',
                'logical_source_port': port1['port']['id']
            }
            fc2_dict = {
                'name': 'fc2',
                'ethertype': 'IPv6',
                'protocol': 'tcp',
                'logical_source_port': port2['port']['id']
            }
            fc3_dict = {
                'name': 'fc3',
                'ethertype': 'IPv4',
                'protocol': 'udp',
                'logical_source_port': port3['port']['id']
            }
            fc4_dict = {
                'name': 'fc4',
                'ethertype': 'IPv6',
                'protocol': 'udp',
                'logical_source_port': port4['port']['id']
            }
            self._test_create_service_graph_single_branching_two_fcs_each(
                fc1_dict, fc2_dict, fc3_dict, fc4_dict,
                expected_res_status=201)

    def test_create_service_graph_with_direct_loop_fail(self):
        # this test will attempt to create a graph where there is a direct
        # loop, i.e. a chain linked to itself - specifically pc2->pc2.
        with self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg2:
            with self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']],
                        pc2['port_chain']['id']: [pc2['port_chain']['id']]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=400)

    def test_create_service_graph_with_indirect_loop_fail(self):
        # this test will attempt to create a graph where there is an indirect
        # loop, i.e. a chain is linked to a chain providing a path back to
        # the first chain again - specifically pc2->pc3->pc4->pc2.
        with self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg2, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg3, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg4, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg5:
            with self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg3['port_pair_group']['id']]}
            ) as pc3, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg4['port_pair_group']['id']]}
            ) as pc4, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg5['port_pair_group']['id']]}
            ) as pc5:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']],
                        pc2['port_chain']['id']: [pc3['port_chain']['id']],
                        pc3['port_chain']['id']: [pc4['port_chain']['id']],
                        pc4['port_chain']['id']: [
                            pc2['port_chain']['id'],
                            pc5['port_chain']['id']
                        ]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=400)

    def test_create_service_graph_with_inexistent_port_chains(self):
        # this test will attempt to create a graph where one
        # of the referenced port chains do not exist, and fail.
        with self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg2, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg3:
            with self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg3['port_pair_group']['id']]}
            ) as pc3:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']],
                        pc2['port_chain']['id']: [
                            pc3['port_chain']['id'],
                            uuidutils.generate_uuid()
                        ]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=404)

    def test_create_service_graph_with_joining_branches(self):
        # this test will create a graph that including "joining" branches, i.e.
        # a set of at least 2 branches that will be linked to the same next
        # port chain, thus joining traffic at that point.
        with self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg2, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg3, self.port_pair_group(
                port_pair_group={}, do_delete=False
        ) as pg4:
            with self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg3['port_pair_group']['id']]}
            ) as pc3, self.port_chain(
                do_delete=False,
                port_chain={'port_pair_groups': [pg4['port_pair_group']['id']]}
            ) as pc4:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']],
                        pc2['port_chain']['id']: [
                            pc3['port_chain']['id'], pc4['port_chain']['id']
                        ],
                        pc3['port_chain']['id']: [pc4['port_chain']['id']]
                    },
                    'name': 'abc',
                    'description': 'def'
                }, expected_res_status=201)

    def test_update_service_graph(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                with self.service_graph(service_graph={
                    'name': 'test1',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]
                    }
                }) as graph:
                    updates = {
                        'name': 'test2',
                        'description': 'desc2'
                    }
                    req = self.new_update_request(
                        'service_graphs', {'service_graph': updates},
                        graph['service_graph']['id']
                    )
                    res = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )
                    expected = graph['service_graph']
                    expected.update(updates)
                    for k, v in expected.items():
                        self.assertEqual(res['service_graph'][k], v)
                    req = self.new_show_request(
                        'service_graphs', graph['service_graph']['id']
                    )
                    res = self.deserialize(
                        self.fmt, req.get_response(self.ext_api)
                    )
                    for k, v in expected.items():
                        self.assertEqual(res['service_graph'][k], v)

    def test_delete_service_graph(self):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={
                    'port_pair_groups': [pg1['port_pair_group']['id']]},
            ) as pc1, self.port_chain(
                port_chain={
                    'port_pair_groups': [pg2['port_pair_group']['id']]},
            ) as pc2:
                with self.service_graph(service_graph={
                    'name': 'test1',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]
                    }
                }, do_delete=False) as graph:
                    req = self.new_delete_request(
                        'service_graphs', graph['service_graph']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(204, res.status_int)
                    req = self.new_show_request(
                        'service_graphs', graph['service_graph']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(404, res.status_int)
                    req = self.new_show_request(
                        'port_chains', pc1['port_chain']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(200, res.status_int)
                    req = self.new_show_request(
                        'port_chains', pc2['port_chain']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(200, res.status_int)
