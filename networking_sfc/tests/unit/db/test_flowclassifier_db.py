# Copyright 2015 Futurewei. All rights reserved.
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
import mock
import six
import webob.exc

from oslo_config import cfg
from oslo_utils import importutils
from oslo_utils import uuidutils

from neutron.api import extensions as api_ext
from neutron.common import config
from neutron.common import constants as const
import neutron.extensions as nextensions

from networking_sfc.db import flowclassifier_db as fdb
from networking_sfc import extensions
from networking_sfc.extensions import flowclassifier as fc_ext
from networking_sfc.tests import base


DB_FLOWCLASSIFIER_PLUGIN_CLASS = (
    "networking_sfc.db.flowclassifier_db.FlowClassifierDbPlugin"
)
extensions_path = ':'.join(extensions.__path__ + nextensions.__path__)


class FlowClassifierDbPluginTestCaseBase(base.BaseTestCase):
    def _create_flow_classifier(
        self, fmt, flow_classifier=None, expected_res_status=None, **kwargs
    ):
        ctx = kwargs.get('context', None)
        tenant_id = kwargs.get('tenant_id', self._tenant_id)
        data = {'flow_classifier': flow_classifier or {}}
        if ctx is None:
            data['flow_classifier'].update({'tenant_id': tenant_id})
        req = self.new_create_request(
            'flow_classifiers', data, fmt, context=ctx
        )
        res = req.get_response(self.ext_api)
        if expected_res_status:
            self.assertEqual(res.status_int, expected_res_status)
        return res

    @contextlib.contextmanager
    def flow_classifier(
        self, fmt=None, flow_classifier=None, do_delete=True, **kwargs
    ):
        if not fmt:
            fmt = self.fmt
        res = self._create_flow_classifier(fmt, flow_classifier, **kwargs)
        if res.status_int >= 400:
            raise webob.exc.HTTPClientError(code=res.status_int)
        flow_classifier = self.deserialize(fmt or self.fmt, res)
        yield flow_classifier
        if do_delete:
            self._delete('flow_classifiers',
                         flow_classifier['flow_classifier']['id'])

    def _get_expected_flow_classifier(self, flow_classifier):
        expected_flow_classifier = {
            'name': flow_classifier.get('name') or '',
            'description': flow_classifier.get('description') or '',
            'source_port_range_min': flow_classifier.get(
                'source_port_range_min'),
            'source_port_range_max': flow_classifier.get(
                'source_port_range_max'),
            'destination_port_range_min': flow_classifier.get(
                'destination_port_range_min'),
            'destination_port_range_max': flow_classifier.get(
                'destination_port_range_max'),
            'ethertype': flow_classifier.get(
                'ethertype') or 'IPv4',
            'protocol': flow_classifier.get(
                'protocol'),
            'l7_parameters': flow_classifier.get(
                'l7_parameters') or {}
        }
        if (
            'source_ip_prefix' in flow_classifier and
            flow_classifier['source_ip_prefix']
        ):
            expected_flow_classifier['source_ip_prefix'] = (
                flow_classifier['source_ip_prefix'])
        if (
            'destination_ip_prefix' in flow_classifier and
            flow_classifier['destination_ip_prefix']
        ):
            expected_flow_classifier['destination_ip_prefix'] = (
                flow_classifier['destination_ip_prefix'])
        return expected_flow_classifier

    def _test_create_flow_classifier(
        self, flow_classifier, expected_flow_classifier=None
    ):
        if expected_flow_classifier is None:
            expected_flow_classifier = self._get_expected_flow_classifier(
                flow_classifier)
        with self.flow_classifier(flow_classifier=flow_classifier) as fc:
            for k, v in six.iteritems(expected_flow_classifier):
                self.assertIn(k, fc['flow_classifier'])
                self.assertEqual(fc['flow_classifier'][k], v)


class FlowClassifierDbPluginTestCase(
    base.NeutronDbPluginV2TestCase,
    FlowClassifierDbPluginTestCaseBase
):
    resource_prefix_map = dict(
        (k, fc_ext.FLOW_CLASSIFIER_PREFIX)
        for k in fc_ext.RESOURCE_ATTRIBUTE_MAP.keys()
    )

    def setUp(self, core_plugin=None, flowclassifier_plugin=None,
              ext_mgr=None):
        mock_log_p = mock.patch.object(fdb, 'LOG')
        self.mock_log = mock_log_p.start()
        cfg.CONF.register_opts(fc_ext.flow_classifier_quota_opts, 'QUOTAS')
        if not flowclassifier_plugin:
            flowclassifier_plugin = DB_FLOWCLASSIFIER_PLUGIN_CLASS
        service_plugins = {
            fc_ext.FLOW_CLASSIFIER_EXT: flowclassifier_plugin
        }
        fdb.FlowClassifierDbPlugin.supported_extension_aliases = [
            fc_ext.FLOW_CLASSIFIER_EXT]
        fdb.FlowClassifierDbPlugin.path_prefix = (
            fc_ext.FLOW_CLASSIFIER_PREFIX
        )
        super(FlowClassifierDbPluginTestCase, self).setUp(
            ext_mgr=ext_mgr,
            plugin=core_plugin,
            service_plugins=service_plugins
        )
        if not ext_mgr:
            self.flowclassifier_plugin = importutils.import_object(
                flowclassifier_plugin)
            ext_mgr = api_ext.PluginAwareExtensionManager(
                extensions_path,
                {fc_ext.FLOW_CLASSIFIER_EXT: self.flowclassifier_plugin}
            )
            app = config.load_paste_app('extensions_test_app')
            self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)

    def test_create_flow_classifier(self):
        self._test_create_flow_classifier({})

    def test_quota_create_flow_classifier(self):
        cfg.CONF.set_override('quota_flow_classifier', 3, group='QUOTAS')
        self._create_flow_classifier(self.fmt, {}, expected_res_status=201)
        self._create_flow_classifier(self.fmt, {}, expected_res_status=201)
        self._create_flow_classifier(self.fmt, {}, expected_res_status=201)
        self._create_flow_classifier(self.fmt, {}, expected_res_status=409)

    def test_create_flow_classifier_with_all_fields(self):
        self._test_create_flow_classifier({
            'name': 'test1',
            'ethertype': const.IPv4,
            'protocol': const.PROTO_NAME_TCP,
            'source_port_range_min': 100,
            'source_port_range_max': 200,
            'destination_port_range_min': 101,
            'destination_port_range_max': 201,
            'source_ip_prefix': '10.100.0.0/16',
            'destination_ip_prefix': '10.200.0.0/16',
            'logical_source_port': None,
            'logical_destination_port': None,
            'l7_parameters': {}
        })

    def test_create_flow_classifier_with_all_supported_ethertype(self):
        self._test_create_flow_classifier({
            'ethertype': None
        })
        self._test_create_flow_classifier({
            'ethertype': 'IPv4'
        })
        self._test_create_flow_classifier({
            'ethertype': 'IPv6'
        })

    def test_create_flow_classifier_with_invalid_ethertype(self):
        self._create_flow_classifier(
            self.fmt, {
                'ethertype': 'unsupported',
            },
            expected_res_status=400
        )

    def test_create_flow_classifier_with_all_supported_protocol(self):
        self._test_create_flow_classifier({
            'protocol': None
        })
        self._test_create_flow_classifier({
            'protocol': const.PROTO_NAME_TCP
        })
        self._test_create_flow_classifier({
            'protocol': const.PROTO_NAME_UDP
        })
        self._test_create_flow_classifier({
            'protocol': const.PROTO_NAME_ICMP
        })

    def test_create_flow_classifier_with_invalid_protocol(self):
        self._create_flow_classifier(
            self.fmt, {
                'protocol': 'unsupported',
            },
            expected_res_status=400
        )

    def test_create_flow_classifier_with_all_supported_port_protocol(self):
        self._test_create_flow_classifier({
            'source_port_range_min': None,
            'source_port_range_max': None,
            'destination_port_range_min': None,
            'destination_port_range_max': None
        })
        self._test_create_flow_classifier({
            'source_port_range_min': 100,
            'source_port_range_max': 200,
            'destination_port_range_min': 100,
            'destination_port_range_max': 200,
            'protocol': const.PROTO_NAME_TCP
        })
        self._test_create_flow_classifier({
            'source_port_range_min': 100,
            'source_port_range_max': 100,
            'destination_port_range_min': 100,
            'destination_port_range_max': 100,
            'protocol': const.PROTO_NAME_TCP
        })
        self._test_create_flow_classifier({
            'source_port_range_min': '100',
            'source_port_range_max': '200',
            'destination_port_range_min': '100',
            'destination_port_range_max': '200',
            'protocol': const.PROTO_NAME_UDP
        }, {
            'source_port_range_min': 100,
            'source_port_range_max': 200,
            'destination_port_range_min': 100,
            'destination_port_range_max': 200,
            'protocol': const.PROTO_NAME_UDP
        })

    def test_create_flow_classifier_with_invalid__port_protocol(self):
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_min': 'abc',
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_max': 'abc',
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_min': 100,
                'source_port_range_max': 99,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_min': 65536,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_max': 65536,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_min': -1,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_max': -1,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_min': 'abc',
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_max': 'abc',
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_min': 100,
                'destination_port_range_max': 99,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_min': 65536,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_max': 65536,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_min': -1,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_max': -1,
                'protocol': const.PROTO_NAME_TCP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_min': 100
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_max': 100
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_min': 100,
                'source_port_range_max': 200
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_port_range_min': 100,
                'source_port_range_max': 200,
                'protocol': const.PROTO_NAME_ICMP
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_min': 100
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_max': 100
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_min': 100,
                'destination_port_range_max': 200
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_port_range_min': 100,
                'destination_port_range_max': 200,
                'protocol': const.PROTO_NAME_ICMP
            },
            expected_res_status=400
        )

    def test_create_flow_classifier_with_all_supported_ip_prefix(self):
        self._test_create_flow_classifier({
            'source_ip_prefix': None,
            'destination_ip_prefix': None
        })
        self._test_create_flow_classifier({
            'source_ip_prefix': '10.0.0.0/8',
            'destination_ip_prefix': '10.0.0.0/8'
        })

    def test_create_flow_classifier_with_invalid_ip_prefix(self):
        self._create_flow_classifier(
            self.fmt, {
                'source_ip_prefix': '10.0.0.0/34'
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_ip_prefix': '10.0.0.0.0/8'
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_ip_prefix': '256.0.0.0/8'
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'source_ip_prefix': '10.0.0.0'
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_ip_prefix': '10.0.0.0/34'
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_ip_prefix': '10.0.0.0.0/8'
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_ip_prefix': '256.0.0.0/8'
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'destination_ip_prefix': '10.0.0.0'
            },
            expected_res_status=400
        )

    def test_create_flow_classifier_with_all_supported_l7_parameters(self):
        self._test_create_flow_classifier({
            'l7_parameters': None
        })
        self._test_create_flow_classifier({
            'l7_parameters': {}
        })

    def test_create_flow_classifier_with_invalid_l7_parameters(self):
        self._create_flow_classifier(
            self.fmt, {
                'l7_parameters': {'abc': 'def'}
            },
            expected_res_status=400
        )

    def test_create_flow_classifier_with_port_id(self):
        self._test_create_flow_classifier({
            'logical_source_port': None,
            'logical_destination_port': None,
        })
        with self.port(
            name='test1'
        ) as port:
            self._test_create_flow_classifier({
                'logical_source_port': port['port']['id'],
                'logical_destination_port': port['port']['id'],
            })

    def test_create_flow_classifier_with_nouuid_port_id(self):
        self._create_flow_classifier(
            self.fmt, {
                'logical_source_port': 'abc'
            },
            expected_res_status=400
        )
        self._create_flow_classifier(
            self.fmt, {
                'logical_destination_port': 'abc'
            },
            expected_res_status=400
        )

    def test_create_flow_classifier_with_unknown_port_id(self):
        self._create_flow_classifier(
            self.fmt, {
                'logical_source_port': uuidutils.generate_uuid()
            },
            expected_res_status=404
        )
        self._create_flow_classifier(
            self.fmt, {
                'logical_destination_port': uuidutils.generate_uuid()
            },
            expected_res_status=404
        )

    def test_list_flow_classifiers(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1'
        }) as fc1, self.flow_classifier(flow_classifier={
            'name': 'test2',
        }) as fc2:
            fcs = [fc1, fc2]
            self._test_list_resources(
                'flow_classifier', fcs
            )

    def test_list_flow_classifiers_with_params(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1'
        }) as fc1, self.flow_classifier(flow_classifier={
            'name': 'test2',
        }) as fc2:
            self._test_list_resources(
                'flow_classifier', [fc1],
                query_params='name=test1'
            )
            self._test_list_resources(
                'flow_classifier', [fc2],
                query_params='name=test2'
            )
            self._test_list_resources(
                'flow_classifier', [],
                query_params='name=test3'
            )

    def test_list_flow_classifiers_with_unknown_params(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1'
        }) as fc1, self.flow_classifier(flow_classifier={
            'name': 'test2',
        }) as fc2:
            self._test_list_resources(
                'flow_classifier', [fc1, fc2],
                query_params='hello=test3'
            )

    def test_show_flow_classifier(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1'
        }) as fc:
            req = self.new_show_request(
                'flow_classifiers', fc['flow_classifier']['id']
            )
            res = self.deserialize(
                self.fmt, req.get_response(self.ext_api)
            )
            for k, v in six.iteritems(fc['flow_classifier']):
                self.assertEqual(res['flow_classifier'][k], v)

    def test_show_flow_classifier_noexist(self):
        req = self.new_show_request(
            'flow_classifiers', '1'
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 404)

    def test_update_flow_classifier(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1',
            'description': 'desc1'
        }) as fc:
            updates = {
                'name': 'test2',
                'description': 'desc2',
            }
            req = self.new_update_request(
                'flow_classifiers', {'flow_classifier': updates},
                fc['flow_classifier']['id']
            )
            res = self.deserialize(
                self.fmt,
                req.get_response(self.ext_api)
            )
            expected = fc['flow_classifier']
            expected.update(updates)
            for k, v in six.iteritems(expected):
                self.assertEqual(res['flow_classifier'][k], v)
            req = self.new_show_request(
                'flow_classifiers', fc['flow_classifier']['id']
            )
            res = self.deserialize(
                self.fmt, req.get_response(self.ext_api)
            )
            for k, v in six.iteritems(expected):
                self.assertEqual(res['flow_classifier'][k], v)

    def _test_update_with_field(
        self, fc, updates, expected_status_code
    ):
        req = self.new_update_request(
            'flow_classifiers', {'flow_classifier': updates},
            fc['flow_classifier']['id']
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, expected_status_code)

    def test_update_flow_classifer_unsupported_fields(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1',
            'description': 'desc1'
        }) as fc:
            self._test_update_with_field(
                fc, {'ethertype': None}, 400)
            self._test_update_with_field(
                fc, {'protocol': None}, 400)
            self._test_update_with_field(
                fc, {'source_port_range_min': None}, 400)
            self._test_update_with_field(
                fc, {'source_port_range_max': None}, 400)
            self._test_update_with_field(
                fc, {'destination_port_range_min': None}, 400)
            self._test_update_with_field(
                fc, {'destination_port_range_max': None}, 400)
            self._test_update_with_field(
                fc, {'source_ip_prefix': None}, 400)
            self._test_update_with_field(
                fc, {'destination_ip_prefix': None}, 400)
            self._test_update_with_field(
                fc, {'l7_parameters': None}, 400)

    def test_delete_flow_classifier(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1'
        }, do_delete=False) as fc:
            req = self.new_delete_request(
                'flow_classifiers', fc['flow_classifier']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 204)
            req = self.new_show_request(
                'flow_classifiers', fc['flow_classifier']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(res.status_int, 404)

    def test_delete_flow_classifier_noexist(self):
        req = self.new_delete_request(
            'flow_classifiers', '1'
        )
        res = req.get_response(self.ext_api)
        self.assertEqual(res.status_int, 404)
