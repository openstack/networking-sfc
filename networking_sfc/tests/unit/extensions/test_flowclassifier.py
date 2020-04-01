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

import copy
from unittest import mock

from neutron.api.v2 import resource as api_res_log
from neutron import manager
from neutron.notifiers import nova as nova_log
from neutron.tests.unit.api.v2 import test_base as test_api_v2
from neutron.tests.unit.extensions import base as test_api_v2_extension
from neutron_lib import constants as const
from oslo_config import cfg
from oslo_utils import uuidutils
from webob import exc
import webtest

from networking_sfc.extensions import flowclassifier as fc_ext

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path

FLOW_CLASSIFIER_PATH = (fc_ext.FLOW_CLASSIFIER_PREFIX[1:] + '/' +
                        fc_ext.FLOW_CLASSIFIER_EXT + 's')


class FlowClassifierExtensionTestCase(
    test_api_v2_extension.ExtensionTestCase
):
    fmt = 'json'

    def setUp(self):
        self._mock_unnecessary_logging()
        super(FlowClassifierExtensionTestCase, self).setUp()
        self.setup_extension(
            'networking_sfc.extensions.flowclassifier.'
            'FlowClassifierPluginBase',
            fc_ext.FLOW_CLASSIFIER_EXT,
            fc_ext.Flowclassifier,
            fc_ext.FLOW_CLASSIFIER_PREFIX[1:],
            plural_mappings={}
        )

    def _mock_unnecessary_logging(self):
        mock_log_cfg_p = mock.patch.object(cfg, 'LOG')
        self.mock_log_cfg = mock_log_cfg_p.start()

        mock_log_manager_p = mock.patch.object(manager, 'LOG')
        self.mock_log_manager = mock_log_manager_p.start()

        mock_log_nova_p = mock.patch.object(nova_log, 'LOG')
        self.mock_log_nova = mock_log_nova_p.start()

        mock_log_api_res_log_p = mock.patch.object(api_res_log, 'LOG')
        self.mock_log_api_res_log = mock_log_api_res_log_p.start()

    def _get_expected_flow_classifier(self, data):
        source_port_range_min = data['flow_classifier'].get(
            'source_port_range_min')
        if source_port_range_min is not None:
            source_port_range_min = int(source_port_range_min)
        source_port_range_max = data['flow_classifier'].get(
            'source_port_range_max')
        if source_port_range_max is not None:
            source_port_range_max = int(source_port_range_max)
        destination_port_range_min = data['flow_classifier'].get(
            'destination_port_range_min')
        if destination_port_range_min is not None:
            destination_port_range_min = int(destination_port_range_min)
        destination_port_range_max = data['flow_classifier'].get(
            'destination_port_range_max')
        if destination_port_range_max is not None:
            destination_port_range_max = int(destination_port_range_max)

        return {'flow_classifier': {
            'name': data['flow_classifier'].get('name') or '',
            'description': data['flow_classifier'].get('description') or '',
            'tenant_id': data['flow_classifier']['tenant_id'],
            'project_id': data['flow_classifier']['project_id'],
            'source_port_range_min': source_port_range_min,
            'source_port_range_max': source_port_range_max,
            'destination_port_range_min': destination_port_range_min,
            'destination_port_range_max': destination_port_range_max,
            'l7_parameters': data['flow_classifier'].get(
                'l7_parameters') or {},
            'destination_ip_prefix': data['flow_classifier'].get(
                'destination_ip_prefix'),
            'source_ip_prefix': data['flow_classifier'].get(
                'source_ip_prefix'),
            'logical_source_port': data['flow_classifier'].get(
                'logical_source_port'),
            'logical_destination_port': data['flow_classifier'].get(
                'logical_destination_port'),
            'ethertype': data['flow_classifier'].get(
                'ethertype') or 'IPv4',
            'protocol': data['flow_classifier'].get(
                'protocol')
        }}

    def test_create_flow_classifier(self):
        flowclassifier_id = _uuid()
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'logical_source_port': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        expected_data = self._get_expected_flow_classifier(data)
        return_value = copy.copy(expected_data['flow_classifier'])
        return_value.update({'id': flowclassifier_id})
        instance = self.plugin.return_value
        instance.create_flow_classifier.return_value = return_value
        res = self.api.post(
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)
        instance.create_flow_classifier.assert_called_with(
            mock.ANY,
            flow_classifier=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('flow_classifier', res)
        self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_source_port_range(self):
        for source_port_range_min in [None, 100, '100']:
            for source_port_range_max in [None, 200, '200']:
                flowclassifier_id = _uuid()
                tenant_id = _uuid()
                data = {'flow_classifier': {
                    'source_port_range_min': source_port_range_min,
                    'source_port_range_max': source_port_range_max,
                    'logical_source_port': _uuid(),
                    'tenant_id': tenant_id, 'project_id': tenant_id,
                }}
                expected_data = self._get_expected_flow_classifier(data)
                return_value = copy.copy(expected_data['flow_classifier'])
                return_value.update({'id': flowclassifier_id})
                instance = self.plugin.return_value
                instance.create_flow_classifier.return_value = return_value
                res = self.api.post(
                    _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                    self.serialize(data),
                    content_type='application/%s' % self.fmt)
                instance.create_flow_classifier.assert_called_with(
                    mock.ANY,
                    flow_classifier=expected_data)
                self.assertEqual(exc.HTTPCreated.code, res.status_int)
                res = self.deserialize(res)
                self.assertIn('flow_classifier', res)
                self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_destination_port_range(self):
        for destination_port_range_min in [None, 100, '100']:
            for destination_port_range_max in [None, 200, '200']:
                flowclassifier_id = _uuid()
                tenant_id = _uuid()
                data = {'flow_classifier': {
                    'destination_port_range_min': destination_port_range_min,
                    'destination_port_range_max': destination_port_range_max,
                    'logical_source_port': _uuid(),
                    'tenant_id': tenant_id, 'project_id': tenant_id,
                }}
                expected_data = self._get_expected_flow_classifier(data)
                return_value = copy.copy(expected_data['flow_classifier'])
                return_value.update({'id': flowclassifier_id})
                instance = self.plugin.return_value
                instance.create_flow_classifier.return_value = return_value
                res = self.api.post(
                    _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                    self.serialize(data),
                    content_type='application/%s' % self.fmt)
                instance.create_flow_classifier.assert_called_with(
                    mock.ANY,
                    flow_classifier=expected_data)
                self.assertEqual(exc.HTTPCreated.code, res.status_int)
                res = self.deserialize(res)
                self.assertIn('flow_classifier', res)
                self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_source_ip_prefix(self):
        for logical_source_ip_prefix in [
            None, '10.0.0.0/8'
        ]:
            flowclassifier_id = _uuid()
            tenant_id = _uuid()
            data = {'flow_classifier': {
                'source_ip_prefix': logical_source_ip_prefix,
                'logical_source_port': _uuid(),
                'tenant_id': tenant_id, 'project_id': tenant_id,
            }}
            expected_data = self._get_expected_flow_classifier(data)
            return_value = copy.copy(expected_data['flow_classifier'])
            return_value.update({'id': flowclassifier_id})
            instance = self.plugin.return_value
            instance.create_flow_classifier.return_value = return_value
            res = self.api.post(
                _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                self.serialize(data),
                content_type='application/%s' % self.fmt)
            instance.create_flow_classifier.assert_called_with(
                mock.ANY,
                flow_classifier=expected_data)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)
            res = self.deserialize(res)
            self.assertIn('flow_classifier', res)
            self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_destination_ip_prefix(self):
        for logical_destination_ip_prefix in [
            None, '10.0.0.0/8'
        ]:
            flowclassifier_id = _uuid()
            tenant_id = _uuid()
            data = {'flow_classifier': {
                'destination_ip_prefix': logical_destination_ip_prefix,
                'logical_source_port': _uuid(),
                'tenant_id': tenant_id, 'project_id': tenant_id,
            }}
            expected_data = self._get_expected_flow_classifier(data)
            return_value = copy.copy(expected_data['flow_classifier'])
            return_value.update({'id': flowclassifier_id})
            instance = self.plugin.return_value
            instance.create_flow_classifier.return_value = return_value
            res = self.api.post(
                _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                self.serialize(data),
                content_type='application/%s' % self.fmt)
            instance.create_flow_classifier.assert_called_with(
                mock.ANY,
                flow_classifier=expected_data)
            self.assertEqual(res.status_int, exc.HTTPCreated.code)
            res = self.deserialize(res)
            self.assertIn('flow_classifier', res)
            self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_logical_source_port(self):
        for logical_source_port in [
            None, _uuid()
        ]:
            flowclassifier_id = _uuid()
            tenant_id = _uuid()
            data = {'flow_classifier': {
                'logical_source_port': logical_source_port,
                'tenant_id': tenant_id, 'project_id': tenant_id,
            }}
            expected_data = self._get_expected_flow_classifier(data)
            return_value = copy.copy(expected_data['flow_classifier'])
            return_value.update({'id': flowclassifier_id})
            instance = self.plugin.return_value
            instance.create_flow_classifier.return_value = return_value
            res = self.api.post(
                _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                self.serialize(data),
                content_type='application/%s' % self.fmt)
            instance.create_flow_classifier.assert_called_with(
                mock.ANY,
                flow_classifier=expected_data)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)
            res = self.deserialize(res)
            self.assertIn('flow_classifier', res)
            self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_logical_destination_port(self):
        for logical_destination_port in [
            None, _uuid()
        ]:
            flowclassifier_id = _uuid()
            tenant_id = _uuid()
            data = {'flow_classifier': {
                'logical_destination_port': logical_destination_port,
                'tenant_id': tenant_id, 'project_id': tenant_id,
            }}
            expected_data = self._get_expected_flow_classifier(data)
            return_value = copy.copy(expected_data['flow_classifier'])
            return_value.update({'id': flowclassifier_id})
            instance = self.plugin.return_value
            instance.create_flow_classifier.return_value = return_value
            res = self.api.post(
                _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                self.serialize(data),
                content_type='application/%s' % self.fmt)
            instance.create_flow_classifier.assert_called_with(
                mock.ANY,
                flow_classifier=expected_data)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)
            res = self.deserialize(res)
            self.assertIn('flow_classifier', res)
            self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_l7_parameters(self):
        for l7_parameters in [None, {}]:
            flowclassifier_id = _uuid()
            tenant_id = _uuid()
            data = {'flow_classifier': {
                'logical_source_port': _uuid(),
                'tenant_id': tenant_id, 'project_id': tenant_id,
                'l7_parameters': l7_parameters
            }}
            expected_data = self._get_expected_flow_classifier(data)
            return_value = copy.copy(expected_data['flow_classifier'])
            return_value.update({'id': flowclassifier_id})
            instance = self.plugin.return_value
            instance.create_flow_classifier.return_value = return_value
            res = self.api.post(
                _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                self.serialize(data),
                content_type='application/%s' % self.fmt)
            instance.create_flow_classifier.assert_called_with(
                mock.ANY,
                flow_classifier=expected_data)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)
            res = self.deserialize(res)
            self.assertIn('flow_classifier', res)
            self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_ethertype(self):
        for ethertype in [None, 'IPv4', 'IPv6']:
            flowclassifier_id = _uuid()
            tenant_id = _uuid()
            data = {'flow_classifier': {
                'logical_source_port': _uuid(),
                'tenant_id': tenant_id, 'project_id': tenant_id,
                'ethertype': ethertype
            }}
            expected_data = self._get_expected_flow_classifier(data)
            return_value = copy.copy(expected_data['flow_classifier'])
            return_value.update({'id': flowclassifier_id})
            instance = self.plugin.return_value
            instance.create_flow_classifier.return_value = return_value
            res = self.api.post(
                _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                self.serialize(data),
                content_type='application/%s' % self.fmt)
            instance.create_flow_classifier.assert_called_with(
                mock.ANY,
                flow_classifier=expected_data)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)
            res = self.deserialize(res)
            self.assertIn('flow_classifier', res)
            self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_protocol(self):
        for protocol in [
            None, const.PROTO_NAME_TCP, const.PROTO_NAME_UDP,
            const.PROTO_NAME_ICMP
        ]:
            flowclassifier_id = _uuid()
            tenant_id = _uuid()
            data = {'flow_classifier': {
                'logical_source_port': _uuid(),
                'tenant_id': tenant_id, 'project_id': tenant_id,
                'protocol': protocol
            }}
            expected_data = self._get_expected_flow_classifier(data)
            return_value = copy.copy(expected_data['flow_classifier'])
            return_value.update({'id': flowclassifier_id})
            instance = self.plugin.return_value
            instance.create_flow_classifier.return_value = return_value
            res = self.api.post(
                _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
                self.serialize(data),
                content_type='application/%s' % self.fmt)
            instance.create_flow_classifier.assert_called_with(
                mock.ANY,
                flow_classifier=expected_data)
            self.assertEqual(exc.HTTPCreated.code, res.status_int)
            res = self.deserialize(res)
            self.assertIn('flow_classifier', res)
            self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_all_fields(self):
        flowclassifier_id = _uuid()
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'name': 'test1',
            'description': 'desc',
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'source_port_range_min': 100,
            'source_port_range_max': 200,
            'destination_port_range_min': 100,
            'destination_port_range_max': 200,
            'l7_parameters': {},
            'destination_ip_prefix': '10.0.0.0/8',
            'source_ip_prefix': '10.0.0.0/8',
            'logical_source_port': _uuid(),
            'logical_destination_port': _uuid(),
            'ethertype': None,
            'protocol': None
        }}
        expected_data = self._get_expected_flow_classifier(data)
        return_value = copy.copy(expected_data['flow_classifier'])
        return_value.update({'id': flowclassifier_id})
        instance = self.plugin.return_value
        instance.create_flow_classifier.return_value = return_value
        res = self.api.post(
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)
        instance.create_flow_classifier.assert_called_with(
            mock.ANY,
            flow_classifier=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('flow_classifier', res)
        self.assertEqual(return_value, res['flow_classifier'])

    def test_create_flow_classifier_invalid_l7_parameters(self):
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'logical_source_port': _uuid(),
            'l7_parameters': {'abc': 'def'},
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_flow_classifier_invalid_protocol(self):
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'logical_source_port': _uuid(),
            'protocol': 'unknown',
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_flow_classifier_invalid_ethertype(self):
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'logical_source_port': _uuid(),
            'ethertype': 'unknown',
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_flow_classifier_port_small(self):
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'logical_source_port': _uuid(),
            'source_port_range_min': -1,
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_flow_classifier_port_large(self):
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'logical_source_port': _uuid(),
            'source_port_range_min': 65536,
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_flow_classifier_ip_prefix_no_cidr(self):
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'source_ip_prefix': '10.0.0.0',
            'logical_source_port': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_flow_classifier_ip_prefix_invalid_cidr(self):
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'source_ip_prefix': '10.0.0.0/33',
            'logical_source_port': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_flow_classifier_port_id_nouuid(self):
        tenant_id = _uuid()
        data = {'flow_classifier': {
            'logical_source_port': 'unknown',
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_list(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        return_value = [{
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': flowclassifier_id
        }]
        instance = self.plugin.return_value
        instance.get_flow_classifiers.return_value = return_value

        res = self.api.get(
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt))

        instance.get_flow_classifiers.assert_called_with(
            mock.ANY,
            fields=mock.ANY,
            filters=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('flow_classifiers', res)
        self.assertEqual(return_value, res['flow_classifiers'])

    def test_flow_classifier_list_all_fields(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        return_value = [{
            'name': 'abc',
            'description': 'abc',
            'ethertype': 'IPv4',
            'protocol': const.PROTO_NAME_TCP,
            'source_ip_prefix': '10.0.0.0/8',
            'destination_ip_prefix': '10.0.0.0/8',
            'source_port_range_min': 100,
            'source_port_range_max': 200,
            'destination_port_range_min': 100,
            'destination_port_range_max': 200,
            'logical_source_port': _uuid(),
            'logical_destination_port': _uuid(),
            'l7_parameters': {},
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': flowclassifier_id
        }]
        instance = self.plugin.return_value
        instance.get_flow_classifiers.return_value = return_value
        res = self.api.get(
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt))
        instance.get_flow_classifiers.assert_called_with(
            mock.ANY,
            fields=mock.ANY,
            filters=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('flow_classifiers', res)
        self.assertEqual(return_value, res['flow_classifiers'])

    def test_flow_classifier_list_unknown_fields(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        return_value = [{
            'logical_source_port': _uuid(),
            'new_key': 'value',
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': flowclassifier_id
        }]
        expected_return = copy.copy(return_value)
        for item in expected_return:
            del item['new_key']
        instance = self.plugin.return_value
        instance.get_flow_classifiers.return_value = return_value
        res = self.api.get(
            _get_path(FLOW_CLASSIFIER_PATH, fmt=self.fmt))
        instance.get_flow_classifiers.assert_called_with(
            mock.ANY,
            fields=mock.ANY,
            filters=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('flow_classifiers', res)
        self.assertEqual(expected_return, res['flow_classifiers'])

    def test_flow_classifier_get(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        return_value = {
            'logical_source_port': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': flowclassifier_id
        }
        instance = self.plugin.return_value
        instance.get_flow_classifier.return_value = return_value
        res = self.api.get(
            _get_path(
                FLOW_CLASSIFIER_PATH,
                id=flowclassifier_id, fmt=self.fmt
            )
        )
        instance.get_flow_classifier.assert_called_with(
            mock.ANY,
            flowclassifier_id,
            fields=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('flow_classifier', res)
        self.assertEqual(return_value, res['flow_classifier'])

    def test_flow_classifier_update(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        update_data = {'flow_classifier': {
            'name': 'new_name',
            'description': 'new_desc',
        }}
        return_value = {
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': flowclassifier_id
        }

        instance = self.plugin.return_value
        instance.update_flow_classifier.return_value = return_value

        res = self.api.put(
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(update_data))

        instance.update_flow_classifier.assert_called_with(
            mock.ANY, flowclassifier_id,
            flow_classifier=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('flow_classifier', res)
        self.assertEqual(return_value, res['flow_classifier'])

    def test_flow_classifier_update_source_port_range_min(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'source_port_range_min': 100,
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_source_port_range_max(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'source_port_range_max': 100,
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_destination_port_range_min(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'destination_port_range_min': 100,
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_destination_port_range_max(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'destination_port_range_max': 100,
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_source_ip_prefix(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'source_ip_prefix': '10.0.0.0/8',
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_destination_ip_prefix(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'destination_ip_prefix': '10.0.0.0/8',
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_logical_source_port(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'logical_source_port': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_logical_destination_port(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'logical_destination_port': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_ethertype(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'ethertype': None,
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_protocol(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'protococol': None,
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_update_l7_parameters(self):
        tenant_id = _uuid()
        flowclassifier_id = _uuid()
        data = {'flow_classifier': {
            'l7_parameters': {},
            'tenant_id': tenant_id, 'project_id': tenant_id,
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(FLOW_CLASSIFIER_PATH, id=flowclassifier_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_flow_classifier_delete(self):
        self._test_entity_delete('flow_classifier')
