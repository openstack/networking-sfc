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

import copy
from unittest import mock

from neutron.api.v2 import resource as api_res_log
from neutron import manager
from neutron.notifiers import nova as nova_log
from neutron.tests.unit.api.v2 import test_base as test_api_v2
from neutron.tests.unit.extensions import base as test_api_v2_extension
from oslo_config import cfg
from oslo_utils import uuidutils
from webob import exc
import webtest

from networking_sfc.extensions import sfc as sfc_ext

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path

PORT_CHAIN_PATH = (sfc_ext.SFC_PREFIX[1:] + '/port_chains')
PORT_PAIR_PATH = (sfc_ext.SFC_PREFIX[1:] + '/port_pairs')
PORT_PAIR_GROUP_PATH = (sfc_ext.SFC_PREFIX[1:] + '/port_pair_groups')


class SfcExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        self._mock_unnecessary_logging()
        super(SfcExtensionTestCase, self).setUp()
        self.setup_extension(
            'networking_sfc.extensions.sfc.SfcPluginBase',
            sfc_ext.SFC_EXT,
            sfc_ext.Sfc,
            sfc_ext.SFC_PREFIX[1:],
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

    @staticmethod
    def _get_expected_port_chain(data):
        port_chain = data['port_chain']
        chain_params = port_chain.get('chain_parameters') or dict()
        chain_params.setdefault('correlation', 'mpls')
        chain_params.setdefault('symmetric', False)
        ret = {'port_chain': {
            'description': port_chain.get('description') or '',
            'name': port_chain.get('name') or '',
            'port_pair_groups': port_chain['port_pair_groups'],
            'chain_parameters': chain_params,
            'flow_classifiers': port_chain.get(
                'flow_classifiers') or [],
            'tenant_id': port_chain['tenant_id'],
            'project_id': port_chain['project_id'],
            'chain_id': port_chain.get('chain_id') or 0
        }}
        return ret

    def _test_create_port_chain(self, **kwargs):
        tenant_id = _uuid()
        port_chain_data = {
            'port_pair_groups': [_uuid()],
            'tenant_id': tenant_id,
            'project_id': tenant_id
        }
        port_chain_data.update(kwargs)
        data = {'port_chain': port_chain_data}
        expected_data = self._get_expected_port_chain(data)
        return_value = copy.copy(expected_data['port_chain'])
        return_value.update({'id': _uuid()})
        instance = self.plugin.return_value
        instance.create_port_chain.return_value = return_value
        res = self.api.post(_get_path(PORT_CHAIN_PATH, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_port_chain.assert_called_with(
            mock.ANY,
            port_chain=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_chain', res)
        self.assertEqual(return_value, res['port_chain'])

    def test_create_port_chain(self):
        self._test_create_port_chain()

    def test_create_port_chain_all_fields(self):
        self._test_create_port_chain(description='desc',
                                     name='test1',
                                     chain_parameters={'symmetric': False,
                                                       'correlation': 'mpls'},
                                     flow_classifiers=[])

    def test_create_port_chain_all_fields_with_symmetric(self):
        self._test_create_port_chain(description='desc',
                                     name='test1',
                                     chain_parameters={'symmetric': True,
                                                       'correlation': 'mpls'},
                                     flow_classifiers=[])

    def test_create_port_chain_none_chain_parameters(self):
        self._test_create_port_chain(chain_parameters=None)

    def test_create_port_chain_empty_chain_parameters(self):
        self._test_create_port_chain(chain_parameters={})

    def test_create_port_chain_multiple_chain_parameters(self):
        self._test_create_port_chain(chain_parameters={
            'correlation': 'mpls',
            'symmetric': True
        })

    def test_create_port_chain_empty_port_pair_groups(self):
        tenant_id = _uuid()
        data = {'port_chain': {
            'port_pair_groups': [],
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_CHAIN_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_chain_nonuuid_port_pair_groups(self):
        tenant_id = _uuid()
        data = {'port_chain': {
            'port_pair_groups': ['nouuid'],
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_CHAIN_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_chain_nonuuid_flow_classifiers(self):
        tenant_id = _uuid()
        data = {'port_chain': {
            'port_pair_groups': [_uuid()],
            'flow_classifiers': ['nouuid'],
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_CHAIN_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_chain_invalid_chain_parameters(self):
        tenant_id = _uuid()
        data = {'port_chain': {
            'port_pair_groups': [_uuid()],
            'chain_parameters': {'abc': 'def'},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_CHAIN_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_chain_invalid_chain_parameters_correlation(self):
        tenant_id = _uuid()
        data = {'port_chain': {
            'port_pair_groups': [_uuid()],
            'chain_parameters': {'symmetric': False, 'correlation': 'def'},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_CHAIN_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_chain_invalid_chain_parameters_symmetric(self):
        tenant_id = _uuid()
        data = {'port_chain': {
            'port_pair_groups': [_uuid()],
            'chain_parameters': {'symmetric': 'abc', 'correlation': 'mpls'},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_CHAIN_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_port_chain_list(self):
        portchain_id = _uuid()
        tenant_id = _uuid()
        return_value = [{
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portchain_id
        }]
        instance = self.plugin.return_value
        instance.get_port_chains.return_value = return_value

        res = self.api.get(_get_path(PORT_CHAIN_PATH, fmt=self.fmt))

        instance.get_port_chains.assert_called_with(
            mock.ANY,
            fields=mock.ANY,
            filters=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_chains', res)
        self.assertEqual(return_value, res['port_chains'])

    def test_port_chain_get(self):
        portchain_id = _uuid()
        tenant_id = _uuid()
        return_value = {
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portchain_id
        }

        instance = self.plugin.return_value
        instance.get_port_chain.return_value = return_value

        res = self.api.get(_get_path(PORT_CHAIN_PATH,
                                     id=portchain_id, fmt=self.fmt))

        instance.get_port_chain.assert_called_with(
            mock.ANY,
            portchain_id,
            fields=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_chain', res)
        self.assertEqual(return_value, res['port_chain'])

    def test_port_chain_update(self):
        portchain_id = _uuid()
        tenant_id = _uuid()
        update_data = {'port_chain': {
            'name': 'new_name',
            'description': 'new_desc',
            'flow_classifiers': [_uuid()],
            'port_pair_groups': [_uuid()]
        }}
        return_value = {
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portchain_id
        }

        instance = self.plugin.return_value
        instance.update_port_chain.return_value = return_value

        res = self.api.put(_get_path(PORT_CHAIN_PATH, id=portchain_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_port_chain.assert_called_with(
            mock.ANY, portchain_id,
            port_chain=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_chain', res)
        self.assertEqual(return_value, res['port_chain'])

    def test_port_chain_update_nonuuid_flow_classifiers(self):
        portchain_id = _uuid()
        data = {'port_chain': {
            'flow_classifiers': ['nouuid'],
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(PORT_CHAIN_PATH, id=portchain_id, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_port_chain_update_nonuuid_port_pair_groups(self):
        portchain_id = _uuid()
        update_data = {'port_chain': {
            'port_pair_groups': ['nouuid']
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(PORT_CHAIN_PATH, id=portchain_id,
                      fmt=self.fmt),
            self.serialize(update_data),
            content_type='application/%s' % self.fmt
        )

    def test_port_chain_update_chain_parameters(self):
        portchain_id = _uuid()
        update_data = {'port_chain': {
            'chain_parameters': {}
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(PORT_CHAIN_PATH, id=portchain_id,
                      fmt=self.fmt),
            self.serialize(update_data)
        )

    def test_port_chain_delete(self):
        self._test_entity_delete('port_chain')

    def _get_expected_port_pair_group(self, data):
        port_pair_group = data['port_pair_group']
        ret = {'port_pair_group': {
            'description': port_pair_group.get('description') or '',
            'name': port_pair_group.get('name') or '',
            'port_pairs': port_pair_group.get('port_pairs') or [],
            'tenant_id': port_pair_group['tenant_id'],
            'project_id': port_pair_group['project_id'],
            'port_pair_group_parameters': port_pair_group.get(
                'port_pair_group_parameters'
            ) or {'lb_fields': [],
                  'ppg_n_tuple_mapping': {'ingress_n_tuple': {},
                                          'egress_n_tuple': {}}
                  }
        }}
        if port_pair_group.get('group_id'):
            ret['port_pair_group']['group_id'] = port_pair_group['group_id']
        return ret

    def test_create_port_pair_group(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair_group(data)
        return_value = copy.copy(expected_data['port_pair_group'])
        return_value.update({'id': portpairgroup_id})
        instance = self.plugin.return_value
        instance.create_port_pair_group.return_value = return_value
        res = self.api.post(
            _get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)
        instance.create_port_pair_group.assert_called_with(
            mock.ANY,
            port_pair_group=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair_group', res)
        self.assertEqual(return_value, res['port_pair_group'])

    def test_create_port_pair_group_all_fields(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'description': 'desc',
            'name': 'test1',
            'port_pairs': [],
            'port_pair_group_parameters': {},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair_group(data)
        return_value = copy.copy(expected_data['port_pair_group'])
        return_value.update({'id': portpairgroup_id})
        instance = self.plugin.return_value
        instance.create_port_pair_group.return_value = return_value
        res = self.api.post(
            _get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)
        instance.create_port_pair_group.assert_called_with(
            mock.ANY,
            port_pair_group=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair_group', res)
        self.assertEqual(return_value, res['port_pair_group'])

    def test_create_port_pair_group_none_parameters(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': [_uuid()],
            'port_pair_group_parameters': None,
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair_group(data)
        return_value = copy.copy(expected_data['port_pair_group'])
        return_value.update({'id': portpairgroup_id})
        instance = self.plugin.return_value
        instance.create_port_pair_group.return_value = return_value
        res = self.api.post(_get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_port_pair_group.assert_called_with(
            mock.ANY,
            port_pair_group=expected_data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('port_pair_group', res)
        self.assertEqual(return_value, res['port_pair_group'])

    def test_create_port_pair_group_empty_parameters(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': [_uuid()],
            'port_pair_group_parameters': {},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair_group(data)
        return_value = copy.copy(expected_data['port_pair_group'])
        return_value.update({'id': portpairgroup_id})
        instance = self.plugin.return_value
        instance.create_port_pair_group.return_value = return_value
        res = self.api.post(_get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_port_pair_group.assert_called_with(
            mock.ANY,
            port_pair_group=expected_data)
        self.assertEqual(res.status_int, exc.HTTPCreated.code)
        res = self.deserialize(res)
        self.assertIn('port_pair_group', res)
        self.assertEqual(return_value, res['port_pair_group'])

    def test_create_port_pair_group_invalid_parameters(self):
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': [_uuid()],
            'port_pair_group_parameters': {'abc': 'def'},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_group_invalid_lb_fields_type(self):
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': [_uuid()],
            'port_pair_group_parameters': {'lb_fields': 'ip_src'},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_group_invalid_lb_fields(self):
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': [_uuid()],
            'port_pair_group_parameters': {'lb_fields': ['def']},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_group_invalid_ppg_n_tuple_mapping_key(self):
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': [_uuid()],
            'port_pair_group_parameters': {
                'ppg_n_tuple_mapping': {
                    'ingress_n_tuple': {'sssource_ip_prefix': None},
                    'egress_n_tuple': {'protool': None}
                }
            },
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_group_nonuuid_port_pairs(self):
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': ['nouuid'],
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_port_pair_group_list(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        return_value = [{
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portpairgroup_id
        }]
        instance = self.plugin.return_value
        instance.get_port_pair_groups.return_value = return_value

        res = self.api.get(
            _get_path(PORT_PAIR_GROUP_PATH, fmt=self.fmt))

        instance.get_port_pair_groups.assert_called_with(
            mock.ANY,
            fields=mock.ANY,
            filters=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair_groups', res)
        self.assertEqual(return_value, res['port_pair_groups'])

    def test_port_pair_group_get(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        return_value = {
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portpairgroup_id
        }

        instance = self.plugin.return_value
        instance.get_port_pair_group.return_value = return_value

        res = self.api.get(_get_path(PORT_PAIR_GROUP_PATH,
                                     id=portpairgroup_id, fmt=self.fmt))

        instance.get_port_pair_group.assert_called_with(
            mock.ANY,
            portpairgroup_id,
            fields=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair_group', res)
        self.assertEqual(return_value, res['port_pair_group'])

    def test_port_pair_group_update(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        update_data = {'port_pair_group': {
            'name': 'new_name',
            'description': 'new_desc',
            'port_pairs': [_uuid()]
        }}
        return_value = {
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portpairgroup_id
        }

        instance = self.plugin.return_value
        instance.update_port_pair_group.return_value = return_value

        res = self.api.put(
            _get_path(
                PORT_PAIR_GROUP_PATH, id=portpairgroup_id,
                fmt=self.fmt),
            self.serialize(update_data))

        instance.update_port_pair_group.assert_called_with(
            mock.ANY, portpairgroup_id,
            port_pair_group=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair_group', res)
        self.assertEqual(return_value, res['port_pair_group'])

    def test_port_pair_group_update_nonuuid_port_pairs(self):
        portpairgroup_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': ['nouuid']
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(PORT_PAIR_GROUP_PATH, id=portpairgroup_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_port_pair_group_delete(self):
        self._test_entity_delete('port_pair_group')

    def _get_expected_port_pair(self, data):
        return {'port_pair': {
            'name': data['port_pair'].get('name') or '',
            'description': data['port_pair'].get('description') or '',
            'ingress': data['port_pair']['ingress'],
            'egress': data['port_pair']['egress'],
            'service_function_parameters': data['port_pair'].get(
                'service_function_parameters') or {
                'correlation': None, 'weight': 1},
            'tenant_id': data['port_pair']['tenant_id'],
            'project_id': data['port_pair']['project_id']
        }}

    def test_create_port_pair(self):
        portpair_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair': {
            'ingress': _uuid(),
            'egress': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair(data)
        return_value = copy.copy(expected_data['port_pair'])
        return_value.update({'id': portpair_id})
        instance = self.plugin.return_value
        instance.create_port_pair.return_value = return_value
        res = self.api.post(_get_path(PORT_PAIR_PATH, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_port_pair.assert_called_with(
            mock.ANY,
            port_pair=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair', res)
        self.assertEqual(return_value, res['port_pair'])

    def test_create_port_pair_all_fields(self):
        portpair_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair': {
            'description': 'desc',
            'name': 'test1',
            'ingress': _uuid(),
            'egress': _uuid(),
            'service_function_parameters': {
                'correlation': None, 'weight': 2},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair(data)
        return_value = copy.copy(expected_data['port_pair'])
        return_value.update({'id': portpair_id})
        instance = self.plugin.return_value
        instance.create_port_pair.return_value = return_value
        res = self.api.post(_get_path(PORT_PAIR_PATH, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_port_pair.assert_called_with(
            mock.ANY,
            port_pair=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair', res)
        self.assertEqual(return_value, res['port_pair'])

    def test_create_port_pair_non_service_function_parameters(self):
        portpair_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair': {
            'ingress': _uuid(),
            'egress': _uuid(),
            'service_function_parameters': None,
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair(data)
        return_value = copy.copy(expected_data['port_pair'])
        return_value.update({'id': portpair_id})
        instance = self.plugin.return_value
        instance.create_port_pair.return_value = return_value
        res = self.api.post(_get_path(PORT_PAIR_PATH, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_port_pair.assert_called_with(
            mock.ANY,
            port_pair=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair', res)
        self.assertEqual(return_value, res['port_pair'])

    def test_create_port_pair_empty_service_function_parameters(self):
        portpair_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair': {
            'ingress': _uuid(),
            'egress': _uuid(),
            'service_function_parameters': {},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair(data)
        return_value = copy.copy(expected_data['port_pair'])
        return_value.update({'id': portpair_id})
        instance = self.plugin.return_value
        instance.create_port_pair.return_value = return_value
        res = self.api.post(_get_path(PORT_PAIR_PATH, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_port_pair.assert_called_with(
            mock.ANY,
            port_pair=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair', res)
        self.assertEqual(return_value, res['port_pair'])

    def test_create_port_pair_invalid_service_function_parameters(self):
        tenant_id = _uuid()
        data = {'port_pair': {
            'ingress': _uuid(),
            'egress': _uuid(),
            'service_function_parameters': {'abc': 'def'},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_invalid_correlation(self):
        tenant_id = _uuid()
        data = {'port_pair': {
            'ingress': _uuid(),
            'egress': _uuid(),
            'service_function_parameters': {'correlation': 'def'},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_invalid_weight_type(self):
        tenant_id = _uuid()
        data = {'port_pair': {
            'ingress': _uuid(),
            'egress': _uuid(),
            'service_function_parameters': {'weight': 'abc'},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_invalid_weight(self):
        tenant_id = _uuid()
        data = {'port_pair': {
            'ingress': _uuid(),
            'egress': _uuid(),
            'service_function_parameters': {'weight': -1},
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_nouuid_ingress(self):
        tenant_id = _uuid()
        data = {'port_pair': {
            'ingress': 'abc',
            'egress': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_create_port_pair_nouuid_egress(self):
        tenant_id = _uuid()
        data = {'port_pair': {
            'egress': 'abc',
            'ingress': _uuid(),
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(PORT_PAIR_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_port_pair_list(self):
        portpair_id = _uuid()
        tenant_id = _uuid()
        return_value = [{
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portpair_id
        }]
        instance = self.plugin.return_value
        instance.get_port_pairs.return_value = return_value

        res = self.api.get(_get_path(PORT_PAIR_PATH, fmt=self.fmt))

        instance.get_port_pairs.assert_called_with(
            mock.ANY,
            fields=mock.ANY,
            filters=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pairs', res)
        self.assertEqual(return_value, res['port_pairs'])

    def test_port_pair_get(self):
        portpair_id = _uuid()
        tenant_id = _uuid()
        return_value = {
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portpair_id
        }

        instance = self.plugin.return_value
        instance.get_port_pair.return_value = return_value

        res = self.api.get(_get_path(PORT_PAIR_PATH,
                                     id=portpair_id, fmt=self.fmt))

        instance.get_port_pair.assert_called_with(
            mock.ANY,
            portpair_id,
            fields=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair', res)
        self.assertEqual(return_value, res['port_pair'])

    def test_port_pair_update(self):
        portpair_id = _uuid()
        tenant_id = _uuid()
        update_data = {'port_pair': {
            'name': 'new_name',
            'description': 'new_desc'
        }}
        return_value = {
            'tenant_id': tenant_id, 'project_id': tenant_id,
            'id': portpair_id
        }

        instance = self.plugin.return_value
        instance.update_port_pair.return_value = return_value

        res = self.api.put(_get_path(PORT_PAIR_PATH, id=portpair_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_port_pair.assert_called_with(
            mock.ANY, portpair_id,
            port_pair=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair', res)
        self.assertEqual(return_value, res['port_pair'])

    def test_port_pair_update_service_function_parameters(self):
        portpair_id = _uuid()
        data = {'port_pair': {
            'service_function_parameters': None
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(PORT_PAIR_PATH, id=portpair_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_port_pair_update_ingress(self):
        portpair_id = _uuid()
        data = {'port_pair': {
            'ingress': _uuid()
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(PORT_PAIR_PATH, id=portpair_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_port_pair_update_egress(self):
        portpair_id = _uuid()
        data = {'port_pair': {
            'egress': _uuid()
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(PORT_PAIR_PATH, id=portpair_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_port_pair_delete(self):
        self._test_entity_delete('port_pair')

    # NOTE(scsnow): move to neutron-lib
    def test_validate_list_of_allowed_values(self):
        data = ['eth_src', 'eth_src', 'illegal']
        allowed_values = ['eth_src', 'eth_src']
        msg = sfc_ext.validate_list_of_allowed_values(data, allowed_values)
        self.assertIn("Illegal values in a list:", msg)
