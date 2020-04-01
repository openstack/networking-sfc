# Copyright (c) 2017 One Convergence Inc
# All Rights Reserved.
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

from networking_sfc.extensions import sfc as sfc_ext
from networking_sfc.extensions import tap as tap_ext
from networking_sfc.tests.unit.extensions import test_sfc as test_sfc_ext
from oslo_utils import uuidutils
from webob import exc

from neutron.tests.unit.api.v2 import test_base as test_api_v2
import webtest


_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path


class SFCTapExtensionTestCase(test_sfc_ext.SfcExtensionTestCase):
    def setUp(self):
        super(test_sfc_ext.SfcExtensionTestCase, self).setUp()

        attr_map = sfc_ext.RESOURCE_ATTRIBUTE_MAP
        attr_map['port_pair_groups'].update(
            tap_ext.EXTENDED_ATTRIBUTES_2_0['port_pair_groups'])
        self.setup_extension(
            'networking_sfc.extensions.sfc.SfcPluginBase',
            sfc_ext.SFC_EXT,
            sfc_ext.Sfc,
            sfc_ext.SFC_PREFIX[1:],
            plural_mappings={}
        )

    def _get_expected_port_pair_group(self, data):
        ret = super(SFCTapExtensionTestCase,
                    self)._get_expected_port_pair_group(data)
        ret['port_pair_group'].update(
            tap_enabled=data['port_pair_group'].get('tap_enabled', False))
        return ret

    def test_create_port_pair_group_with_default_fields(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'tenant_id': tenant_id,
            'project_id': tenant_id,
        }}
        expected_data = self._get_expected_port_pair_group(data)
        return_value = copy.copy(expected_data['port_pair_group'])
        return_value.update({'id': portpairgroup_id})
        instance = self.plugin.return_value
        instance.create_port_pair_group.return_value = return_value
        res = self.api.post(
            _get_path(test_sfc_ext.PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)
        instance.create_port_pair_group.assert_called_with(
            mock.ANY,
            port_pair_group=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('port_pair_group', res)
        self.assertEqual(return_value, res['port_pair_group'])
        self.assertEqual(False, res['port_pair_group']['tap_enabled'])

    def test_create_port_pair_group_with_tap_enabled(self):
        portpairgroup_id = _uuid()
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'description': 'desc',
            'name': 'test1',
            'port_pairs': [],
            'port_pair_group_parameters': {},
            'tap_enabled': True,
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        expected_data = self._get_expected_port_pair_group(data)
        return_value = copy.copy(expected_data['port_pair_group'])
        return_value.update({'id': portpairgroup_id})
        instance = self.plugin.return_value
        instance.create_port_pair_group.return_value = return_value
        res = self.api.post(
            _get_path(test_sfc_ext.PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)
        instance.create_port_pair_group.assert_called_with(
            mock.ANY,
            port_pair_group=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertEqual(True, res['port_pair_group']['tap_enabled'])

    def test_create_port_pair_group_invalid_tap_enabled_value(self):
        tenant_id = _uuid()
        data = {'port_pair_group': {
            'port_pairs': [_uuid()],
            'tap_enabled': 'two',
            'tenant_id': tenant_id, 'project_id': tenant_id
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.post,
            _get_path(test_sfc_ext.PORT_PAIR_GROUP_PATH, fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)

    def test_update_port_pair_group_tap_enabled_field(self):
        portpairgroup_id = _uuid()
        data = {'port_pair_group': {
            'tap_enabled': True
        }}
        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(test_sfc_ext.PORT_PAIR_GROUP_PATH, id=portpairgroup_id,
                      fmt=self.fmt),
            self.serialize(data),
            content_type='application/%s' % self.fmt)
