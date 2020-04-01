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

from networking_sfc.extensions import servicegraph as sg_ext
from networking_sfc.extensions import sfc as sfc_ext

_uuid = uuidutils.generate_uuid
_get_path = test_api_v2._get_path

SERVICE_GRAPH_PATH = (sg_ext.SG_PREFIX[1:] + '/service_graphs')


class ServiceGraphExtensionTestCase(test_api_v2_extension.ExtensionTestCase):
    fmt = 'json'

    def setUp(self):
        self._mock_unnecessary_logging()
        super(ServiceGraphExtensionTestCase, self).setUp()
        self.setup_extension(
            'networking_sfc.extensions.servicegraph.ServiceGraphPluginBase',
            sfc_ext.SFC_EXT,
            sg_ext.Servicegraph,
            sg_ext.SG_PREFIX[1:],
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
    def _get_expected_service_graph(data):
        service_graph = data['service_graph']
        ret = {'service_graph': {
            'description': service_graph.get('description') or '',
            'name': service_graph.get('name') or '',
            'port_chains': service_graph['port_chains'],
            'tenant_id': service_graph['project_id'],
            'project_id': service_graph['project_id']
        }}
        return ret

    def _test_create_service_graph(self, **kwargs):
        tenant_id = _uuid()
        graph_data = {
            'port_chains': {_uuid(): [_uuid()]},
            'project_id': tenant_id
        }
        graph_data.update(kwargs)
        data = {'service_graph': graph_data}
        expected_data = self._get_expected_service_graph(data)
        return_value = copy.copy(expected_data['service_graph'])
        return_value.update({'id': _uuid()})
        instance = self.plugin.return_value
        instance.create_service_graph.return_value = return_value
        res = self.api.post(_get_path(SERVICE_GRAPH_PATH, fmt=self.fmt),
                            self.serialize(data),
                            content_type='application/%s' % self.fmt)
        instance.create_service_graph.assert_called_with(
            mock.ANY,
            service_graph=expected_data)
        self.assertEqual(exc.HTTPCreated.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('service_graph', res)
        self.assertEqual(return_value, res['service_graph'])

    def test_create_service_graph(self):
        self._test_create_service_graph()

    def test_create_service_graph_complex_dict(self):
        port_chains = {_uuid(): [_uuid()],
                       _uuid(): [_uuid(), _uuid()]}
        self._test_create_service_graph(description='desc',
                                        name='graph1',
                                        port_chains=port_chains)

    def test_list_service_graph(self):
        service_graph_id = _uuid()
        tenant_id = _uuid()
        return_value = [{
            'project_id': tenant_id,
            'id': service_graph_id
        }]
        instance = self.plugin.return_value
        instance.get_service_graphs.return_value = return_value

        res = self.api.get(_get_path(SERVICE_GRAPH_PATH, fmt=self.fmt))

        instance.get_service_graphs.assert_called_with(
            mock.ANY,
            fields=mock.ANY,
            filters=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('service_graphs', res)
        self.assertEqual(return_value, res['service_graphs'])

    def test_get_service_graph(self):
        service_graph_id = _uuid()
        tenant_id = _uuid()
        return_value = {
            'project_id': tenant_id,
            'id': service_graph_id
        }

        instance = self.plugin.return_value
        instance.get_service_graph.return_value = return_value

        res = self.api.get(_get_path(SERVICE_GRAPH_PATH,
                                     id=service_graph_id, fmt=self.fmt))

        instance.get_service_graph.assert_called_with(
            mock.ANY,
            service_graph_id,
            fields=mock.ANY
        )
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('service_graph', res)
        self.assertEqual(return_value, res['service_graph'])

    def test_update_service_graph(self):
        service_graph_id = _uuid()
        tenant_id = _uuid()
        update_data = {'service_graph': {
            'name': 'new_name',
            'description': 'new_desc'
        }}
        return_value = {
            'project_id': tenant_id,
            'id': service_graph_id
        }

        instance = self.plugin.return_value
        instance.update_service_graph.return_value = return_value

        res = self.api.put(_get_path(SERVICE_GRAPH_PATH, id=service_graph_id,
                                     fmt=self.fmt),
                           self.serialize(update_data))

        instance.update_service_graph.assert_called_with(
            mock.ANY, service_graph_id,
            service_graph=update_data)
        self.assertEqual(exc.HTTPOk.code, res.status_int)
        res = self.deserialize(res)
        self.assertIn('service_graph', res)
        self.assertEqual(return_value, res['service_graph'])

    def test_update_service_graph_with_port_chains(self):
        # API currently disallows rebuilding graphs, so we test this
        service_graph_id = _uuid()
        update_data = {'service_graph': {
            'name': 'new_name',
            'description': 'new_desc',
            'port_chains': {_uuid(): [_uuid()]}
        }}

        self.assertRaises(
            webtest.app.AppError,
            self.api.put,
            _get_path(SERVICE_GRAPH_PATH, id=service_graph_id, fmt=self.fmt),
            self.serialize(update_data),
            content_type='application/%s' % self.fmt)

    def test_delete_service_graph(self):
        self._test_entity_delete('service_graph')
