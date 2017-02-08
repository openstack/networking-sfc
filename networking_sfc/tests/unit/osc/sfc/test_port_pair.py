# Copyright (c) 2016 Huawei Technologies India Pvt.Limited.
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

import mock

from osc_lib.tests import utils as tests_utils

from networking_sfc.osc import common
from networking_sfc.osc.sfc import port_pair
from networking_sfc.tests.unit.osc import fakes


def _get_id(client, id_or_name, resource):
    return id_or_name


class TestListPortPair(fakes.TestNeutronClientOSCV2):
    _port_pairs = fakes.FakePortPair.create_port_pairs(count=1)
    columns = ('ID', 'Name', 'Ingress Logical Port', 'Egress Logical Port')
    data = []
    _port_pair = _port_pairs['port_pairs'][0]
    data.append((
        _port_pair['id'],
        _port_pair['name'],
        _port_pair['ingress'],
        _port_pair['egress']))
    _port_pair1 = {'port_pairs': _port_pair}
    _port_pair_id = _port_pair['id'],

    def setUp(self):
        super(TestListPortPair, self).setUp()

        self.neutronclient.list_ext = mock.Mock(
            return_value=self._port_pair1
        )
        # Get the command object to test
        self.cmd = port_pair.ListPortPair(self.app, self.namespace)

    def test_port_pair_list(self):
        client = self.app.client_manager.neutronclient
        mock_port_pair_list = client.list_ext
        parsed_args = self.check_parser(self.cmd, [], [])
        columns = self.cmd.take_action(parsed_args)
        data = mock_port_pair_list.assert_called_once_with(
            collection='port_pairs', path='/sfc/port_pairs', retrieve_all=True)
        self.assertEqual(self.columns, columns[0])
        self.assertIsNone(data)


class TestCreatePortPair(fakes.TestNeutronClientOSCV2):
    # The new port_pair created
    _port_pair = fakes.FakePortPair.create_port_pair()

    columns = (
        'id',
        'name',
        'description',
        'ingress',
        'egress',
        'service_function_parameter',
    )

    def get_data(self):
        return (
            self._port_pair['id'],
            self._port_pair['name'],
            self._port_pair['description'],
            self._port_pair['ingress'],
            self._port_pair['egress'],
            self._port_pair['service_function_parameter'],
        )

    def setUp(self):
        super(TestCreatePortPair, self).setUp()
        mock.patch('networking_sfc.osc.common.get_id',
                   new=_get_id).start()
        common.create_sfc_resource = mock.Mock(
            return_value={'port_pairs': self._port_pair})
        self.data = self.get_data()

        # Get the command object to test
        self.cmd = port_pair.CreatePortPair(self.app, self.namespace)

    def test_create_port_pair_with_no_args(self):
        arglist = []
        verifylist = []

        self.assertRaises(tests_utils.ParserException, self.check_parser,
                          self.cmd, arglist, verifylist)


class TestDeletePortPair(fakes.TestNeutronClientOSCV2):

    def setUp(self):
        super(TestDeletePortPair, self).setUp()
        _port_pair = fakes.FakePortPair.create_port_pairs()
        self._port_pair = _port_pair['port_pairs'][0]
        _port_pair_id = self._port_pair['id']
        common.delete_sfc_resource = mock.Mock(return_value=None)
        common.find_sfc_resource = mock.Mock(return_value=_port_pair_id)

        self.cmd = port_pair.DeletePortPair(self.app, self.namespace)

    def test_delete_port_pair(self):
        client = self.app.client_manager.neutronclient
        mock_port_pair_delete = common.delete_sfc_resource
        arglist = [
            self._port_pair['id'],
        ]
        verifylist = [
            ('port_pair', self._port_pair['id']),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        mock_port_pair_delete.assert_called_once_with(client,
                                                      'port_pair',
                                                      self._port_pair['id'])
        self.assertIsNone(result)


class TestShowPortPair(fakes.TestNeutronClientOSCV2):

    _pp = fakes.FakePortPair.create_port_pair()
    data = (
        _pp['description'],
        _pp['egress'],
        _pp['id'],
        _pp['ingress'],
        _pp['name'],
        _pp['project_id'],
        _pp['service_function_parameter']
    )
    _port_pair = {'port_pair': _pp}
    _port_pair_id = _pp['id']
    columns = (
        'description',
        'egress',
        'id',
        'ingress',
        'name',
        'project_id',
        'service_function_parameter'
    )

    def setUp(self):
        super(TestShowPortPair, self).setUp()
        common.find_sfc_resource = mock.Mock(return_value=self._port_pair_id)

        common.show_sfc_resource = mock.Mock(
            return_value=self._port_pair
        )

        # Get the command object to test
        self.cmd = port_pair.ShowPortPair(self.app, self.namespace)

    def test_port_pair_show(self):
        client = self.app.client_manager.neutronclient
        mock_port_pair_show = common.show_sfc_resource
        arglist = [
            self._port_pair_id,
        ]
        verifylist = [
            ('port_pair', self._port_pair_id),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        data = self.cmd.take_action(parsed_args)
        mock_port_pair_show.assert_called_once_with(client,
                                                    'port_pair',
                                                    self._port_pair_id)
        self.assertEqual(self.columns, data[0])
        self.assertEqual(self.data, data[1])


class TestUpdatePortPair(fakes.TestNeutronClientOSCV2):
    _port_pair = fakes.FakePortPair.create_port_pair()
    _port_pair_name = _port_pair['name']
    _port_pair_id = _port_pair['id']

    def setUp(self):
        super(TestUpdatePortPair, self).setUp()
        common.update_sfc_resource = mock.Mock(return_value=None)
        common.find_sfc_resource = mock.Mock(return_value=self._port_pair_id)

        self.cmd = port_pair.UpdatePortPair(self.app, self.namespace)

    def test_update_port_pair(self):
        client = self.app.client_manager.neutronclient
        mock_port_pair_update = common.update_sfc_resource
        arglist = [
            self._port_pair_name,
            '--name', 'name_updated',
            '--description', 'desc_updated'
        ]
        verifylist = [
            ('port_pair', self._port_pair_name),
            ('name', 'name_updated'),
            ('description', 'desc_updated'),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)

        attrs = {
            'name': 'name_updated',
            'description': 'desc_updated'}
        mock_port_pair_update.assert_called_once_with(client,
                                                      'port_pair', attrs,
                                                      self._port_pair_id)
        self.assertIsNone(result)
