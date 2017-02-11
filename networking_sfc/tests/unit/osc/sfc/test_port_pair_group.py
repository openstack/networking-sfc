# Copyright (c) 2016 Huawei Technologies India Pvt.Limited.
# All Rights Reserved.
#
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
from networking_sfc.osc.sfc import port_pair_group
from networking_sfc.tests.unit.osc import fakes


def _get_id(client, id_or_name, resource):
    return id_or_name


class TestListPortPairGroup(fakes.TestNeutronClientOSCV2):
    _ppgs = fakes.FakePortPairGroup.create_port_pair_groups(count=1)
    columns = ('ID', 'Name', 'Port Pair', 'Port Pair Group Parameters')
    data = []
    _port_pair_group = _ppgs['port_pair_groups'][0]
    data.append((
        _port_pair_group['id'],
        _port_pair_group['name'],
        _port_pair_group['port_pairs'],
        _port_pair_group['port_pair_group_parameters']))
    _port_pair_group1 = {'port_pair_groups': _port_pair_group}
    _port_pair_id = _port_pair_group['id']

    def setUp(self):
        super(TestListPortPairGroup, self).setUp()

        self.neutronclient.list_ext = mock.Mock(
            return_value=self._port_pair_group1
        )
        # Get the command object to test
        self.cmd = port_pair_group.ListPortPairGroup(self.app, self.namespace)

    def test_port_pair_group_list(self):
        client = self.app.client_manager.neutronclient
        mock_port_pair_group_list = client.list_ext
        parsed_args = self.check_parser(self.cmd, [], [])
        columns = self.cmd.take_action(parsed_args)
        data = mock_port_pair_group_list.assert_called_once_with(
            collection='port_pair_groups', path='/sfc/port_pair_groups',
            retrieve_all=True)
        self.assertEqual(self.columns, columns[0])
        self.assertIsNone(data)


class TestCreatePortPairGroup(fakes.TestNeutronClientOSCV2):
    # The new port_pair created
    _port_pair_group = fakes.FakePortPairGroup.create_port_pair_group()

    columns = (
        'id',
        'name',
        'description',
        'port_pairs',
        'port_pair_group_parameters',
    )

    def get_data(self):
        return (
            self._port_pair_group['id'],
            self._port_pair_group['name'],
            self._port_pair_group['description'],
            self._port_pair_group['port_pairs'],
            self._port_pair_group['port_pair_group_parameters'],
        )

    def setUp(self):
        super(TestCreatePortPairGroup, self).setUp()
        mock.patch('networking_sfc.osc.common.find_sfc_resource',
                   new=_get_id).start()
        common.create_sfc_resource = mock.Mock(
            return_value={'port_pair_groups': self._port_pair_group})
        self.data = self.get_data()

        # Get the command object to test
        self.cmd = port_pair_group.CreatePortPairGroup(self.app,
                                                       self.namespace)

    def test_create_port_pair_group(self):
        arglist = []
        verifylist = []

        self.assertRaises(tests_utils.ParserException, self.check_parser,
                          self.cmd, arglist, verifylist)


class TestDeletePortPairGroup(fakes.TestNeutronClientOSCV2):

    def setUp(self):
        super(TestDeletePortPairGroup, self).setUp()
        _port_pair_group = fakes.FakePortPairGroup.create_port_pair_groups()
        self._port_pair_group = _port_pair_group['port_pair_groups'][0]
        _port_pair_group_id = self._port_pair_group['id']
        common.delete_sfc_resource = mock.Mock(return_value=None)
        common.find_sfc_resource = mock.Mock(return_value=_port_pair_group_id)
        self.cmd = port_pair_group.DeletePortPairGroup(self.app,
                                                       self.namespace)

    def test_delete_port_pair_group(self):
        client = self.app.client_manager.neutronclient
        ppg_id = self._port_pair_group['id']
        mock_port_pair_group_delete = common.delete_sfc_resource
        arglist = [
            self._port_pair_group['id'],
        ]
        verifylist = [
            ('port_pair_group', self._port_pair_group['id']),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        mock_port_pair_group_delete.assert_called_once_with(client,
                                                            'port_pair_group',
                                                            ppg_id)
        self.assertIsNone(result)


class TestShowPortPairGroup(fakes.TestNeutronClientOSCV2):

    _ppg = fakes.FakePortPairGroup.create_port_pair_group()
    data = (
        _ppg['description'],
        _ppg['group_id'],
        _ppg['id'],
        _ppg['name'],
        _ppg['port_pair_group_parameters'],
        _ppg['port_pairs'],
        _ppg['project_id'])
    _port_pair_group = {'port_pair_group': _ppg}
    _port_pair_group_id = _ppg['id']
    columns = (
        'description',
        'group_id',
        'id',
        'name',
        'port_pair_group_parameters',
        'port_pairs',
        'project_id')

    def setUp(self):
        super(TestShowPortPairGroup, self).setUp()
        common.find_sfc_resource = mock.Mock(
            return_value=self._port_pair_group_id)
        common.show_sfc_resource = mock.Mock(
            return_value=self._port_pair_group
        )
        # Get the command object to test
        self.cmd = port_pair_group.ShowPortPairGroup(self.app, self.namespace)

    def test_port_pair_group_show(self):
        client = self.app.client_manager.neutronclient
        mock_port_pair_group_show = common.show_sfc_resource
        arglist = [
            self._port_pair_group_id,
        ]
        verifylist = [
            ('port_pair_group', self._port_pair_group_id),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        data = self.cmd.take_action(parsed_args)
        ppg_id = self._port_pair_group_id
        mock_port_pair_group_show.assert_called_once_with(client,
                                                          'port_pair_group',
                                                          ppg_id)
        self.assertEqual(self.columns, data[0])
        self.assertEqual(self.data, data[1])


class TestUpdatePortPairGroup(fakes.TestNeutronClientOSCV2):
    _port_pair_group = fakes.FakePortPairGroup.create_port_pair_group()
    _port_pair_group_name = _port_pair_group['name']
    _port_pair_group_id = _port_pair_group['id']
    port_id = _port_pair_group_id

    def setUp(self):
        super(TestUpdatePortPairGroup, self).setUp()
        common.update_sfc_resource = mock.Mock(return_value=None)
        common.find_sfc_resource = mock.Mock(
            return_value=self._port_pair_group_id)

        self.cmd = port_pair_group.UpdatePortPairGroup(self.app,
                                                       self.namespace)

    def test_update_port_pair_group(self):
        client = self.app.client_manager.neutronclient
        mock_port_pair_group_update = common.update_sfc_resource
        arglist = [
            self._port_pair_group_name,
            '--name', 'name_updated',
            '--description', 'desc_updated',
            '--port-pair', self.port_id,
        ]
        verifylist = [
            ('port_pair_group', self._port_pair_group_name),
            ('name', 'name_updated'),
            ('description', 'desc_updated'),
            ('port_pairs', [self.port_id]),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)

        attrs = {
            'name': 'name_updated',
            'description': 'desc_updated',
            'port_pairs': [self.port_id]}
        ppg_id = self._port_pair_group_id
        mock_port_pair_group_update.assert_called_once_with(client,
                                                            'port_pair_group',
                                                            attrs, ppg_id)
        self.assertIsNone(result)
