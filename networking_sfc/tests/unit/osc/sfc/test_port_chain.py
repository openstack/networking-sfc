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
from networking_sfc.osc.sfc import port_chain
from networking_sfc.tests.unit.osc import fakes


def _get_id(client, id_or_name, resource):
    return id_or_name


class TestListPortChain(fakes.TestNeutronClientOSCV2):
    _port_chains = fakes.FakePortChain.create_port_chains(count=1)
    columns = ('ID', 'Name', 'Port Pair Groups', 'Flow Classifiers',
               'Chain Parameters')
    data = []
    _port_chain = _port_chains['port_chains'][0]
    data.append((
        _port_chain['id'],
        _port_chain['name'],
        _port_chain['port_pair_groups'],
        _port_chain['flow_classifiers'],
        _port_chain['chain_parameters']))
    _port_chain1 = {'port_chains': _port_chain}
    _port_chain_id = _port_chain['id']

    def setUp(self):
        super(TestListPortChain, self).setUp()

        self.neutronclient.list_ext = mock.Mock(
            return_value=self._port_chain1
        )
        # Get the command object to test
        self.cmd = port_chain.ListPortChain(self.app, self.namespace)

    def test_port_chain_list(self):
        client = self.app.client_manager.neutronclient
        mock_port_chain_list = client.list_ext
        parsed_args = self.check_parser(self.cmd, [], [])
        columns = self.cmd.take_action(parsed_args)
        data = mock_port_chain_list.assert_called_once_with(
            collection='port_chains', path='/sfc/port_chains',
            retrieve_all=True)
        self.assertEqual(self.columns, columns[0])
        self.assertIsNone(data)


class TestCreatePortChain(fakes.TestNeutronClientOSCV2):
    # The new port_chain created
    _port_chain = fakes.FakePortChain.create_port_chain()

    columns = (
        'id',
        'name',
        'description',
        'port_pair_groups',
        'flow_classifiers'
        'chain_parameters',
    )

    def get_data(self):
        return (
            self._port_chain['id'],
            self._port_chain['name'],
            self._port_chain['description'],
            self._port_chain['port_pair_groups'],
            self._port_chain['flow_classifiers'],
            self._port_chain['chain_parameters'],
        )

    def setUp(self):
        super(TestCreatePortChain, self).setUp()
        mock.patch('networking_sfc.osc.common.find_sfc_resource',
                   new=_get_id).start()
        common.create_sfc_resource = mock.Mock(
            return_value={'port_pair_groups': self._port_chain})
        self.data = self.get_data()

        # Get the command object to test
        self.cmd = port_chain.CreatePortChain(self.app, self.namespace)

    def test_create_port_chain(self):
        arglist = []
        verifylist = []

        self.assertRaises(tests_utils.ParserException, self.check_parser,
                          self.cmd, arglist, verifylist)


class TestDeletePortChain(fakes.TestNeutronClientOSCV2):

    def setUp(self):
        super(TestDeletePortChain, self).setUp()
        _port_chain = fakes.FakePortChain.create_port_chains()
        self._port_chain = _port_chain['port_chains'][0]
        _port_chain_id = self._port_chain['id']
        common.delete_sfc_resource = mock.Mock(return_value=None)
        common.find_sfc_resource = mock.Mock(return_value=_port_chain_id)
        self.cmd = port_chain.DeletePortChain(self.app, self.namespace)

    def test_delete_port_chain(self):
        client = self.app.client_manager.neutronclient
        mock_port_chain_delete = common.delete_sfc_resource
        arglist = [
            self._port_chain['id'],
        ]
        verifylist = [
            ('port_chain', self._port_chain['id']),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        mock_port_chain_delete.assert_called_once_with(client,
                                                       'port_chain',
                                                       self._port_chain['id'])
        self.assertIsNone(result)


class TestShowPortChain(fakes.TestNeutronClientOSCV2):

    _pc = fakes.FakePortChain.create_port_chain()
    data = (
        _pc['chain_id'],
        _pc['chain_parameters'],
        _pc['description'],
        _pc['flow_classifiers'],
        _pc['id'],
        _pc['name'],
        _pc['port_pair_groups'],
        _pc['project_id']
    )
    _port_chain = {'port_chain': _pc}
    _port_chain_id = _pc['id']
    columns = (
        'chain_id',
        'chain_parameters',
        'description',
        'flow_classifiers',
        'id',
        'name',
        'port_pair_groups',
        'project_id'
    )

    def setUp(self):
        super(TestShowPortChain, self).setUp()
        common.find_sfc_resource = mock.Mock(return_value=self._port_chain_id)
        common.show_sfc_resource = mock.Mock(
            return_value=self._port_chain
        )
        # Get the command object to test
        self.cmd = port_chain.ShowPortChain(self.app, self.namespace)

    def test_port_chain_show(self):
        client = self.app.client_manager.neutronclient
        mock_port_chain_show = common.show_sfc_resource
        arglist = [
            self._port_chain_id,
        ]
        verifylist = [
            ('port_chain', self._port_chain_id),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        data = self.cmd.take_action(parsed_args)
        mock_port_chain_show.assert_called_once_with(client,
                                                     'port_chain',
                                                     self._port_chain_id)
        self.assertEqual(self.columns, data[0])
        self.assertEqual(self.data, data[1])


class TestUpdatePortChain(fakes.TestNeutronClientOSCV2):
    _port_chain = fakes.FakePortChain.create_port_chain()
    _port_chain_name = _port_chain['name']
    _port_chain_id = _port_chain['id']
    port_pair_group_id = _port_chain_id

    def setUp(self):
        super(TestUpdatePortChain, self).setUp()
        common.update_sfc_resource = mock.Mock(return_value=None)
        common.find_sfc_resource = mock.Mock(return_value=self._port_chain_id)
        self.cmd = port_chain.UpdatePortChain(self.app, self.namespace)

    def test_update_port_chain(self):
        client = self.app.client_manager.neutronclient
        mock_port_chain_update = common.update_sfc_resource
        arglist = [
            self._port_chain_name,
            '--name', 'name_updated',
            '--description', 'desc_updated',
            '--no-flow-classifier',
            '--port-pair-group', self.port_pair_group_id,
        ]
        verifylist = [
            ('port_chain', self._port_chain_name),
            ('name', 'name_updated'),
            ('description', 'desc_updated'),
            ('no_flow_classifier', True),
            ('port_pair_groups', [self.port_pair_group_id])
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)

        attrs = {
            'name': 'name_updated',
            'description': 'desc_updated',
            'flow_classifiers': [],
            'port_pair_groups': [self.port_pair_group_id]}
        mock_port_chain_update.assert_called_once_with(client,
                                                       'port_chain', attrs,
                                                       self._port_chain_id)
        self.assertIsNone(result)
