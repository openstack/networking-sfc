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
from networking_sfc.osc.flow_classifier import flow_classifier
from networking_sfc.tests.unit.osc import fakes


def _get_id(client, id_or_name, resource):
    return id_or_name


class TestListFlowClassifierList(fakes.TestNeutronClientOSCV2):

    _fc = fakes.FakeFlowClassifier.create_flow_classifiers(count=1)
    columns = ('ID', 'Name', 'Protocol', 'Source-IP', 'Destination-IP',
               'Logical-Source-Port', 'Logical-Destination-Port')
    data = []
    _flow_classifier = _fc['flow_classifiers'][0]
    data.append((
        _flow_classifier['id'],
        _flow_classifier['name'],
        _flow_classifier['protocol'],
        _flow_classifier['source_ip_prefix'],
        _flow_classifier['destination_ip_prefix'],
        _flow_classifier['logical_source_port'],
        _flow_classifier['logical_destination_port']))
    _flow_classifier1 = {'flow_classifiers': _flow_classifier}
    _flow_classifier_id = _flow_classifier['id']

    def setUp(self):
        super(TestListFlowClassifierList, self).setUp()

        self.neutronclient.list_ext = mock.Mock(
            return_value=self._flow_classifier1
        )
        # Get the command object to test
        self.cmd = flow_classifier.ListFlowClassifier(self.app, self.namespace)

    def test_flow_classifier_list(self):
        client = self.app.client_manager.neutronclient
        mock_flow_classifier_list = client.list_ext
        parsed_args = self.check_parser(self.cmd, [], [])
        columns = self.cmd.take_action(parsed_args)
        data = mock_flow_classifier_list.assert_called_once_with(
            collection='flow_classifiers', path='/sfc/flow_classifiers',
            retrieve_all=True)
        self.assertEqual(self.columns, columns[0])
        self.assertIsNone(data)


class TestCreateFlowClassifier(fakes.TestNeutronClientOSCV2):
    # The new port_pair created
    _flow_classifier = fakes.FakeFlowClassifier.create_flow_classifier()

    columns = (
        'id',
        'name',
        'description',
        'protocol',
        'source_ip_prefix',
        'destination_ip_prefix',
        'logical_source_port',
        'logical_destination_port',
        'source_port_min',
        'source_port_max',
        'destination_port_min',
        'destination_port_max',
        'l7_parameters',
    )

    def get_data(self):
        return (
            self._flow_classifier['id'],
            self._flow_classifier['name'],
            self._flow_classifier['description'],
            self._flow_classifier['protocol'],
            self._flow_classifier['source_ip_prefix'],
            self._flow_classifier['destination_ip_prefix'],
            self._flow_classifier['logical_source_port'],
            self._flow_classifier['logical_destination_port'],
            self._flow_classifier['source_port_range_min'],
            self._flow_classifier['source_port_range_max'],
            self._flow_classifier['destination_port_range_min'],
            self._flow_classifier['destination_port_range_max'],
            self._flow_classifier['l7_parameters'],
        )

    def setUp(self):
        super(TestCreateFlowClassifier, self).setUp()
        mock.patch('networking_sfc.osc.common.find_sfc_resource',
                   new=_get_id).start()
        common.create_sfc_resource = mock.Mock(
            return_value={'flow_classifiers': self._flow_classifier})
        self.data = self.get_data()

        # Get the command object to test
        self.cmd = flow_classifier.CreateFlowClassifier(self.app,
                                                        self.namespace)

    def test_create_flow_classifier(self):
        arglist = []
        verifylist = []

        self.assertRaises(tests_utils.ParserException, self.check_parser,
                          self.cmd, arglist, verifylist)


class TestDeleteFlowClassifier(fakes.TestNeutronClientOSCV2):

    def setUp(self):
        super(TestDeleteFlowClassifier, self).setUp()
        _flow_classifier = fakes.FakePortPairGroup.create_port_pair_groups()
        self._flow_classifier = _flow_classifier['port_pair_groups'][0]
        _port_pair_group_id = self._flow_classifier['id']
        common.delete_sfc_resource = mock.Mock(return_value=None)
        common.find_sfc_resource = mock.Mock(return_value=_port_pair_group_id)
        self.cmd = flow_classifier.DeleteFlowClassifier(self.app,
                                                        self.namespace)

    def test_delete_port_pair_group(self):
        client = self.app.client_manager.neutronclient
        fc_id = self._flow_classifier['id']
        mock_flow_classifier_delete = common.delete_sfc_resource
        arglist = [
            self._flow_classifier['id'],
        ]
        verifylist = [
            ('flow_classifier', self._flow_classifier['id']),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)
        mock_flow_classifier_delete.assert_called_once_with(client,
                                                            'flow_classifier',
                                                            fc_id)
        self.assertIsNone(result)


class TestShowFlowClassifier(fakes.TestNeutronClientOSCV2):

    _fc = fakes.FakeFlowClassifier.create_flow_classifier()
    data = (
        _fc['description'],
        _fc['destination_ip_prefix'],
        _fc['destination_port_range_max'],
        _fc['destination_port_range_min'],
        _fc['ethertype'],
        _fc['id'],
        _fc['l7_parameters'],
        _fc['logical_destination_port'],
        _fc['logical_source_port'],
        _fc['name'],
        _fc['no_flow_classifier'],
        _fc['project_id'],
        _fc['protocol'],
        _fc['source_ip_prefix'],
        _fc['source_port_range_max'],
        _fc['source_port_range_min']
    )
    _flow_classifier = {'flow_classifier': _fc}
    _flow_classifier_id = _fc['id']
    columns = (
        'description',
        'destination_ip_prefix',
        'destination_port_range_max',
        'destination_port_range_min',
        'ethertype',
        'id',
        'l7_parameters',
        'logical_destination_port',
        'logical_source_port',
        'name',
        'no_flow_classifier',
        'project_id',
        'protocol',
        'source_ip_prefix',
        'source_port_range_max',
        'source_port_range_min'
    )

    def setUp(self):
        super(TestShowFlowClassifier, self).setUp()
        common.find_sfc_resource = mock.Mock(
            return_value=self._flow_classifier_id)
        common.show_sfc_resource = mock.Mock(
            return_value=self._flow_classifier
        )
        # Get the command object to test
        self.cmd = flow_classifier.ShowFlowClassifier(self.app, self.namespace)

    def test_port_pair_group_show(self):
        client = self.app.client_manager.neutronclient
        fc_id = self._flow_classifier_id
        mock_flow_classifier_show = common.show_sfc_resource
        arglist = [
            self._flow_classifier_id,
        ]
        verifylist = [
            ('flow_classifier', self._flow_classifier_id),
        ]
        parsed_args = self.check_parser(self.cmd, arglist, verifylist)

        data = self.cmd.take_action(parsed_args)
        mock_flow_classifier_show.assert_called_once_with(client,
                                                          'flow_classifier',
                                                          fc_id)
        self.assertEqual(self.columns, data[0])
        self.assertEqual(self.data, data[1])


class TestUpdateFlowClassifier(fakes.TestNeutronClientOSCV2):
    _flow_classifier = fakes.FakeFlowClassifier.create_flow_classifier()
    _flow_classifier_name = _flow_classifier['name']
    _flow_classifier_id = _flow_classifier['id']

    def setUp(self):
        super(TestUpdateFlowClassifier, self).setUp()
        common.update_sfc_resource = mock.Mock(return_value=None)
        common.find_sfc_resource = mock.Mock(
            return_value=self._flow_classifier_id)
        self.cmd = flow_classifier.UpdateFlowClassifier(
            self.app, self.namespace)

    def test_update_flow_classifier(self):
        client = self.app.client_manager.neutronclient
        fc_id = self._flow_classifier_id
        mock_flow_classifier_update = common.update_sfc_resource
        arglist = [
            self._flow_classifier_name,
            '--name', 'name_updated',
            '--description', 'desc_updated'
        ]
        verifylist = [
            ('flow_classifier', self._flow_classifier_name),
            ('name', 'name_updated'),
            ('description', 'desc_updated'),
        ]

        parsed_args = self.check_parser(self.cmd, arglist, verifylist)
        result = self.cmd.take_action(parsed_args)

        attrs = {
            'name': 'name_updated',
            'description': 'desc_updated'}
        mock_flow_classifier_update.assert_called_once_with(client,
                                                            'flow_classifier',
                                                            attrs,
                                                            fc_id)

        self.assertIsNone(result)
