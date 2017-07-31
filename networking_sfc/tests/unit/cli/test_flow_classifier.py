# Copyright 2015 Huawei Technologies India Pvt. Ltd.
# All Rights Reserved
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
#

import sys

import mock

from neutronclient import shell
from neutronclient.tests.unit import test_cli20

from networking_sfc.cli import flow_classifier as fc

from oslo_utils import uuidutils

source_port_UUID = uuidutils.generate_uuid()
destination_port_UUID = uuidutils.generate_uuid()


class CLITestV20FCExtensionJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20FCExtensionJSON, self).setUp()
        self._mock_extension_loading()
        self.register_non_admin_status_resource('flow_classifier')

    def _create_patch(self, name, func=None):
        patcher = mock.patch(name)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def _mock_extension_loading(self):
        ext_pkg = 'neutronclient.common.extension'
        flow_classifier = self._create_patch(ext_pkg +
                                             '._discover_via_entry_points')
        flow_classifier.return_value = [("flow_classifier", fc)]
        return flow_classifier

    def test_ext_cmd_loaded(self):
        neutron_shell = shell.NeutronShell('2.0')
        ext_cmd = {'flow-classifier-list': fc.FlowClassifierList,
                   'flow-classifier-create': fc.FlowClassifierCreate,
                   'flow-classifier-update': fc.FlowClassifierUpdate,
                   'flow-classifier-delete': fc.FlowClassifierDelete,
                   'flow-classifier-show': fc.FlowClassifierShow}
        for cmd_name, cmd_class in ext_cmd.items():
            found = neutron_shell.command_manager.find_command([cmd_name])
            self.assertEqual(cmd_class, found[0])

    def test_create_flow_classifier_with_mandatory_params(self):
        """create flow-classifier: flow1."""
        resource = 'flow_classifier'
        cmd = fc.FlowClassifierCreate(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        name = 'flow1'
        ethertype = 'IPv4'
        args = [
            name,
            '--ethertype', ethertype,
        ]
        position_names = ['name', 'ethertype']
        position_values = [name, ethertype]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_flow_classifier_with_all_params(self):
        """create flow-classifier: flow1."""
        resource = 'flow_classifier'
        cmd = fc.FlowClassifierCreate(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        name = 'flow1'
        protocol_name = 'TCP'
        ethertype = 'IPv4'
        source_port = '0:65535'
        source_port_min = 0
        source_port_max = 65535
        destination_port = '1:65534'
        destination_port_min = 1
        destination_port_max = 65534
        source_ip = '192.168.1.0/24'
        destination_ip = '192.168.2.0/24'
        logical_source_port = '4a334cd4-fe9c-4fae-af4b-321c5e2eb051'
        logical_destination_port = '1278dcd4-459f-62ed-754b-87fc5e4a6751'
        description = 'my-desc'
        l7_param = "url=my_url"
        l7_param_expected = {"url": "my_url"}
        args = [name,
                '--protocol', protocol_name,
                '--ethertype', ethertype,
                '--source-port', source_port,
                '--destination-port', destination_port,
                '--source-ip-prefix', source_ip,
                '--destination-ip-prefix', destination_ip,
                '--logical-source-port', logical_source_port,
                '--logical-destination-port', logical_destination_port,
                '--description', description,
                '--l7-parameters', l7_param]
        position_names = ['name', 'protocol', 'ethertype',
                          'source_port_range_min', 'source_port_range_max',
                          'destination_port_range_min',
                          'destination_port_range_max',
                          'source_ip_prefix', 'destination_ip_prefix',
                          'logical_source_port', 'logical_destination_port',
                          'description', 'l7_parameters']
        position_values = [name, protocol_name, ethertype,
                           source_port_min, source_port_max,
                           destination_port_min, destination_port_max,
                           source_ip, destination_ip,
                           logical_source_port,
                           logical_destination_port, description,
                           l7_param_expected]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_list_flow_classifier(self):
        """List available flow-classifiers."""
        resources = "flow_classifiers"
        cmd = fc.FlowClassifierList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_list_flow_classifier_sort(self):
        """flow_classifier-list --sort-key name --sort-key id --sort-key asc

        --sort-key desc
        """
        resources = "flow_classifiers"
        cmd = fc.FlowClassifierList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_list_flow_classifier_limit(self):
        """flow-classifier-list -P."""
        resources = "flow_classifiers"
        cmd = fc.FlowClassifierList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_show_flow_classifier_id(self):
        """flow-classifier-show test_id."""
        resource = 'flow_classifier'
        cmd = fc.FlowClassifierShow(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id, args, ['id'])

    def test_show_flow_classifier_id_name(self):
        """flow-classifier-show ."""
        resource = 'flow_classifier'
        cmd = fc.FlowClassifierShow(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])

    def test_update_flow_classifier_description(self):
        """flow-classifier-update myid --description mydesc."""
        resource = 'flow_classifier'
        cmd = fc.FlowClassifierUpdate(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        args = [myid, '--description', 'flow_classifier1', '--description',
                'flow_classifier2']
        updatefields = {'description': 'flow_classifier2'}
        self._test_update_resource(resource, cmd, myid, args, updatefields)

    def test_update_flow_classifier_name(self):
        """flow-classifier-update myid --name myname."""
        resource = 'flow_classifier'
        cmd = fc.FlowClassifierUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname'],
                                   {'name': 'myname'})

    def test_delete_flow_classifer(self):
        """flow-classifier-delete my-id."""
        resource = 'flow_classifier'
        cmd = fc.FlowClassifierDelete(test_cli20.MyApp(sys.stdout), None)
        my_id = 'myid1'
        args = [my_id]
        self._test_delete_resource(resource, cmd, my_id, args)
