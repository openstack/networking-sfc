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

from networking_sfc.cli import port_pair as pp

from oslo_utils import uuidutils

ingress_port_UUID = uuidutils.generate_uuid()
egress_port_UUID = uuidutils.generate_uuid()


class CLITestV20PortPairExtensionJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20PortPairExtensionJSON, self).setUp()
        self._mock_extension_loading()
        self.register_non_admin_status_resource('port_pair')

    def _create_patch(self, name, func=None):
        patcher = mock.patch(name)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def _mock_extension_loading(self):
        ext_pkg = 'neutronclient.common.extension'
        port_pair = self._create_patch(ext_pkg +
                                       '._discover_via_entry_points')
        port_pair.return_value = [("port_pair", pp)]
        return port_pair

    def test_ext_cmd_loaded(self):
        neutron_shell = shell.NeutronShell('2.0')
        ext_cmd = {'port-pair-list': pp.PortPairList,
                   'port-pair-create': pp.PortPairCreate,
                   'port-pair-update': pp.PortPairUpdate,
                   'port-pair-delete': pp.PortPairDelete,
                   'port-pair-show': pp.PortPairShow}
        for cmd_name, cmd_class in ext_cmd.items():
            found = neutron_shell.command_manager.find_command([cmd_name])
            self.assertEqual(cmd_class, found[0])

    def test_create_port_pair_with_mandatory_param(self):
        """Create port_pair: myname."""
        resource = 'port_pair'
        cmd = pp.PortPairCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--ingress', ingress_port_UUID,
                '--egress', egress_port_UUID]
        position_names = ['name', 'ingress', 'egress']
        position_values = [name, ingress_port_UUID, egress_port_UUID]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_pair_with_bidirectional_port(self):
        """Create port_pair: myname with bidirectional port."""
        resource = 'port_pair'
        cmd = pp.PortPairCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--ingress', ingress_port_UUID,
                '--egress', ingress_port_UUID]
        position_names = ['name', 'ingress', 'egress']
        position_values = [name, ingress_port_UUID, ingress_port_UUID]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_pair_with_all_param(self):
        """Create port_pair: myname with all parameter"""
        resource = 'port_pair'
        cmd = pp.PortPairCreate(test_cli20.MyApp(sys.stdout),
                                None)
        name = 'myname'
        myid = 'myid'
        desc = "my_port_pair"
        service_fn_param = 'correlation=None,weight=2'
        service_fn_param_exp = {"correlation": "None", "weight": "2"}
        args = [name, '--ingress', ingress_port_UUID,
                '--egress', egress_port_UUID, '--description', desc,
                '--service-function-parameters', service_fn_param]
        position_names = ['name', 'ingress', 'egress', 'description',
                          'service_function_parameters']
        position_values = [name, ingress_port_UUID, egress_port_UUID, desc,
                           service_fn_param_exp]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_update_port_pair_description(self):
        """Update port_pair: myid --description mydesc."""
        resource = 'port_pair'
        desc1 = "My_New_Port_Pair"
        cmd = pp.PortPairUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--description', desc1],
                                   {'description': desc1})

    def test_update_port_pair_name(self):
        """Update port_pair: myid --name myname."""
        resource = 'port_pair'
        my_name = "My_New_Port_Pair"
        cmd = pp.PortPairUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', my_name],
                                   {'name': my_name})

    def test_delete_port_pair(self):
        """Delete port-pair: myid."""
        resource = 'port_pair'
        cmd = pp.PortPairDelete(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        args = [myid]
        self._test_delete_resource(resource, cmd, myid, args)

    def test_list_port_pair(self):
        """List port_pairs."""
        resources = 'port_pairs'
        cmd = pp.PortPairList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_list_port_pair_limit(self):
        """size (1000) limited list: port-pair -P."""
        resources = "port_pairs"
        cmd = pp.PortPairList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_list_port_pairs_sort(self):
        """List port_pairs: --sort-key name --sort-key id --sort-key asc

        --sort-key desc
        """
        resources = "port_pairs"
        cmd = pp.PortPairList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_show_port_pair(self):
        """Show port-pairs: --fields id --fields name myid."""
        resource = 'port_pair'
        cmd = pp.PortPairShow(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])
