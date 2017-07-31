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

from networking_sfc.cli import port_chain as pc

from oslo_utils import uuidutils

FAKE_port_pair_group1_UUID = uuidutils.generate_uuid()
FAKE_port_pair_group2_UUID = uuidutils.generate_uuid()
FAKE_FC1_UUID = uuidutils.generate_uuid()
FAKE_FC2_UUID = uuidutils.generate_uuid()
FAKE_PARAM1_UUID = uuidutils.generate_uuid()
FAKE_PARAM2_UUID = uuidutils.generate_uuid()


class CLITestV20PortChainExtensionJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20PortChainExtensionJSON, self).setUp()
        self._mock_extension_loading()
        self.register_non_admin_status_resource('port_chain')

    def _create_patch(self, name, func=None):
        patcher = mock.patch(name)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def _mock_extension_loading(self):
        ext_pkg = 'neutronclient.common.extension'
        port_chain = self._create_patch(ext_pkg +
                                        '._discover_via_entry_points')
        port_chain.return_value = [("port_chain", pc)]
        return port_chain

    def test_ext_cmd_loaded(self):
        neutron_shell = shell.NeutronShell('2.0')
        ext_cmd = {'port-chain-list': pc.PortChainList,
                   'port-chain-create': pc.PortChainCreate,
                   'port-chain-update': pc.PortChainUpdate,
                   'port-chain-delete': pc.PortChainDelete,
                   'port-chain-show': pc.PortChainShow}
        for cmd_name, cmd_class in ext_cmd.items():
            found = neutron_shell.command_manager.find_command([cmd_name])
            self.assertEqual(cmd_class, found[0])

    def test_create_port_chain_with_mandatory_param(self):
        """Create port_chain: myname."""
        resource = 'port_chain'
        cmd = pc.PortChainCreate(test_cli20.MyApp(sys.stdout),
                                 None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--port-pair-group', FAKE_port_pair_group1_UUID]
        position_names = ['name', 'port_pair_groups']
        position_values = [name, [FAKE_port_pair_group1_UUID]]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_chain_with_multiple_port_pair_group(self):
        """Create port_chain: myname."""
        resource = 'port_chain'
        cmd = pc.PortChainCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--port-pair-group', FAKE_port_pair_group1_UUID,
                '--port-pair-group', FAKE_port_pair_group2_UUID]
        position_names = ['name', 'port_pair_groups']
        position_values = [name, [FAKE_port_pair_group1_UUID,
                                  FAKE_port_pair_group2_UUID]]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_chain_with_all_params(self):
        """Create port_chain: myname."""
        resource = 'port_chain'
        cmd = pc.PortChainCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        desc = 'check port chain cli'
        chain_parameter = "correlation=mpls"
        chain_parameter_expected = {"correlation": "mpls"}
        args = [name, '--description', desc, '--port-pair-group',
                FAKE_port_pair_group1_UUID, '--flow-classifier',
                FAKE_FC1_UUID, '--chain-parameters', chain_parameter]
        position_names = ['name', 'description', 'port_pair_groups',
                          'flow_classifiers', 'chain_parameters']
        position_values = [name, desc, [FAKE_port_pair_group1_UUID],
                           [FAKE_FC1_UUID], chain_parameter_expected]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_chain_with_single_classifier(self):
        """Create port_chain: myname."""
        resource = 'port_chain'
        cmd = pc.PortChainCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--port-pair-group', FAKE_port_pair_group1_UUID,
                '--flow-classifier', FAKE_FC1_UUID]
        position_names = ['name', 'port_pair_groups', 'flow_classifiers']
        position_values = [name, [FAKE_port_pair_group1_UUID], [FAKE_FC1_UUID]]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_chain_with_chain_parameters(self):
        """Create port_chain: myname."""
        resource = 'port_chain'
        cmd = pc.PortChainCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--port-pair-group', FAKE_port_pair_group1_UUID,
                '--chain-parameters', 'symmetric=True']
        position_names = ['name', 'port_pair_groups', 'chain_parameters']
        position_values = [name, [FAKE_port_pair_group1_UUID],
                           {'symmetric': 'True'}]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_chain_with_multiple_classifiers(self):
        """Create port_chain: myname."""
        resource = 'port_chain'
        cmd = pc.PortChainCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--port-pair-group', FAKE_port_pair_group1_UUID,
                '--flow-classifier', FAKE_FC1_UUID,
                '--flow-classifier', FAKE_FC2_UUID]
        position_names = ['name', 'port_pair_groups', 'flow_classifiers']
        position_values = [name, [FAKE_port_pair_group1_UUID], [FAKE_FC1_UUID,
                                                                FAKE_FC2_UUID]]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_update_port_chain(self):
        """Update port_chain: myid --name myname."""
        resource = 'port_chain'
        cmd = pc.PortChainUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname'],
                                   {'name': 'myname'})

    def test_update_port_chain_with_no_flow_classifier(self):
        """Update port_chain: myid --name myname --no-flow-classifier None."""
        resource = 'port_chain'
        cmd = pc.PortChainUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--no-flow-classifier'],
                                   {'name': 'myname',
                                    'flow_classifiers': []})

    def test_update_port_chain_with_single_port_pair_group(self):
        """Update port_chain: myid --name myname --port-pair-group uuid."""
        resource = 'port_chain'
        cmd = pc.PortChainUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--port-pair-group',
                                    FAKE_port_pair_group1_UUID,
                                    '--no-flow-classifier'],
                                   {'name': 'myname',
                                    'port_pair_groups': [
                                        FAKE_port_pair_group1_UUID],
                                    'flow_classifiers': []})

    def test_update_port_chain_with_multi_port_pair_groups(self):
        """Update port_chain: myid --name myname --port-pair-group uuid ..."""
        resource = 'port_chain'
        cmd = pc.PortChainUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--port-pair-group',
                                    FAKE_port_pair_group1_UUID,
                                    '--port-pair-group',
                                    FAKE_port_pair_group2_UUID,
                                    '--no-flow-classifier'],
                                   {'name': 'myname',
                                    'port_pair_groups': [
                                        FAKE_port_pair_group1_UUID,
                                        FAKE_port_pair_group2_UUID],
                                    'flow_classifiers': []})

    def test_update_port_chain_with_single_classifier(self):
        """Update port_chain: myid --name myname --flow-classifier uuid."""
        resource = 'port_chain'
        cmd = pc.PortChainUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--flow-classifier', FAKE_FC1_UUID],
                                   {'name': 'myname',
                                    'flow_classifiers': [FAKE_FC1_UUID]})

    def test_update_port_chain_with_multi_classifiers(self):
        """Update port_chain: myid --name myname --flow-classifier uuid ..."""
        resource = 'port_chain'
        cmd = pc.PortChainUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--flow-classifier', FAKE_FC1_UUID,
                                    '--flow-classifier', FAKE_FC2_UUID],
                                   {'name': 'myname',
                                    'flow_classifiers': [
                                        FAKE_FC1_UUID, FAKE_FC2_UUID]})

    def test_update_port_chain_with_port_pair_group_classifier(self):
        """Update port_chain."""
        resource = 'port_chain'
        cmd = pc.PortChainUpdate(test_cli20.MyApp(sys.stdout), None)
        self._test_update_resource(resource, cmd, 'myid',
                                   ['myid', '--name', 'myname',
                                    '--flow-classifier', FAKE_FC1_UUID,
                                    '--port-pair-group',
                                    FAKE_port_pair_group1_UUID],
                                   {'name': 'myname',
                                    'flow_classifiers': [FAKE_FC1_UUID],
                                    'port_pair_groups': [
                                        FAKE_port_pair_group1_UUID]})

    def test_delete_port_chain(self):
        """Delete port-chain: myid."""
        resource = 'port_chain'
        cmd = pc.PortChainDelete(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        args = [myid]
        self._test_delete_resource(resource, cmd, myid, args)

    def test_list_port_chain(self):
        """List port_chain."""
        resources = 'port_chains'
        cmd = pc.PortChainList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_list_port_chains_sort(self):
        """List port_chains: --sort-key name --sort-key id --sort-key asc

        --sort-key desc
        """
        resources = "port_chains"
        cmd = pc.PortChainList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_show_port_chain(self):
        """Show port-chain: --fields id --fields name myid."""
        resource = 'port_chain'
        cmd = pc.PortChainShow(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])
