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

from networking_sfc.cli import port_pair_group as pg

from oslo_utils import uuidutils

pp1 = uuidutils.generate_uuid()
pp2 = uuidutils.generate_uuid()
pp3 = uuidutils.generate_uuid()
pp4 = uuidutils.generate_uuid()


class CLITestV20PortGroupExtensionJSON(test_cli20.CLITestV20Base):
    def setUp(self):
        super(CLITestV20PortGroupExtensionJSON, self).setUp()
        self._mock_extension_loading()
        self.register_non_admin_status_resource('port_pair_group')

    def _create_patch(self, name, func=None):
        patcher = mock.patch(name)
        thing = patcher.start()
        self.addCleanup(patcher.stop)
        return thing

    def _mock_extension_loading(self):
        ext_pkg = 'neutronclient.common.extension'
        port_pair_group = self._create_patch(ext_pkg +
                                             '._discover_via_entry_points')
        port_pair_group.return_value = [("port_pair_group", pg)]
        return port_pair_group

    def test_ext_cmd_loaded(self):
        neutron_shell = shell.NeutronShell('2.0')
        ext_cmd = {'port-pair-group-list': pg.PortPairGroupList,
                   'port-pair-group-create': pg.PortPairGroupCreate,
                   'port-pair-group-update': pg.PortPairGroupUpdate,
                   'port-pair-group-delete': pg.PortPairGroupDelete,
                   'port-pair-group-show': pg.PortPairGroupShow}
        for cmd_name, cmd_class in ext_cmd.items():
            found = neutron_shell.command_manager.find_command([cmd_name])
            self.assertEqual(cmd_class, found[0])

    def test_create_port_pair_group_with_mandatory_args(self):
        """Create port_pair_group: myname."""
        resource = 'port_pair_group'
        cmd = pg.PortPairGroupCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--port-pair', pp1]
        position_names = ['name', 'port_pairs']
        position_values = [name, [pp1]]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_pair_group_with_multi_port_pairs(self):
        """Create port_pair_group: myname with multiple port pairs"""
        resource = 'port_pair_group'
        cmd = pg.PortPairGroupCreate(test_cli20.MyApp(sys.stdout), None)
        name = 'myname'
        myid = 'myid'
        args = [name, '--port-pair', pp1, '--port-pair', pp2]
        position_names = ['name', 'port_pairs']
        position_values = [name, [pp1, pp2]]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_pair_group_with_lb_fields_param(self):
        """Create port_pair_group: myname with lb_fields parameter"""
        resource = 'port_pair_group'
        cmd = pg.PortPairGroupCreate(test_cli20.MyApp(sys.stdout),
                                     None)
        name = 'myname'
        myid = 'myid'
        ppg_param = 'lb_fields=ip_src&ip_dst'
        ppg_exp = {"lb_fields": ["ip_src", "ip_dst"]}
        args = [name, '--port-pair', pp1,
                '--port-pair-group-parameters', ppg_param]
        position_names = ['name', 'port_pairs',
                          'port_pair_group_parameters']
        position_values = [name, [pp1], ppg_exp]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_create_port_pair_group_with_ppg_n_tuple_mapping_param(self):
        """Create port_pair_group: myname with ppg_n_tuple_mapping parameter"""
        resource = 'port_pair_group'
        cmd = pg.PortPairGroupCreate(test_cli20.MyApp(sys.stdout),
                                     None)
        name = 'myname'
        myid = 'myid'
        ppg_param = ('ppg_n_tuple_mapping=source_ip_prefix_ingress=None'
                     '&source_ip_prefix_egress=None')
        ppg_exp = {
            'ppg_n_tuple_mapping': {
                'ingress_n_tuple': {'source_ip_prefix': 'None'},
                'egress_n_tuple': {'source_ip_prefix': 'None'}}}
        args = [name, '--port-pair', pp1,
                '--port-pair-group-parameters', ppg_param]
        position_names = ['name', 'port_pairs',
                          'port_pair_group_parameters']
        position_values = [name, [pp1], ppg_exp]
        self._test_create_resource(resource, cmd, name, myid, args,
                                   position_names, position_values)

    def test_delete_port_pair_group(self):
        """Delete port_pair_group: myid."""
        resource = 'port_pair_group'
        cmd = pg.PortPairGroupDelete(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        args = [myid]
        self._test_delete_resource(resource, cmd, myid, args)

    def test_update_port_group_only_port_pair(self):
        """Update port_pair_group"""
        resource = 'port_pair_group'
        cmd = pg.PortPairGroupUpdate(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        args = [myid, '--port-pair', pp1,
                '--port-pair', pp2]
        updatefields = {'port_pairs': [pp1, pp2]}
        self._test_update_resource(resource, cmd, myid, args, updatefields)

    def test_update_port_group_with_all_desc(self):
        """Update port_pair_group and description"""
        resource = 'port_pair_group'
        cmd = pg.PortPairGroupUpdate(test_cli20.MyApp(sys.stdout), None)
        myid = 'myid'
        args = [myid, '--port-pair', pp1, '--port-pair', pp2,
                '--description', 'my_port_pair_group']
        updatefields = {'port_pairs': [pp1, pp2],
                        'description': 'my_port_pair_group'}
        self._test_update_resource(resource, cmd, myid, args, updatefields)

    def test_list_port_pair_group(self):
        """List port_pair_group."""
        resources = 'port_pair_groups'
        cmd = pg.PortPairGroupList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, True)

    def test_list_port_pair_group_limit(self):
        """size (1000) limited list: port-pair-group -P."""
        resources = "port_pair_groups"
        cmd = pg.PortPairGroupList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd, page_size=1000)

    def test_list_port_group_sort(self):
        """List port_pair_group: --sort-key name --sort-key id --sort-key asc

        --sort-key desc
        """
        resources = "port_pair_groups"
        cmd = pg.PortPairGroupList(test_cli20.MyApp(sys.stdout), None)
        self._test_list_resources(resources, cmd,
                                  sort_key=["name", "id"],
                                  sort_dir=["asc", "desc"])

    def test_show_port_group(self):
        """Show port-chain: --fields id --fields name myid."""
        resource = 'port_pair_group'
        cmd = pg.PortPairGroupShow(test_cli20.MyApp(sys.stdout), None)
        args = ['--fields', 'id', '--fields', 'name', self.test_id]
        self._test_show_resource(resource, cmd, self.test_id,
                                 args, ['id', 'name'])
