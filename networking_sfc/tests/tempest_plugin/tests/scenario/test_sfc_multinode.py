# Copyright 2016 Futurewei. All rights reserved.
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

import testscenarios

from tempest.common import waiters
from tempest import config
from tempest import exceptions

from networking_sfc.tests.tempest_plugin.tests.scenario import test_sfc

CONF = config.CONF
load_tests = testscenarios.load_tests_apply_scenarios


class TestSfcMultinode(test_sfc.TestSfc):
    @classmethod
    def skip_checks(cls):
        super(TestSfcMultinode, cls).skip_checks()
        if CONF.compute.min_compute_nodes < 2:
            raise cls.skipException(
                "Less than 2 compute nodes, skipping multinode tests.")

    # @classmethod
    # def setup_credentials(cls):
    #     super(TestSfcMultinode, cls).setup_credentials()
    #     cls.manager = cls.admin_manager
    #     cls.os = cls.os_adm

    @classmethod
    def setup_clients(cls):
        super(TestSfcMultinode, cls).setup_clients()
        # Use admin client by default
        # cls.manager = cls.admin_manager
        # this is needed so that we can use the availability_zone:host
        # scheduler hint, which is admin_only by default
        # cls.servers_client = cls.admin_manager.servers_client
        # super(TestSfcMultinode, cls).resource_setup()

    def _setup_security_group(self):
        self.security_group = self._create_security_group(
            security_group_rules_client=(
                self.admin_manager.security_group_rules_client
            ),
            security_groups_client=self.admin_manager.security_groups_client
        )
        self._create_security_group_rule(
            self.security_group,
            security_group_rules_client=(
                self.admin_manager.security_group_rules_client
            ),
            security_groups_client=self.admin_manager.security_groups_client,
            protocol=None,
            direction='ingress'
        )

    def setUp(self):
        super(TestSfcMultinode, self).setUp()
        host_client = self.manager.hosts_client
        hosts = host_client.list_hosts()['hosts']
        hosts = [x for x in hosts if x['service'] == 'compute']

        # ensure we have at least as many compute hosts as we expect
        if len(hosts) < CONF.compute.min_compute_nodes:
            raise exceptions.InvalidConfiguration(
                "Host list %s is shorter than min_compute_nodes. "
                "Did a compute worker not boot correctly?" % hosts)
        self.hosts = hosts
        self.host_index_to_create = 0

    def _create_server(self, network):
        kwargs = {}
        host = self.hosts[self.host_index_to_create]
        if self.host_index_to_create >= len(self.hosts):
            self.host_index_to_create = 0
        else:
            self.host_index_to_create += 1
        if self.keypair is not None:
            kwargs['key_name'] = self.keypair['name']
        if self.security_group is not None:
            kwargs['security_groups'] = [{'name': self.security_group['name']}]
        server = self.create_server(
            availability_zone='%(zone)s:%(host_name)s' % host,
            networks=[{'uuid': network['id']}],
            wait_until='ACTIVE',
            clients=self.admin_manager,
            **kwargs)
        waiters.wait_for_server_status(self.servers_client,
                                       server['id'], 'ACTIVE')
        self._check_tenant_network_connectivity(
            server, self.ssh_user, self.keypair['private_key'])
        return server
