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

import netaddr

from tempest.lib.common.utils import data_utils
from tempest.lib import decorators

from networking_sfc.tests.tempest_plugin.tests.api import base


class SfcExtensionTestJSON(base.BaseSfcTest):
    """Tests the following operations in the Neutron API:

        List port chains
        Create port chain
        Update port chain
        Delete port chain
        Show port chain
        List port pair groups
        Create port pair group
        Update port pair group
        Delete port pair group
        Show port pair groups
        List port pairs
        Create port pair
        Update port pair
        Delete port pair
        Show port pair
        List Service Graphs
        Create Service Graph
        Update Service Graph
        Delete Service Graph
        Show Service Graphs
    """
    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076469')
    def test_create_port_pair_different_ingress_egress(self):
        ingress_network = self.create_network()
        self.addCleanup(self.networks_client.delete_network,
                        ingress_network['id'])
        cidr = netaddr.IPNetwork('192.168.1.0/24')
        allocation_pools = {'allocation_pools': [{'start': str(cidr[2]),
                                                  'end': str(cidr[-2])}]}
        ingress_subnet = self.create_subnet(ingress_network, cidr=cidr,
                                            mask_bits=cidr.prefixlen,
                                            **allocation_pools)
        self.addCleanup(self.subnets_client.delete_subnet,
                        ingress_subnet['id'])
        egress_network = self.create_network()
        self.addCleanup(self.networks_client.delete_network,
                        egress_network['id'])
        cidr = netaddr.IPNetwork('192.168.2.0/24')
        allocation_pools = {'allocation_pools': [{'start': str(cidr[2]),
                                                  'end': str(cidr[-2])}]}
        egress_subnet = self.create_subnet(egress_network, cidr=cidr,
                                           mask_bits=cidr.prefixlen,
                                           **allocation_pools)
        self.addCleanup(self.subnets_client.delete_subnet,
                        egress_subnet['id'])
        router = self.admin_routers_client.create_router(
            name=data_utils.rand_name('router-'))['router']
        self.addCleanup(self.admin_routers_client.delete_router, router['id'])
        port_kwargs = {"binding:host_id": self.host_id}
        ingress = self._create_port(
            network=ingress_network, **port_kwargs)
        self.addCleanup(self._try_delete_port, ingress['id'])
        self.admin_routers_client.add_router_interface(
            router['id'], port_id=ingress['id'])
        self.addCleanup(self.admin_routers_client.remove_router_interface,
                        router['id'],
                        port_id=ingress['id'])
        egress = self._create_port(
            network=egress_network, **port_kwargs)
        self.addCleanup(self._try_delete_port, egress['id'])
        self.admin_routers_client.add_router_interface(
            router['id'], port_id=egress['id'])
        self.addCleanup(self.admin_routers_client.remove_router_interface,
                        router['id'],
                        port_id=egress['id'])
        pp = self._try_create_port_pair(
            ingress=ingress['id'],
            egress=egress['id'])
        pps = self.portpair_client.list_port_pairs()
        self.assertIn((
            pp['id'],
            pp['name'],
            pp['ingress'],
            pp['egress']
        ), [(
            m['id'],
            m['name'],
            m['ingress'],
            m['egress'],
        ) for m in pps['port_pairs']])

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076468')
    def test_list_port_pair(self):
        # List port pairs
        pp = self._try_create_port_pair()
        pps = self.portpair_client.list_port_pairs()
        self.assertIn((
            pp['id'],
            pp['name'],
            pp['ingress'],
            pp['egress']
        ), [(
            m['id'],
            m['name'],
            m['ingress'],
            m['egress'],
        ) for m in pps['port_pairs']])

    @decorators.idempotent_id('3ff8c08e-26ff-4034-ae48-810ed213a998')
    def test_show_port_pair(self):
        # show a created port pair
        created = self._try_create_port_pair()
        pp = self.portpair_client.show_port_pair(
            created['id'])
        for key, value in pp['port_pair'].items():
            self.assertEqual(created[key], value)

    @decorators.idempotent_id('563564f7-7077-4f5e-8cdc-51f37ae5a2b9')
    def test_update_port_pair(self):
        # Create port pair
        name1 = data_utils.rand_name('test')
        pp = self._try_create_port_pair(
            name=name1
        )
        pp_id = pp['id']

        # Update port pair
        name2 = data_utils.rand_name('test')
        body = self.portpair_client.update_port_pair(
            pp_id, name=name2)
        self.assertEqual(body['port_pair']['name'], name2)

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076479')
    def test_create_port_pair_group_empty_port_pairs(self):
        pg = self._try_create_port_pair_group(
            port_pairs=[])
        pgs = self.portpairgroup_client.list_port_pair_groups()
        self.assertIn((
            pg['id'],
            pg['name'],
            set(pg['port_pairs']),
        ), [(
            m['id'],
            m['name'],
            set(m['port_pairs'])
        ) for m in pgs['port_pair_groups']])

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076469')
    def test_create_port_pair_group_multi_port_pairs(self):
        pp1 = self._try_create_port_pair()
        pp2 = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(
            port_pairs=[pp1['id'], pp2['id']])
        pgs = self.portpairgroup_client.list_port_pair_groups()
        self.assertIn((
            pg['id'],
            pg['name'],
            set(pg['port_pairs']),
        ), [(
            m['id'],
            m['name'],
            set(m['port_pairs'])
        ) for m in pgs['port_pair_groups']])

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076468')
    def test_list_port_pair_group(self):
        # List port pair groups
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        pgs = self.portpairgroup_client.list_port_pair_groups()
        self.assertIn((
            pg['id'],
            pg['name'],
            pg['port_pairs'],
        ), [(
            m['id'],
            m['name'],
            m['port_pairs']
        ) for m in pgs['port_pair_groups']])

    @decorators.idempotent_id('3ff8c08e-26ff-4034-ae48-810ed213a998')
    def test_show_port_pair_group(self):
        # show a created port pair group
        pp = self._try_create_port_pair()
        created = self._try_create_port_pair_group(port_pairs=[pp['id']])
        pg = self.portpairgroup_client.show_port_pair_group(
            created['id'])
        for key, value in pg['port_pair_group'].items():
            self.assertEqual(created[key], value)

    @decorators.idempotent_id('563564f7-7077-4f5e-8cdc-51f37ae5a2b9')
    def test_update_port_pair_group(self):
        # Create port pair group
        pp = self._try_create_port_pair()
        name1 = data_utils.rand_name('test')
        pg = self._try_create_port_pair_group(
            name=name1, port_pairs=[pp['id']]
        )
        pg_id = pg['id']

        # Update port pair group
        name2 = data_utils.rand_name('test')
        body = self.portpairgroup_client.update_port_pair_group(
            pg_id, name=name2)
        self.assertEqual(body['port_pair_group']['name'], name2)

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076568')
    def test_create_port_chain_empty_flow_classifiers(self):
        # Create port chains
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[])
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['port_pair_groups'],
            pc['flow_classifiers']
        ), [(
            m['id'],
            m['name'],
            m['port_pair_groups'],
            m['flow_classifiers']
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076668')
    def test_create_port_chain_multi_flowclassifiers(self):
        # Create port chains
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc1 = self._try_create_flowclassifier()
        fc2 = self._try_create_flowclassifier()
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc1['id'], fc2['id']])
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            set(pc['flow_classifiers'])
        ), [(
            m['id'],
            m['name'],
            set(m['flow_classifiers'])
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076669')
    def test_create_port_chain_flowclassifiers_symmetric(self):
        # Create symmetric port chain
        router = self.admin_routers_client.create_router(
            name=data_utils.rand_name('router-'))['router']
        self.addCleanup(
            self.admin_routers_client.delete_router, router['id'])
        port_kwargs = {"binding:host_id": self.host_id}
        dst_port = self._create_port(
            network=self.network, **port_kwargs)
        self.addCleanup(self._try_delete_port, dst_port['id'])
        self.admin_routers_client.add_router_interface(
            router['id'], port_id=dst_port['id'])
        self.addCleanup(self.admin_routers_client.remove_router_interface,
                        router['id'],
                        port_id=dst_port['id'])
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier(
            logical_destination_port=dst_port['id'])
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']],
            chain_parameters={'symmetric': True})
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['chain_parameters'],
            set(pc['flow_classifiers'])
        ), [(
            m['id'],
            m['name'],
            m['chain_parameters'],
            set(m['flow_classifiers'])
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076478')
    def test_create_port_chain_multi_port_pair_groups(self):
        # Create port chain
        pp1 = self._try_create_port_pair()
        pg1 = self._try_create_port_pair_group(port_pairs=[pp1['id']])
        pp2 = self._try_create_port_pair()
        pg2 = self._try_create_port_pair_group(port_pairs=[pp2['id']])
        fc = self._try_create_flowclassifier()
        pc = self._try_create_port_chain(
            port_pair_groups=[pg1['id'], pg2['id']],
            flow_classifiers=[fc['id']])
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['port_pair_groups'],
        ), [(
            m['id'],
            m['name'],
            m['port_pair_groups']
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076490')
    def test_create_port_chain_port_pair_group_symmetric(self):
        # Create symmetric port chain with port_pair_group
        router = self.admin_routers_client.create_router(
            name=data_utils.rand_name('router-'))['router']
        self.addCleanup(
            self.admin_routers_client.delete_router, router['id'])
        port_kwargs = {"binding:host_id": self.host_id}
        dst_port = self._create_port(
            network=self.network, **port_kwargs)
        self.addCleanup(self._try_delete_port, dst_port['id'])
        self.admin_routers_client.add_router_interface(
            router['id'], port_id=dst_port['id'])
        self.addCleanup(self.admin_routers_client.remove_router_interface,
                        router['id'],
                        port_id=dst_port['id'])
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier(
            logical_destination_port=dst_port['id'])
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']],
            chain_parameters={'symmetric': True})
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['port_pair_groups'],
            pc['chain_parameters']
        ), [(
            m['id'],
            m['name'],
            m['port_pair_groups'],
            m['chain_parameters']
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('1b84cf01-9c09-4ce7-bc72-b15e39076468')
    def test_list_port_chain(self):
        # List port chains
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier()
        pc = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']])
        pcs = self.portchain_client.list_port_chains()
        self.assertIn((
            pc['id'],
            pc['name'],
            pc['port_pair_groups'],
            set(pc['flow_classifiers'])
        ), [(
            m['id'],
            m['name'],
            m['port_pair_groups'],
            set(m['flow_classifiers'])
        ) for m in pcs['port_chains']])

    @decorators.idempotent_id('3ff8c08e-26ff-4034-ae48-810ed213a998')
    def test_show_port_chain(self):
        # show a created port chain
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier()
        created = self._try_create_port_chain(
            port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']])
        pc = self.portchain_client.show_port_chain(
            created['id'])
        for key, value in pc['port_chain'].items():
            self.assertEqual(created[key], value)

    @decorators.idempotent_id('563564f7-7077-4f5e-8cdc-51f37ae5a2b9')
    def test_update_port_chain(self):
        # Create port chain
        pp = self._try_create_port_pair()
        pg = self._try_create_port_pair_group(port_pairs=[pp['id']])
        fc = self._try_create_flowclassifier()
        name1 = data_utils.rand_name('test')
        pc = self._try_create_port_chain(
            name=name1, port_pair_groups=[pg['id']],
            flow_classifiers=[fc['id']]
        )
        pc_id = pc['id']

        # Update port chain
        name2 = data_utils.rand_name('test')
        body = self.portchain_client.update_port_chain(
            pc_id, name=name2)
        self.assertEqual(body['port_chain']['name'], name2)
