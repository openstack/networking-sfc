# Copyright 2016 Futurewei. All rights reserved.
# Copyright 2017 Intel Corporation.
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

import socket

import netaddr
from tempest.api.network import base
from tempest.common import utils
from tempest.lib.common.utils import data_utils
from tempest.lib import exceptions as lib_exc

from networking_sfc.tests.tempest_plugin.tests import flowclassifier_client
from networking_sfc.tests.tempest_plugin.tests import sfc_client


class BaseFlowClassifierTest(
    flowclassifier_client.FlowClassifierClientMixin,
    base.BaseAdminNetworkTest
):
    @classmethod
    def resource_setup(cls):
        super(BaseFlowClassifierTest, cls).resource_setup()
        if not utils.is_extension_enabled('flow_classifier', 'network'):
            msg = "FlowClassifier Extension not enabled."
            raise cls.skipException(msg)
        cls.network = cls.create_network()
        cls.subnet = cls.create_subnet(cls.network)
        cls.host_id = socket.gethostname()

    @classmethod
    def resource_cleanup(cls):
        if not utils.is_extension_enabled('flow_classifier', 'network'):
            msg = "FlowClassifier Extension not enabled."
            raise cls.skipException(msg)
        super(BaseFlowClassifierTest, cls).resource_cleanup()

    @classmethod
    def _create_port(cls, network, **kwargs):
        body = cls.admin_ports_client.create_port(
            network_id=network['id'],
            **kwargs)
        port = body['port']
        return port

    def _try_create_flowclassifier(self, **kwargs):
        if 'logical_source_port' not in kwargs:
            port_kwargs = {"binding:host_id": self.host_id}
            port = self._create_port(network=self.network, **port_kwargs)
            self.addCleanup(self._try_delete_port, port['id'])
            kwargs['logical_source_port'] = port['id']
            if 'source_ip_prefix' not in kwargs:
                port_ip_prefix = str(netaddr.IPNetwork(
                    port['fixed_ips'][0]['ip_address']))
                kwargs['source_ip_prefix'] = port_ip_prefix
        fc = self.create_flowclassifier(**kwargs)
        self.addCleanup(self._try_delete_flowclassifier, fc['id'])
        return fc

    def _try_delete_port(self, port_id):
        try:
            self.admin_ports_client.delete_port(port_id)
        except lib_exc.NotFound:
            pass
        body = self.admin_ports_client.list_ports()
        ports_list = body['ports']
        self.assertNotIn(port_id, [n['id'] for n in ports_list])

    def _try_delete_flowclassifier(self, fc_id):
        # delete flowclassifier, if it exists
        try:
            self.flowclassifier_client.delete_flowclassifier(fc_id)
        # if flowclassifier is not found, this means it was deleted
        except lib_exc.NotFound:
            pass
        body = self.flowclassifier_client.list_flowclassifiers()
        fc_list = body['flow_classifiers']
        self.assertNotIn(fc_id, [n['id'] for n in fc_list])


class BaseSfcTest(
    sfc_client.SfcClientMixin, BaseFlowClassifierTest
):
    @classmethod
    def resource_setup(cls):
        super(BaseSfcTest, cls).resource_setup()
        if not utils.is_extension_enabled('sfc', 'network'):
            msg = "Sfc Extension not enabled."
            raise cls.skipException(msg)

    @classmethod
    def resource_cleanup(cls):
        if not utils.is_extension_enabled('sfc', 'network'):
            msg = "Sfc Extension not enabled."
            raise cls.skipException(msg)
        super(BaseSfcTest, cls).resource_cleanup()

    def _try_create_port_pair(self, **kwargs):
        if 'ingress' not in kwargs or 'egress' not in 'kwargs':
            router = self.admin_routers_client.create_router(
                name=data_utils.rand_name('router-'))['router']
            self.addCleanup(
                self.admin_routers_client.delete_router, router['id'])
            port_kwargs = {"binding:host_id": self.host_id}
            port = self._create_port(
                network=self.network, **port_kwargs)
            self.addCleanup(self._try_delete_port, port['id'])
            self.admin_routers_client.add_router_interface(
                router['id'], port_id=port['id'])
            self.addCleanup(self.admin_routers_client.remove_router_interface,
                            router['id'],
                            port_id=port['id'])
            if 'ingress' not in kwargs:
                kwargs['ingress'] = port['id']
            if 'egress' not in kwargs:
                kwargs['egress'] = port['id']
        pp = self.create_port_pair(**kwargs)
        self.addCleanup(self._try_delete_port_pair, pp['id'])
        return pp

    def _try_delete_port_pair(self, pp_id):
        # delete port pair, if it exists
        try:
            self.portpair_client.delete_port_pair(pp_id)
        # if port pair is not found, this means it was deleted
        except lib_exc.NotFound:
            pass
        body = self.portpair_client.list_port_pairs()
        pp_list = body['port_pairs']
        self.assertNotIn(pp_id, [n['id'] for n in pp_list])

    def _try_create_port_pair_group(self, **kwargs):
        pg = self.create_port_pair_group(
            **kwargs)
        self.addCleanup(self._try_delete_port_pair_group, pg['id'])
        # self.pgs.append(pg)
        return pg

    def _try_delete_port_pair_group(self, pg_id):
        # delete port pair group, if it exists
        try:
            self.portpairgroup_client.delete_port_pair_group(pg_id)
        # if port pair group is not found, this means it was deleted
        except lib_exc.NotFound:
            pass
        body = self.portpairgroup_client.list_port_pair_groups()
        pg_list = body['port_pair_groups']
        self.assertNotIn(pg_id, [n['id'] for n in pg_list])

    def _try_create_port_chain(self, **kwargs):
        pc = self.create_port_chain(
            **kwargs)
        self.addCleanup(self._try_delete_port_chain, pc['id'])
        # self.pcs.append(pc)
        return pc

    def _try_delete_port_chain(self, pc_id):
        # delete port chain, if it exists
        try:
            self.portchain_client.delete_port_chain(pc_id)
        # if port chain is not found, this means it was deleted
        except lib_exc.NotFound:
            pass
        body = self.portchain_client.list_port_chains()
        pc_list = body['port_chains']
        self.assertNotIn(pc_id, [n['id'] for n in pc_list])

    def _try_create_service_graph(self, **kwargs):
        graph = self.create_service_graph(
            **kwargs)
        self.addCleanup(self._try_delete_service_graph, graph['id'])
        return graph

    def _try_delete_service_graph(self, graph_id):
        # delete Service Graph, if it exists
        try:
            self.sfcgraph_client.delete_service_graph(graph_id)
        # if Service Graph is not found, this means it was deleted
        except lib_exc.NotFound:
            pass
        body = self.sfcgraph_client.list_service_graphs()
        graph_list = body['service_graphs']
        self.assertNotIn(graph_id, [n['id'] for n in graph_list])
