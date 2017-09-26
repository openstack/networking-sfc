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

from tempest.lib import exceptions as lib_exc
from tempest.lib.services.network import base


class PortChainClient(base.BaseNetworkClient):

    def create_port_chain(self, **kwargs):
        uri = '/sfc/port_chains'
        post_data = {'port_chain': kwargs}
        return self.create_resource(uri, post_data)

    def update_port_chain(self, pc_id, **kwargs):
        uri = '/sfc/port_chains/%s' % pc_id
        post_data = {'port_chain': kwargs}
        return self.update_resource(uri, post_data)

    def show_port_chain(self, pc_id, **fields):
        uri = '/sfc/port_chains/%s' % pc_id
        return self.show_resource(uri, **fields)

    def delete_port_chain(self, pc_id):
        uri = '/sfc/port_chains/%s' % pc_id
        return self.delete_resource(uri)

    def list_port_chains(self, **filters):
        uri = '/sfc/port_chains'
        return self.list_resources(uri, **filters)

    def is_resource_deleted(self, id):
        try:
            self.show_port_chain(id)
        except lib_exc.NotFound:
            return True
        return False

    @property
    def resource_type(self):
        """Returns the primary type of resource this client works with."""
        return 'sfc'


class PortPairGroupClient(base.BaseNetworkClient):

    def create_port_pair_group(self, **kwargs):
        uri = '/sfc/port_pair_groups'
        post_data = {'port_pair_group': kwargs}
        return self.create_resource(uri, post_data)

    def update_port_pair_group(self, pg_id, **kwargs):
        uri = '/sfc/port_pair_groups/%s' % pg_id
        post_data = {'port_pair_group': kwargs}
        return self.update_resource(uri, post_data)

    def show_port_pair_group(self, pg_id, **fields):
        uri = '/sfc/port_pair_groups/%s' % pg_id
        return self.show_resource(uri, **fields)

    def delete_port_pair_group(self, pg_id):
        uri = '/sfc/port_pair_groups/%s' % pg_id
        return self.delete_resource(uri)

    def list_port_pair_groups(self, **filters):
        uri = '/sfc/port_pair_groups'
        return self.list_resources(uri, **filters)

    def is_resource_deleted(self, id):
        try:
            self.show_port_pair_group(id)
        except lib_exc.NotFound:
            return True
        return False

    @property
    def resource_type(self):
        """Returns the primary type of resource this client works with."""
        return 'sfc'


class PortPairClient(base.BaseNetworkClient):

    def create_port_pair(self, **kwargs):
        uri = '/sfc/port_pairs'
        post_data = {'port_pair': kwargs}
        return self.create_resource(uri, post_data)

    def update_port_pair(self, pp_id, **kwargs):
        uri = '/sfc/port_pairs/%s' % pp_id
        post_data = {'port_pair': kwargs}
        return self.update_resource(uri, post_data)

    def show_port_pair(self, pp_id, **fields):
        uri = '/sfc/port_pairs/%s' % pp_id
        return self.show_resource(uri, **fields)

    def delete_port_pair(self, pp_id):
        uri = '/sfc/port_pairs/%s' % pp_id
        return self.delete_resource(uri)

    def list_port_pairs(self, **filters):
        uri = '/sfc/port_pairs'
        return self.list_resources(uri, **filters)

    def is_resource_deleted(self, id):
        try:
            self.show_port_pair(id)
        except lib_exc.NotFound:
            return True
        return False

    @property
    def resource_type(self):
        """Returns the primary type of resource this client works with."""
        return 'sfc'


class ServiceGraphClient(base.BaseNetworkClient):

    def create_service_graph(self, **kwargs):
        uri = '/sfc/service_graphs'
        post_data = {'service_graph': kwargs}
        return self.create_resource(uri, post_data)

    def update_service_graph(self, pp_id, **kwargs):
        uri = '/sfc/service_graphs/%s' % pp_id
        post_data = {'service_graph': kwargs}
        return self.update_resource(uri, post_data)

    def show_service_graph(self, pp_id, **fields):
        uri = '/sfc/service_graphs/%s' % pp_id
        return self.show_resource(uri, **fields)

    def delete_service_graph(self, pp_id):
        uri = '/sfc/service_graphs/%s' % pp_id
        return self.delete_resource(uri)

    def list_service_graphs(self, **filters):
        uri = '/sfc/service_graphs'
        return self.list_resources(uri, **filters)

    def is_resource_deleted(self, id):
        try:
            self.show_service_graph(id)
        except lib_exc.NotFound:
            return True
        return False

    @property
    def resource_type(self):
        """Returns the primary type of resource this client works with."""
        return 'sfc'
