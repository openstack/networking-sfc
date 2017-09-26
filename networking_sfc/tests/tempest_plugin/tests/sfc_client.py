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

from tempest import config

from networking_sfc.tests.tempest_plugin.services import sfc_client

CONF = config.CONF


class SfcClientMixin(object):

    @classmethod
    def resource_setup(cls):
        super(SfcClientMixin, cls).resource_setup()
        manager = cls.os_admin
        cls.portchain_client = (
            sfc_client.PortChainClient(
                manager.auth_provider,
                CONF.network.catalog_type,
                CONF.network.region or CONF.identity.region,
                endpoint_type=CONF.network.endpoint_type,
                build_interval=CONF.network.build_interval,
                build_timeout=CONF.network.build_timeout,
                **manager.default_params
            )
        )
        cls.portpairgroup_client = (
            sfc_client.PortPairGroupClient(
                manager.auth_provider,
                CONF.network.catalog_type,
                CONF.network.region or CONF.identity.region,
                endpoint_type=CONF.network.endpoint_type,
                build_interval=CONF.network.build_interval,
                build_timeout=CONF.network.build_timeout,
                **manager.default_params
            )
        )
        cls.portpair_client = (
            sfc_client.PortPairClient(
                manager.auth_provider,
                CONF.network.catalog_type,
                CONF.network.region or CONF.identity.region,
                endpoint_type=CONF.network.endpoint_type,
                build_interval=CONF.network.build_interval,
                build_timeout=CONF.network.build_timeout,
                **manager.default_params
            )
        )
        cls.sfcgraph_client = (
            sfc_client.ServiceGraphClient(
                manager.auth_provider,
                CONF.network.catalog_type,
                CONF.network.region or CONF.identity.region,
                endpoint_type=CONF.network.endpoint_type,
                build_interval=CONF.network.build_interval,
                build_timeout=CONF.network.build_timeout,
                **manager.default_params
            )
        )

    @classmethod
    def create_port_chain(cls, **kwargs):
        body = cls.portchain_client.create_port_chain(
            **kwargs)
        pc = body['port_chain']
        return pc

    @classmethod
    def create_port_pair_group(cls, **kwargs):
        body = cls.portpairgroup_client.create_port_pair_group(
            **kwargs)
        pg = body['port_pair_group']
        return pg

    @classmethod
    def create_port_pair(cls, **kwargs):
        body = cls.portpair_client.create_port_pair(
            **kwargs)
        pp = body['port_pair']
        return pp

    @classmethod
    def create_service_graph(cls, **kwargs):
        body = cls.sfcgraph_client.create_service_graph(
            **kwargs)
        pc = body['service_graph']
        return pc
