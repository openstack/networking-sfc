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

from tempest import config

from networking_sfc.tests.tempest_plugin.services import flowclassifier_client

CONF = config.CONF


class FlowClassifierClientMixin(object):

    @classmethod
    def resource_setup(cls):
        super(FlowClassifierClientMixin, cls).resource_setup()
        manager = cls.os_admin
        cls.flowclassifier_client = (
            flowclassifier_client.FlowClassifierClient(
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
    def create_flowclassifier(cls, **kwargs):
        body = cls.flowclassifier_client.create_flowclassifier(
            **kwargs)
        fc = body['flow_classifier']
        return fc
