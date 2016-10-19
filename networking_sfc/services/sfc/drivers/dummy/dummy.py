# Copyright 2017 Futurewei. All rights reserved.
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

from oslo_log import helpers as log_helpers

from networking_sfc.services.sfc.drivers import base as sfc_driver


class DummyDriver(sfc_driver.SfcDriverBase):
    """SFC Driver Dummy Class."""
    def initialize(self):
        pass

    @log_helpers.log_method_call
    def create_port_chain(self, context):
        pass

    @log_helpers.log_method_call
    def delete_port_chain(self, context):
        pass

    @log_helpers.log_method_call
    def update_port_chain(self, context):
        pass

    @log_helpers.log_method_call
    def create_port_chain_precommit(self, context):
        pass

    @log_helpers.log_method_call
    def create_port_pair_group(self, context):
        pass

    @log_helpers.log_method_call
    def delete_port_pair_group(self, context):
        pass

    @log_helpers.log_method_call
    def update_port_pair_group(self, context):
        pass

    @log_helpers.log_method_call
    def create_port_pair(self, context):
        pass

    @log_helpers.log_method_call
    def delete_port_pair(self, context):
        pass

    @log_helpers.log_method_call
    def update_port_pair(self, context):
        pass

    @log_helpers.log_method_call
    def create_service_graph_precommit(self, context):
        pass

    @log_helpers.log_method_call
    def create_service_graph_postcommit(self, context):
        pass

    @log_helpers.log_method_call
    def update_service_graph_precommit(self, context):
        pass

    @log_helpers.log_method_call
    def update_service_graph_postcommit(self, context):
        pass

    @log_helpers.log_method_call
    def delete_service_graph_precommit(self, context):
        pass

    @log_helpers.log_method_call
    def delete_service_graph_postcommit(self, context):
        pass
