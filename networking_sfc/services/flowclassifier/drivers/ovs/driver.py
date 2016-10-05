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

from oslo_log import helpers as log_helpers

from networking_sfc.services.flowclassifier.common import exceptions as exc
from networking_sfc.services.flowclassifier.drivers import base as fc_driver


class OVSFlowClassifierDriver(fc_driver.FlowClassifierDriverBase):
    """FlowClassifier Driver Base Class."""

    def initialize(self):
        pass

    @log_helpers.log_method_call
    def create_flow_classifier(self, context):
        pass

    @log_helpers.log_method_call
    def update_flow_classifier(self, context):
        pass

    @log_helpers.log_method_call
    def delete_flow_classifier(self, context):
        pass

    @log_helpers.log_method_call
    def create_flow_classifier_precommit(self, context):
        """OVS Driver precommit before transaction committed.

        Make sure the logical_source_port is not None.
        """
        flow_classifier = context.current
        logical_source_port = flow_classifier['logical_source_port']
        if logical_source_port is None:
            raise exc.FlowClassifierBadRequest(message=(
                'FlowClassifier %s does not set '
                'logical source port in ovs driver' % flow_classifier['id']))
