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

from tempest.lib import exceptions as lib_exc
from tempest.lib.services.network import base


class FlowClassifierClient(base.BaseNetworkClient):

    def create_flowclassifier(self, **kwargs):
        uri = '/sfc/flow_classifiers'
        post_data = {'flow_classifier': kwargs}
        return self.create_resource(uri, post_data)

    def update_flowclassifier(self, flowclassifier_id, **kwargs):
        uri = '/sfc/flow_classifiers/%s' % flowclassifier_id
        post_data = {'flow_classifier': kwargs}
        return self.update_resource(uri, post_data)

    def show_flowclassifier(self, flowclassifier_id, **fields):
        uri = '/sfc/flow_classifiers/%s' % flowclassifier_id
        return self.show_resource(uri, **fields)

    def delete_flowclassifier(self, flowclassifier_id):
        uri = '/sfc/flow_classifiers/%s' % flowclassifier_id
        return self.delete_resource(uri)

    def list_flowclassifiers(self, **filters):
        uri = '/sfc/flow_classifiers'
        return self.list_resources(uri, **filters)

    def is_resource_deleted(self, id):
        try:
            self.show_flowclassifier(id)
        except lib_exc.NotFound:
            return True
        return False

    @property
    def resource_type(self):
        """Returns the primary type of resource this client works with."""
        return 'flow_classifier'
