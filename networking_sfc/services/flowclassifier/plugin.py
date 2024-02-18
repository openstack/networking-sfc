# Copyright 2015 Futurewei.  All rights reserved.
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
from oslo_log import log as logging
from oslo_utils import excutils

from neutron_lib.db import api as db_api
from neutron_lib.plugins import directory

from networking_sfc.db import flowclassifier_db as fc_db
from networking_sfc.extensions import flowclassifier as fc_ext
from networking_sfc.services.flowclassifier.common import context as fc_ctx
from networking_sfc.services.flowclassifier.common import exceptions as fc_exc
from networking_sfc.services.flowclassifier import driver_manager as fc_driver


LOG = logging.getLogger(__name__)


class FlowClassifierPlugin(fc_db.FlowClassifierDbPlugin):

    """Implementation of the Plugin."""
    supported_extension_aliases = [fc_ext.FLOW_CLASSIFIER_EXT]
    path_prefix = fc_ext.FLOW_CLASSIFIER_PREFIX

    def __init__(self):
        self.driver_manager = fc_driver.FlowClassifierDriverManager()
        super().__init__()
        self.driver_manager.initialize()

    def _get_port(self, context, id):
        port = super()._get_port(context, id)
        return directory.get_plugin().get_port(context, port['id'])

    @log_helpers.log_method_call
    def create_flow_classifier(self, context, flow_classifier):
        with db_api.CONTEXT_WRITER.using(context):
            fc_db = super().create_flow_classifier(
                context, flow_classifier)
            fc_db_context = fc_ctx.FlowClassifierContext(self, context, fc_db)
            self.driver_manager.create_flow_classifier_precommit(
                fc_db_context)

        try:
            self.driver_manager.create_flow_classifier_postcommit(
                fc_db_context)
        except fc_exc.FlowClassifierDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Create flow classifier failed, "
                          "deleting flow_classifier '%s'",
                          fc_db['id'])
                self.delete_flow_classifier(context, fc_db['id'])
        return fc_db

    @log_helpers.log_method_call
    def update_flow_classifier(self, context, id, flow_classifier):
        with db_api.CONTEXT_WRITER.using(context):
            original_flowclassifier = self.get_flow_classifier(context, id)
            updated_fc = super().update_flow_classifier(
                context, id, flow_classifier)
            fc_db_context = fc_ctx.FlowClassifierContext(
                self, context, updated_fc,
                original_flowclassifier=original_flowclassifier)
            self.driver_manager.update_flow_classifier_precommit(fc_db_context)
        try:
            self.driver_manager.update_flow_classifier_postcommit(
                fc_db_context)
        except fc_exc.FlowClassifierDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Update flow classifier failed, "
                          "flow_classifier '%s'",
                          updated_fc['id'])

        return updated_fc

    @log_helpers.log_method_call
    def delete_flow_classifier(self, context, id):
        fc = self.get_flow_classifier(context, id)
        fc_context = fc_ctx.FlowClassifierContext(self, context, fc)
        try:
            self.driver_manager.delete_flow_classifier(fc_context)
        except fc_exc.FlowClassifierDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Delete flow classifier failed, "
                          "flow_classifier '%s'", id)

        with db_api.CONTEXT_WRITER.using(context):
            fc = self.get_flow_classifier(context, id)
            fc_context = fc_ctx.FlowClassifierContext(self, context, fc)
            super().delete_flow_classifier(context, id)
            self.driver_manager.delete_flow_classifier_precommit(fc_context)
        self.driver_manager.delete_flow_classifier_postcommit(fc_context)
