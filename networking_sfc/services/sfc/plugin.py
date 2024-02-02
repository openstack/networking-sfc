# Copyright 2015 Futurewei. All rights reserved.
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

from networking_sfc.db import sfc_db
from networking_sfc.extensions import servicegraph as sg_ext
from networking_sfc.extensions import sfc as sfc_ext
from networking_sfc.extensions import tap as tap_ext
from networking_sfc.services.sfc.common import context as sfc_ctx
from networking_sfc.services.sfc.common import exceptions as sfc_exc
from networking_sfc.services.sfc import driver_manager as sfc_driver


LOG = logging.getLogger(__name__)


class SfcPlugin(sfc_db.SfcDbPlugin):
    """SFC plugin implementation."""

    # REVISIT(vks1) This should be changed to string instead of importing
    # extensions explicitly. So that even if extensions increase in future,
    # imports do not.
    supported_extension_aliases = [sfc_ext.SFC_EXT, sg_ext.SG_EXT,
                                   tap_ext.TAP_EXT]
    path_prefix = sfc_ext.SFC_PREFIX

    def __init__(self):
        self.driver_manager = sfc_driver.SfcDriverManager()
        super().__init__()
        self.driver_manager.initialize()

    @log_helpers.log_method_call
    def create_port_chain(self, context, port_chain):
        with db_api.CONTEXT_WRITER.using(context):
            port_chain_db = super().create_port_chain(
                context, port_chain)
            portchain_db_context = sfc_ctx.PortChainContext(
                self, context, port_chain_db)
            self.driver_manager.create_port_chain_precommit(
                portchain_db_context)
        try:
            self.driver_manager.create_port_chain_postcommit(
                portchain_db_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Create port chain failed, "
                          "deleting port_chain '%s'",
                          port_chain_db['id'])
                self.delete_port_chain(context, port_chain_db['id'])

        return port_chain_db

    @log_helpers.log_method_call
    def update_port_chain(self, context, id, port_chain):
        with db_api.CONTEXT_WRITER.using(context):
            original_portchain = self.get_port_chain(context, id)
            updated_portchain = super().update_port_chain(
                context, id, port_chain)
            portchain_db_context = sfc_ctx.PortChainContext(
                self, context, updated_portchain,
                original_portchain=original_portchain)
            self.driver_manager.update_port_chain_precommit(
                portchain_db_context)

        try:
            self.driver_manager.update_port_chain_postcommit(
                portchain_db_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Update port chain failed, port_chain '%s'",
                          updated_portchain['id'])

        # TODO(qijing): should we rollback the database update here?
        return updated_portchain

    @log_helpers.log_method_call
    def delete_port_chain(self, context, id):
        pc = self.get_port_chain(context, id)
        pc_context = sfc_ctx.PortChainContext(self, context, pc)
        try:
            self.driver_manager.delete_port_chain(pc_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Delete port chain failed, portchain '%s'", id)

        # TODO(qijing): unsync in case deleted in driver but fail in database
        with db_api.CONTEXT_WRITER.using(context):
            pc = self.get_port_chain(context, id)
            pc_context = sfc_ctx.PortChainContext(self, context, pc)
            super().delete_port_chain(context, id)
            self.driver_manager.delete_port_chain_precommit(pc_context)
        self.driver_manager.delete_port_chain_postcommit(pc_context)

    @log_helpers.log_method_call
    def create_port_pair(self, context, port_pair):
        with db_api.CONTEXT_WRITER.using(context):
            portpair_db = super().create_port_pair(
                context, port_pair)
            portpair_context = sfc_ctx.PortPairContext(
                self, context, portpair_db)
            self.driver_manager.create_port_pair_precommit(portpair_context)

        try:
            self.driver_manager.create_port_pair_postcommit(portpair_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Create port pair failed, "
                          "deleting port_pair '%s'",
                          portpair_db['id'])
                self.delete_port_pair(context, portpair_db['id'])

        return portpair_db

    @log_helpers.log_method_call
    def update_port_pair(self, context, id, port_pair):
        with db_api.CONTEXT_WRITER.using(context):
            original_portpair = self.get_port_pair(context, id)
            updated_portpair = super().update_port_pair(
                context, id, port_pair)
            portpair_context = sfc_ctx.PortPairContext(
                self, context, updated_portpair,
                original_portpair=original_portpair)
            self.driver_manager.update_port_pair_precommit(portpair_context)
        try:
            self.driver_manager.update_port_pair_postcommit(portpair_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Update port pair failed, port_pair '%s'",
                          updated_portpair['id'])

        return updated_portpair

    @log_helpers.log_method_call
    def delete_port_pair(self, context, id):
        portpair = self.get_port_pair(context, id)
        portpair_context = sfc_ctx.PortPairContext(
            self, context, portpair)
        try:
            self.driver_manager.delete_port_pair(portpair_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Delete port pair failed, port_pair '%s'", id)

        with db_api.CONTEXT_WRITER.using(context):
            portpair = self.get_port_pair(context, id)
            portpair_context = sfc_ctx.PortPairContext(
                self, context, portpair)
            super().delete_port_pair(context, id)
            self.driver_manager.delete_port_pair_precommit(portpair_context)
        self.driver_manager.delete_port_pair_postcommit(portpair_context)

    @log_helpers.log_method_call
    def create_port_pair_group(self, context, port_pair_group):
        with db_api.CONTEXT_WRITER.using(context):
            portpairgroup_db = super().create_port_pair_group(
                context, port_pair_group)
            portpairgroup_context = sfc_ctx.PortPairGroupContext(
                self, context, portpairgroup_db)
            self.driver_manager.create_port_pair_group_precommit(
                portpairgroup_context)
        try:
            self.driver_manager.create_port_pair_group_postcommit(
                portpairgroup_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Create port pair group failed, "
                          "deleting port_pair_group '%s'",
                          portpairgroup_db['id'])
                self.delete_port_pair_group(context, portpairgroup_db['id'])

        return portpairgroup_db

    @log_helpers.log_method_call
    def update_port_pair_group(self, context, id, port_pair_group):
        with db_api.CONTEXT_WRITER.using(context):
            original_portpairgroup = self.get_port_pair_group(
                context, id)
            updated_portpairgroup = super().update_port_pair_group(
                context, id, port_pair_group)
            portpairgroup_context = sfc_ctx.PortPairGroupContext(
                self, context, updated_portpairgroup,
                original_portpairgroup=original_portpairgroup)
            self.driver_manager.update_port_pair_group_precommit(
                portpairgroup_context)
        try:
            self.driver_manager.update_port_pair_group_postcommit(
                portpairgroup_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Update port pair group failed, "
                          "port_pair_group '%s'",
                          updated_portpairgroup['id'])

        return updated_portpairgroup

    @log_helpers.log_method_call
    def delete_port_pair_group(self, context, id):
        portpairgroup = self.get_port_pair_group(context, id)
        portpairgroup_context = sfc_ctx.PortPairGroupContext(
            self, context, portpairgroup)
        try:
            self.driver_manager.delete_port_pair_group(portpairgroup_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Delete port pair group failed, "
                          "port_pair_group '%s'",
                          id)

        with db_api.CONTEXT_WRITER.using(context):
            portpairgroup = self.get_port_pair_group(context, id)
            portpairgroup_context = sfc_ctx.PortPairGroupContext(
                self, context, portpairgroup)
            super().delete_port_pair_group(context, id)
            self.driver_manager.delete_port_pair_group_precommit(
                portpairgroup_context)
        self.driver_manager.delete_port_pair_group_postcommit(
            portpairgroup_context)

    @log_helpers.log_method_call
    def create_service_graph(self, context, service_graph):
        with db_api.CONTEXT_WRITER.using(context):
            service_graph_db = super().create_service_graph(
                context, service_graph)
            service_graph_db_context = sfc_ctx.ServiceGraphContext(
                self, context, service_graph_db)
            self.driver_manager.create_service_graph_precommit(
                service_graph_db_context)
        try:
            self.driver_manager.create_service_graph_postcommit(
                service_graph_db_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Create Service Graph failed, "
                          "deleting Service Graph '%s'",
                          service_graph_db['id'])
                self.delete_service_graph(context, service_graph_db['id'])

        return service_graph_db

    @log_helpers.log_method_call
    def update_service_graph(self, context, id, service_graph):
        with db_api.CONTEXT_WRITER.using(context):
            original_graph = self.get_service_graph(context, id)
            updated_graph = super().update_service_graph(
                context, id, service_graph)
            service_graph_db_context = sfc_ctx.ServiceGraphContext(
                self, context, updated_graph,
                original_graph=original_graph)
            self.driver_manager.update_service_graph_precommit(
                service_graph_db_context)
        try:
            self.driver_manager.update_service_graph_postcommit(
                service_graph_db_context)
        except sfc_exc.SfcDriverError:
            with excutils.save_and_reraise_exception():
                LOG.error("Update failed, service_graph '%s'",
                          updated_graph['id'])
        return updated_graph

    @log_helpers.log_method_call
    def delete_service_graph(self, context, id):
        graph = self.get_service_graph(context, id)
        graph_context = sfc_ctx.ServiceGraphContext(self, context, graph)
        with db_api.CONTEXT_WRITER.using(context):
            graph = self.get_service_graph(context, id)
            graph_context = sfc_ctx.ServiceGraphContext(self, context, graph)
            super().delete_service_graph(context, id)
            self.driver_manager.delete_service_graph_precommit(graph_context)
        try:
            self.driver_manager.delete_service_graph_postcommit(graph_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Delete failed, service_graph '%s'", id)
