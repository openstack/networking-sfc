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

from neutron.db import api as db_api

from networking_sfc.db import sfc_db
from networking_sfc.extensions import sfc as sfc_ext
from networking_sfc.services.sfc.common import context as sfc_ctx
from networking_sfc.services.sfc.common import exceptions as sfc_exc
from networking_sfc.services.sfc import driver_manager as sfc_driver


LOG = logging.getLogger(__name__)


class SfcPlugin(sfc_db.SfcDbPlugin):
    """SFC plugin implementation."""

    supported_extension_aliases = [sfc_ext.SFC_EXT]
    path_prefix = sfc_ext.SFC_PREFIX

    def __init__(self):
        self.driver_manager = sfc_driver.SfcDriverManager()
        super(SfcPlugin, self).__init__()
        self.driver_manager.initialize()

    @log_helpers.log_method_call
    def create_port_chain(self, context, port_chain):
        with db_api.context_manager.writer.using(context):
            port_chain_db = super(SfcPlugin, self).create_port_chain(
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
    def update_port_chain(self, context, portchain_id, port_chain):
        with db_api.context_manager.writer.using(context):
            original_portchain = self.get_port_chain(context, portchain_id)
            updated_portchain = super(SfcPlugin, self).update_port_chain(
                context, portchain_id, port_chain)
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
    def delete_port_chain(self, context, portchain_id):
        pc = self.get_port_chain(context, portchain_id)
        pc_context = sfc_ctx.PortChainContext(self, context, pc)
        try:
            self.driver_manager.delete_port_chain(pc_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Delete port chain failed, portchain '%s'",
                          portchain_id)

        # TODO(qijing): unsync in case deleted in driver but fail in database
        with db_api.context_manager.writer.using(context):
            pc = self.get_port_chain(context, portchain_id)
            pc_context = sfc_ctx.PortChainContext(self, context, pc)
            super(SfcPlugin, self).delete_port_chain(context, portchain_id)
            self.driver_manager.delete_port_chain_precommit(pc_context)
        self.driver_manager.delete_port_chain_postcommit(pc_context)

    @log_helpers.log_method_call
    def create_port_pair(self, context, port_pair):
        with db_api.context_manager.writer.using(context):
            portpair_db = super(SfcPlugin, self).create_port_pair(
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
    def update_port_pair(self, context, portpair_id, port_pair):
        with db_api.context_manager.writer.using(context):
            original_portpair = self.get_port_pair(context, portpair_id)
            updated_portpair = super(SfcPlugin, self).update_port_pair(
                context, portpair_id, port_pair)
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
    def delete_port_pair(self, context, portpair_id):
        portpair = self.get_port_pair(context, portpair_id)
        portpair_context = sfc_ctx.PortPairContext(
            self, context, portpair)
        try:
            self.driver_manager.delete_port_pair(portpair_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Delete port pair failed, port_pair '%s'",
                          portpair_id)

        with db_api.context_manager.writer.using(context):
            portpair = self.get_port_pair(context, portpair_id)
            portpair_context = sfc_ctx.PortPairContext(
                self, context, portpair)
            super(SfcPlugin, self).delete_port_pair(context, portpair_id)
            self.driver_manager.delete_port_pair_precommit(portpair_context)
        self.driver_manager.delete_port_pair_postcommit(portpair_context)

    @log_helpers.log_method_call
    def create_port_pair_group(self, context, port_pair_group):
        with db_api.context_manager.writer.using(context):
            portpairgroup_db = super(SfcPlugin, self).create_port_pair_group(
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
    def update_port_pair_group(
        self, context, portpairgroup_id, port_pair_group
    ):
        with db_api.context_manager.writer.using(context):
            original_portpairgroup = self.get_port_pair_group(
                context, portpairgroup_id)
            updated_portpairgroup = super(
                SfcPlugin, self).update_port_pair_group(
                context, portpairgroup_id, port_pair_group)
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
    def delete_port_pair_group(self, context, portpairgroup_id):
        portpairgroup = self.get_port_pair_group(context, portpairgroup_id)
        portpairgroup_context = sfc_ctx.PortPairGroupContext(
            self, context, portpairgroup)
        try:
            self.driver_manager.delete_port_pair_group(portpairgroup_context)
        except sfc_exc.SfcDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("Delete port pair group failed, "
                          "port_pair_group '%s'",
                          portpairgroup_id)

        with db_api.context_manager.writer.using(context):
            portpairgroup = self.get_port_pair_group(context, portpairgroup_id)
            portpairgroup_context = sfc_ctx.PortPairGroupContext(
                self, context, portpairgroup)
            super(SfcPlugin, self).delete_port_pair_group(context,
                                                          portpairgroup_id)
            self.driver_manager.delete_port_pair_group_precommit(
                portpairgroup_context)
        self.driver_manager.delete_port_pair_group_postcommit(
            portpairgroup_context)
