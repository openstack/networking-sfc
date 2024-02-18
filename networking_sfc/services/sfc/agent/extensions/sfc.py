# Copyright 2016 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import abc

from neutron.agent import rpc as agent_rpc
from neutron import manager
from neutron_lib.agent import l2_extension
from neutron_lib.agent import topics
from neutron_lib import rpc as n_rpc
from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging

from networking_sfc.services.sfc.drivers.ovs import rpc_topics as sfc_topics

LOG = logging.getLogger(__name__)


class SfcPluginApi():
    def __init__(self, topic, host):
        self.host = host
        self.target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(self.target)

    def update_flowrules_status(self, context, flowrules_status):
        cctxt = self.client.prepare()
        return cctxt.call(
            context, 'update_flowrules_status',
            flowrules_status=flowrules_status)

    def get_flowrules_by_host_portid(self, context, port_id):
        cctxt = self.client.prepare()
        return cctxt.call(
            context, 'get_flowrules_by_host_portid',
            host=self.host, port_id=port_id)


class SfcAgentDriver(metaclass=abc.ABCMeta):
    """Defines stable abstract interface for SFC Agent Driver."""

    @abc.abstractmethod
    def initialize(self):
        """Perform SFC agent driver initialization."""

    def consume_api(self, agent_api):
        """Consume the AgentAPI instance from the SfcAgentExtension class

        :param agent_api: An instance of an agent specific API
        """

    def update_flow_rules(self, flowrule, flowrule_status):
        """Update a flow rule in driver."""

    def delete_flow_rule(self, flowrule, flowrule_status):
        """Delete a flow rule in driver."""


class SfcAgentExtension(l2_extension.L2AgentExtension):

    def initialize(self, connection, driver_type):
        """Initialize agent extension."""
        self.sfc_driver = manager.NeutronManager.load_class_for_provider(
            'networking_sfc.sfc.agent_drivers', driver_type)()
        self.sfc_driver.consume_api(self.agent_api)
        self.sfc_driver.initialize()

        self._sfc_setup_rpc()

    def consume_api(self, agent_api):
        """Receive neutron agent API object

        Allows an extension to gain access to resources internal to the
        neutron agent and otherwise unavailable to the extension.
        """
        self.agent_api = agent_api

    def handle_port(self, context, data):
        """Handle agent SFC extension port add/update."""
        port_id = data['port_id']
        resync = False
        flowrule_status = []
        try:
            LOG.debug("a new device %s is found", port_id)
            flows_list = (
                self.sfc_plugin_rpc.get_flowrules_by_host_portid(
                    context, port_id
                )
            )
            if flows_list:
                for flow in flows_list:
                    self.sfc_driver.update_flow_rules(
                        flow, flowrule_status)
        except Exception as e:
            LOG.exception(e)
            LOG.error("SFC L2 extension handle_port failed")
            resync = True

        if flowrule_status:
            self.sfc_plugin_rpc.update_flowrules_status(
                context, flowrule_status)

        return resync

    def delete_port(self, context, data):
        """Handle agent SFC extension port delete."""
        port_id = data['port_id']
        resync = False
        LOG.info("a device %s is removed", port_id)
        try:
            self._delete_ports_flowrules_by_id(context, port_id)
        except Exception as e:
            LOG.exception(e)
            LOG.error(
                "delete port flow rule failed for %(port_id)s",
                {'port_id': port_id}
            )
            resync = True

        return resync

    def update_flow_rules(self, context, **kwargs):
        flowrule_status = []
        try:
            flowrules = kwargs['flowrule_entries']
            LOG.debug("update_flow_rules received,  flowrules = %s",
                      flowrules)

            if flowrules:
                self.sfc_driver.update_flow_rules(
                    flowrules, flowrule_status)
        except Exception as e:
            LOG.exception(e)
            LOG.error("update_flow_rules failed")

        if flowrule_status:
            self.sfc_plugin_rpc.update_flowrules_status(
                context, flowrule_status)

    def delete_flow_rules(self, context, **kwargs):
        flowrule_status = []
        try:
            flowrules = kwargs['flowrule_entries']
            LOG.debug("delete_flow_rules received,  flowrules= %s", flowrules)
            if flowrules:
                self.sfc_driver.delete_flow_rule(
                    flowrules, flowrule_status)
        except Exception as e:
            LOG.exception(e)
            LOG.error("delete_flow_rules failed")

        if flowrule_status:
            self.sfc_plugin_rpc.update_flowrules_status(
                context, flowrule_status)

    def _sfc_setup_rpc(self):
        self.sfc_plugin_rpc = SfcPluginApi(
            sfc_topics.SFC_PLUGIN, cfg.CONF.host)

        self.topic = sfc_topics.SFC_AGENT
        self.endpoints = [self]
        consumers = [
            [sfc_topics.PORTFLOW, topics.UPDATE],
            [sfc_topics.PORTFLOW, topics.DELETE]
        ]

        # subscribe sfc plugin message
        self.connection = agent_rpc.create_consumers(
            self.endpoints,
            self.topic,
            consumers)

    def _delete_ports_flowrules_by_id(self, context, ports_id):
        flowrule_status = []
        try:
            LOG.debug("delete_port_id_flows received, ports_id= %s", ports_id)
            count = 0
            if ports_id:
                for port_id in ports_id:
                    flowrule = (
                        self.sfc_plugin_rpc.get_flowrules_by_host_portid(
                            context, port_id
                        )
                    )
                    if flowrule:
                        self.sfc.driver.delete_flow_rule(
                            flowrule, flowrule_status)
            LOG.debug(
                "_delete_ports_flowrules_by_id received, count= %s", count)
        except Exception as e:
            LOG.exception(e)
            LOG.error("delete_port_id_flows failed")
        if flowrule_status:
            self.sfc_plugin_rpc.update_flowrules_status(
                context, flowrule_status)
