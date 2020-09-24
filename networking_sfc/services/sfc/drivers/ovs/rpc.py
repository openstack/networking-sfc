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
from oslo_log import log as logging

import oslo_messaging

from neutron_lib.agent import topics
from neutron_lib import rpc as n_rpc

from networking_sfc.services.sfc.drivers.ovs import rpc_topics as sfc_topics

LOG = logging.getLogger(__name__)


class SfcRpcCallback():
    """Sfc RPC server."""

    def __init__(self, driver):
        self.target = oslo_messaging.Target(version='1.0')
        self.driver = driver

    def get_flowrules_by_host_portid(self, context, **kwargs):
        host = kwargs.get('host')
        port_id = kwargs.get('port_id')
        LOG.debug('from port-chain service plugin')
        pcfrs = self.driver.get_flowrules_by_host_portid(
            context, host, port_id)
        LOG.debug('host: %s, port_id: %s', host, port_id)
        return pcfrs

    def update_flowrules_status(self, context, **kwargs):
        flowrules_status = kwargs.get('flowrules_status')
        LOG.info('update_flowrules_status: %s', flowrules_status)
        for flowrule_dict in flowrules_status:
            self.driver.update_flowrule_status(context,
                                               flowrule_dict['id'],
                                               flowrule_dict['status'])


class SfcAgentRpcClient():
    """RPC client for ovs sfc agent."""

    def __init__(self, topic=sfc_topics.SFC_AGENT):
        self.topic = topic
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def ask_agent_to_update_flow_rules(self, context, flow_rule):
        LOG.debug('Ask agent on the specific host to update flows ')
        LOG.debug('flow_rule: %s', flow_rule)
        host = flow_rule.get('host')
        cctxt = self.client.prepare(
            topic=topics.get_topic_name(
                self.topic, sfc_topics.PORTFLOW, topics.UPDATE),
            server=host)
        cctxt.cast(context, 'update_flow_rules', flowrule_entries=flow_rule)

    def ask_agent_to_delete_flow_rules(self, context, flow_rule):
        LOG.debug('Ask agent on the specific host to delete flows ')
        LOG.debug('flow_rule: %s', flow_rule)
        host = flow_rule.get('host')
        cctxt = self.client.prepare(
            topic=topics.get_topic_name(
                self.topic, sfc_topics.PORTFLOW, topics.DELETE),
            server=host)
        cctxt.cast(context, 'delete_flow_rules', flowrule_entries=flow_rule)
