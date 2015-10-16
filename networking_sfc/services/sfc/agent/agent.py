# Copyright 2015 Huawei.  All rights reserved.
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

import signal
import six
import sys

from neutron.agent.common import config
from neutron.agent.linux import ip_lib

from networking_sfc.services.sfc.agent import br_int
from networking_sfc.services.sfc.agent import br_phys
from networking_sfc.services.sfc.agent import br_tun
from networking_sfc.services.sfc.common import ovs_ext_lib
from networking_sfc.services.sfc.drivers.ovs import constants
from networking_sfc.services.sfc.drivers.ovs import rpc_topics as sfc_topics

from neutron.agent import rpc as agent_rpc
from neutron.common import config as common_config
from neutron.common import constants as n_const
from neutron.common import exceptions
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron.common import utils as q_utils
from neutron.i18n import _LE
from neutron.i18n import _LI
from neutron.i18n import _LW
from neutron.plugins.ml2.drivers.openvswitch.agent.common import (
    constants as ovs_const)
from neutron.plugins.ml2.drivers.openvswitch.agent import ovs_neutron_agent

from oslo_config import cfg
from oslo_log import log as logging
import oslo_messaging


LOG = logging.getLogger(__name__)

agent_opts = [
    cfg.StrOpt('sfc_encap_mode', default='mpls',
               help=_("The encapsulation mode of sfc.")),
]

cfg.CONF.register_opts(agent_opts, "AGENT")

# This table is used to process the traffic across differet subnet scenario.
# Flow 1: pri=1, ip,dl_dst=nexthop_mac,nw_src=nexthop_subnet. actions=
# push_mpls:0x8847,set_mpls_label,set_mpls_ttl,push_vlan,output:(patch port
# or resubmit to table(INGRESS_TABLE)
# Flow 2: pri=0, ip,dl_dst=nexthop_mac,, action=push_mpls:0x8847,
# set_mpls_label,set_mpls_ttl,push_vlan,output:(patch port or resubmit to
# table(INGRESS_TABLE)
ACROSS_SUBNET_TABLE = 5

# The table has multiple flows that steer traffic for the different chains
# to the ingress port of different service functions hosted on this Compute
# node.
INGRESS_TABLE = 10

# port chain default flow rule priority
PC_DEF_PRI = 20
PC_INGRESS_PRI = 30


class FeatureSupportError(exceptions.NeutronException):
    message = _("Current sfc agent don't support %(feature)s ")


class SfcPluginApi(object):
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

    def get_all_src_node_flowrules(self, context):
        cctxt = self.client.prepare()
        return cctxt.call(
            context, 'get_all_src_node_flowrules',
            host=self.host)


class OVSSfcAgent(ovs_neutron_agent.OVSNeutronAgent):
    # history
    # 1.0 Initial version
    """This class will support MPLS frame

    Ethernet + MPLS
    IPv4 Packet:
    +-------------------------------+---------------+--------------------+
    |Outer Ethernet, ET=0x8847      | MPLS head,    | original IP Packet |
    +-------------------------------+---------------+--------------------+
    """

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, bridge_classes, integ_br, tun_br, local_ip,
                 bridge_mappings, polling_interval, tunnel_types=None,
                 veth_mtu=None, l2_population=False,
                 enable_distributed_routing=False,
                 minimize_polling=False,
                 ovsdb_monitor_respawn_interval=(
                     ovs_const.DEFAULT_OVSDBMON_RESPAWN),
                 arp_responder=False,
                 prevent_arp_spoofing=True,
                 use_veth_interconnection=False,
                 quitting_rpc_timeout=None):

        """to get network info from ovs agent."""
        super(OVSSfcAgent, self).__init__(
            bridge_classes, integ_br, tun_br,
            local_ip,
            bridge_mappings, polling_interval, tunnel_types,
            veth_mtu, l2_population,
            enable_distributed_routing,
            minimize_polling,
            ovsdb_monitor_respawn_interval,
            arp_responder,
            prevent_arp_spoofing,
            use_veth_interconnection,
            quitting_rpc_timeout)

        self.overlay_encap_mode = cfg.CONF.AGENT.sfc_encap_mode
        self._sfc_setup_rpc()

        if self.overlay_encap_mode == 'eth_nsh':
            raise FeatureSupportError(feature=self.overlay_encap_mode)
        elif self.overlay_encap_mode == 'vxlan_nsh':
            raise FeatureSupportError(feature=self.overlay_encap_mode)
        elif self.overlay_encap_mode == 'mpls':
            self._clear_sfc_flow_on_int_br()
            self._setup_src_node_flow_rules_with_mpls()

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

    def _parse_flow_classifier(self, flow_classifier):
        dl_type, nw_proto, source_port_masks, destination_port_masks = (
            (None, ) * 4)

        if (
            not flow_classifier['source_port_range_min'] and
            not flow_classifier['source_port_range_max']
        ):
            # wildcard
            source_port_masks = ['0/0x0']
        elif not flow_classifier['source_port_range_min']:
            source_port_masks = ovs_ext_lib.get_port_mask(
                1,
                flow_classifier['source_port_range_max'])
        elif not flow_classifier['source_port_range_max']:
            source_port_masks = ovs_ext_lib.get_port_mask(
                flow_classifier['source_port_range_min'],
                65535)
        else:
            source_port_masks = ovs_ext_lib.get_port_mask(
                flow_classifier['source_port_range_min'],
                flow_classifier['source_port_range_max'])

        if (
            not flow_classifier['destination_port_range_min'] and
            not flow_classifier['destination_port_range_max']
        ):
            # wildcard
            destination_port_masks = ['0/0x0']
        elif not flow_classifier['destination_port_range_min']:
            destination_port_masks = ovs_ext_lib.get_port_mask(
                1,
                flow_classifier['destination_port_range_max'])
        elif not flow_classifier['destination_port_range_max']:
            destination_port_masks = ovs_ext_lib.get_port_mask(
                flow_classifier['destination_port_range_min'],
                65535)
        else:
            destination_port_masks = ovs_ext_lib.get_port_mask(
                flow_classifier['destination_port_range_min'],
                flow_classifier['destination_port_range_max'])

        if "IPv4" == flow_classifier['ethertype']:
            dl_type = 0x0800
            if n_const.PROTO_NAME_TCP == flow_classifier['protocol']:
                nw_proto = n_const.PROTO_NUM_TCP
            elif n_const.PROTO_NAME_UDP == flow_classifier['protocol']:
                nw_proto = n_const.PROTO_NUM_UDP
            elif n_const.PROTO_NAME_ICMP == flow_classifier['protocol']:
                nw_proto = n_const.PROTO_NUM_ICMP
            else:
                nw_proto = None
        elif "IPv6" == flow_classifier['ethertype']:
            LOG.error(_LE("Current portchain agent don't support Ipv6"))
        else:
            LOG.error(_LE("invalid protocol input"))
        return (dl_type, nw_proto,
                source_port_masks, destination_port_masks
                )

    def _clear_sfc_flow_on_int_br(self):
        self.int_br.delete_group(group_id='all')
        self.int_br.delete_flows(table=ACROSS_SUBNET_TABLE)
        self.int_br.delete_flows(table=INGRESS_TABLE)
        self.int_br.install_goto(dest_table_id=INGRESS_TABLE,
                                 priority=PC_DEF_PRI,
                                 dl_type=0x8847)
        self.int_br.install_drop(table_id=INGRESS_TABLE)

    def _get_flow_infos_from_flow_classifier(self, flow_classifier):
        flow_infos = []
        nw_src, nw_dst = ((None, ) * 2)

        if "IPv4" != flow_classifier['ethertype']:
            LOG.error(_LE("Current portchain agent don't support Ipv6"))
            return flow_infos

        # parse and transfer flow info to match field info
        dl_type, nw_proto, source_port_masks, destination_port_masks = (
            self._parse_flow_classifier(flow_classifier))

        if flow_classifier['source_ip_prefix']:
            nw_src = flow_classifier['source_ip_prefix']
        else:
            nw_src = '0.0.0.0/0.0.0.0'
        if flow_classifier['destination_ip_prefix']:
            nw_dst = flow_classifier['destination_ip_prefix']
        else:
            nw_dst = '0.0.0.0/0.0.0.0'

        if source_port_masks and destination_port_masks:
            for destination_port in destination_port_masks:
                for source_port in source_port_masks:
                    if nw_proto is None:
                        flow_infos.append(dict(
                            dl_type=dl_type,
                            nw_src=nw_src,
                            nw_dst=nw_dst,
                            tp_src='%s' % source_port,
                            tp_dst='%s' % destination_port
                        ))
                    else:
                        flow_infos.append(dict(
                            dl_type=dl_type,
                            nw_proto=nw_proto,
                            nw_src=nw_src,
                            nw_dst=nw_dst,
                            tp_src='%s' % source_port,
                            tp_dst='%s' % destination_port
                        ))

        return flow_infos

    def _get_flow_infos_from_flow_classifier_list(self, flow_classifier_list):
        flow_infos = []
        if not flow_classifier_list:
            return flow_infos
        for flow_classifier in flow_classifier_list:
            flow_infos.extend(
                self._get_flow_infos_from_flow_classifier(flow_classifier)
            )

        return flow_infos

    def _setup_local_switch_flows_on_int_br(
        self, flowrule, flow_classifier_list,
        actions, add_flow=True, match_inport=True
    ):
        inport_match = {}
        priority = PC_DEF_PRI

        if match_inport is True:
            egress_port = self.int_br.get_vif_port_by_id(flowrule['egress'])
            if egress_port:
                inport_match = dict(in_port=egress_port.ofport)
                priority = PC_INGRESS_PRI

        for flow_info in self._get_flow_infos_from_flow_classifier_list(
            flow_classifier_list
        ):
            match_info = dict(inport_match, **flow_info)
            if add_flow:
                self.int_br.add_flow(
                    table=ovs_const.LOCAL_SWITCHING,
                    priority=priority,
                    actions=actions, **match_info
                )
            else:
                self.int_br.delete_flows(
                    table=ovs_const.LOCAL_SWITCHING,
                    **match_info
                )

    def _update_destination_ingress_flow_rules(self, flowrule):
        for flow_info in self._get_flow_infos_from_flow_classifier_list(
            flowrule['del_fcs']
        ):
            self.int_br.delete_flows(
                table=ovs_const.LOCAL_SWITCHING,
                in_port=self.patch_tun_ofport,
                **flow_info
            )
        for flow_info in self._get_flow_infos_from_flow_classifier_list(
            flowrule['add_fcs']
        ):
            inport_match = dict(in_port=self.patch_tun_ofport)
            match_info = dict(inport_match, **flow_info)
            self.int_br.install_normal(table_id=ovs_const.LOCAL_SWITCHING,
                                       priority=PC_INGRESS_PRI,
                                       **match_info)

    def _setup_src_node_flow_rules_with_mpls(self):
        flow_rules = self.sfc_plugin_rpc.get_all_src_node_flowrules(
            self.context)
        if not flow_rules:
            return
        for fr in flow_rules:
            self._setup_egress_flow_rules_with_mpls(fr, False)
            # if the traffic is from patch port, it means the destination
            # is on the this host. so implement normal forward but not
            # match the traffic from the source.
            # Next step need to do is check if the traffic is from vRouter
            # on the local host, also need to implement same normal process.
            self._update_destination_ingress_flow_rules(fr)

    def _setup_egress_flow_rules_with_mpls(self, flowrule, match_inport=True):
        group_id = flowrule.get('next_group_id', None)
        next_hops = flowrule.get('next_hops', None)

        if not next_hops:
            return
        # if the group is not none, install the egress rule for this SF
        if (
            (flowrule['node_type'] == constants.SRC_NODE or
             flowrule['node_type'] == constants.SF_NODE) and group_id
        ):
            # 1st, install br-int flow rule on table ACROSS_SUBNET_TABLE
            # and group table
            buckets = []
            for item in next_hops:
                if item['net_uuid'] not in self.local_vlan_map:
                    self.provision_local_vlan(item['net_uuid'],
                                              item['network_type'],
                                              None, item['segment_id'])
                lvm = self.local_vlan_map[item['net_uuid']]
                bucket = (
                    'bucket=weight=%d, mod_dl_dst:%s,'
                    'resubmit(,%d)' % (
                        item['weight'],
                        item['mac_address'],
                        ACROSS_SUBNET_TABLE
                    )
                )
                buckets.append(bucket)

                no_across_subnet_actions_list = []
                across_subnet_actions_list = []

                push_mpls = (
                    "push_mpls:0x8847,"
                    "set_mpls_label:%d,"
                    "set_mpls_ttl:%d,"
                    "mod_vlan_vid:%d," %
                    ((flowrule['nsp'] << 8) | flowrule['nsi'],
                     flowrule['nsi'], lvm.vlan))

                no_across_subnet_actions_list.append(push_mpls)
                across_subnet_actions_list.append(push_mpls)

                if item['local_endpoint'] == self.local_ip:
                    no_across_subnet_actions = (
                        "resubmit(,%d)" % INGRESS_TABLE)
                    across_subnet_actions = (
                        "mod_dl_src:%s, resubmit(,%d)" %
                        (item['gw_mac'], INGRESS_TABLE))
                else:
                    # same subnet with next hop
                    no_across_subnet_actions = ("output:%s" %
                                                self.patch_tun_ofport)
                    across_subnet_actions = ("mod_dl_src:%s, output:%s" %
                                             (item['gw_mac'],
                                              self.patch_tun_ofport))
                no_across_subnet_actions_list.append(no_across_subnet_actions)
                across_subnet_actions_list.append(across_subnet_actions)

                self.int_br.add_flow(
                    table=ACROSS_SUBNET_TABLE,
                    priority=1,
                    dl_dst=item['mac_address'],
                    dl_type=0x0800,
                    nw_src=item['cidr'],
                    actions="%s" %
                            (','.join(no_across_subnet_actions_list)))
                # different subnet with next hop
                self.int_br.add_flow(
                    table=ACROSS_SUBNET_TABLE,
                    priority=0,
                    dl_dst=item['mac_address'],
                    actions="%s" %
                            (','.join(across_subnet_actions_list)))

            buckets = ','.join(buckets)
            group_content = self.int_br.dump_group_for_id(group_id)
            if group_content.find('group_id=%d' % group_id) == -1:
                self.int_br.add_group(group_id=group_id,
                                      type='select', buckets=buckets)
            else:
                self.int_br.mod_group(group_id=group_id,
                                      type='select', buckets=buckets)

            # 2nd, install br-int flow rule on table 0  for egress traffic
            # for egress traffic
            enc_actions = ("group:%d" % group_id)
            # to uninstall the removed flow classifiers
            self._setup_local_switch_flows_on_int_br(
                flowrule,
                flowrule['del_fcs'],
                None,
                add_flow=False,
                match_inport=match_inport)
            # to install the added flow classifiers
            self._setup_local_switch_flows_on_int_br(
                flowrule,
                flowrule['add_fcs'],
                enc_actions,
                add_flow=True,
                match_inport=match_inport)

    def _get_network_by_port(self, port_id):
        for key, val in six.iteritems(self.network_ports):
            if port_id in val:
                return key

        return None

    def _setup_ingress_flow_rules_with_mpls(self, flowrule):
        network_id = self._get_network_by_port(flowrule['ingress'])
        if network_id:
            # install br-int flow rule on table 0 for ingress traffic
            lvm = self.local_vlan_map[network_id]
            vif_port = lvm.vif_ports[flowrule['ingress']]
            match_field = {}

            actions = ("strip_vlan, pop_mpls:0x0800,"
                       "output:%s" % vif_port.ofport)
            match_field = dict(
                table=INGRESS_TABLE,
                priority=1,
                dl_dst=vif_port.vif_mac,
                dl_vlan=lvm.vlan,
                dl_type=0x8847,
                mpls_label=flowrule['nsp'] << 8 | (flowrule['nsi'] + 1),
                actions=actions)

            self.int_br.add_flow(**match_field)

    def _setup_last_egress_flow_rules_with_mpls(self, flowrule):
        group_id = flowrule.get('next_group_id', None)

        # check whether user assign the destination neutron port.
        if (
            constants.SF_NODE == flowrule['node_type'] and
            not group_id and
            flowrule['egress'] is not None
        ):
            # to uninstall the new removed flow classifiers
            self._setup_local_switch_flows_on_int_br(
                flowrule,
                flowrule['del_fcs'],
                None,
                add_flow=False,
                match_inport=True
            )

            # to install the added flow classifiers
            self._setup_local_switch_flows_on_int_br(
                flowrule,
                flowrule['add_fcs'],
                actions='normal',
                add_flow=True,
                match_inport=True)

    def _get_flow_classifier_dest_port_info(self,
                                            logical_destination_port,
                                            flowrule):
        for next_hop in flowrule['next_hops']:
            # this flow classifier's destination port should match
            # with the nexthop's ingress port id
            if logical_destination_port in next_hop.values():
                return next_hop

        return None

    def _update_flow_rules_with_mpls_enc(self, flowrule, flowrule_status):
        try:
            if flowrule.get('egress', None):
                self._setup_egress_flow_rules_with_mpls(flowrule)
                self._setup_last_egress_flow_rules_with_mpls(flowrule)
            if flowrule.get('ingress', None):
                self._setup_ingress_flow_rules_with_mpls(flowrule)

            flowrule_status_temp = {}
            flowrule_status_temp['id'] = flowrule['id']
            flowrule_status_temp['status'] = constants.STATUS_ACTIVE
            flowrule_status.append(flowrule_status_temp)
        except Exception as e:
            flowrule_status_temp = {}
            flowrule_status_temp['id'] = flowrule['id']
            flowrule_status_temp['status'] = constants.STATUS_ERROR
            flowrule_status.append(flowrule_status_temp)
            LOG.exception(e)
            LOG.error(_LE("_update_flow_rules_with_mpls_enc failed"))

    def _delete_ports_flowrules_by_id(self, ports_id):
        flowrule_status = []
        try:
            LOG.debug("delete_port_id_flows received, ports_id= %s", ports_id)
            count = 0
            if ports_id:
                for port_id in ports_id:
                    flowrule = (
                        self.sfc_plugin_rpc.get_flowrules_by_host_portid(
                            self.context, port_id
                        )
                    )
                    if flowrule:
                        self._treat_delete_flow_rules(
                            flowrule, flowrule_status)
            LOG.debug(
                "_delete_ports_flowrules_by_id received, count= %s", count)
        except Exception as e:
            LOG.exception(e)
            LOG.error(_LE("delete_port_id_flows failed"))
        if flowrule_status:
            self.sfc_plugin_rpc.update_flowrules_status(
                self.context, flowrule_status)

    def _delete_flow_rule_with_mpls_enc(self, flowrule, flowrule_status):
        try:
            LOG.debug("_delete_flow_rule_with_mpls_enc, flowrule = %s",
                      flowrule)
            group_id = flowrule.get('next_group_id', None)

            # delete tunnel table flow rule on br-int(egress match)
            if flowrule['egress'] is not None:
                self._setup_local_switch_flows_on_int_br(
                    flowrule,
                    flowrule['del_fcs'],
                    None,
                    add_flow=False,
                    match_inport=True
                )

            # delete table INGRESS_TABLE ingress match flow rule
            # on br-int(ingress match)
            network_id = self._get_network_by_port(flowrule['ingress'])
            if network_id:
                # third, install br-int flow rule on table INGRESS_TABLE
                # for ingress traffic
                lvm = self.local_vlan_map[network_id]
                vif_port = lvm.vif_ports[flowrule['ingress']]
                self.int_br.delete_flows(
                    table=INGRESS_TABLE,
                    dl_type=0x8847,
                    dl_dst=vif_port.vif_mac,
                    mpls_label=flowrule['nsp'] << 8 | (flowrule['nsi'] + 1)
                )

            # delete group table, need to check again
            if group_id and flowrule.get('group_refcnt', None) <= 1:
                self.int_br.delete_group(group_id=group_id)
                for item in flowrule['next_hops']:
                    self.int_br.delete_flows(
                        table=ACROSS_SUBNET_TABLE,
                        dl_dst=item['mac_address'])
            elif (not group_id and
                  flowrule['egress'] is not None):
                # to delete last hop flow rule
                for each in flowrule['del_fcs']:
                    if each.get('logical_destination_port', None):
                        ldp = self._get_flow_classifier_dest_port_info(
                            each['logical_destination_port'],
                            flowrule
                        )
                        if ldp:
                            self.int_br.delete_flows(
                                table=ACROSS_SUBNET_TABLE,
                                dl_dst=ldp['mac_address'])

        except Exception as e:
            flowrule_status_temp = {}
            flowrule_status_temp['id'] = flowrule['id']
            flowrule_status_temp['status'] = constants.STATUS_ERROR
            flowrule_status.append(flowrule_status_temp)
            LOG.exception(e)
            LOG.error(_LE("_delete_flow_rule_with_mpls_enc failed"))

    def _treat_update_flow_rules(self, flowrule, flowrule_status):
        if self.overlay_encap_mode == 'eth_nsh':
            raise FeatureSupportError(feature=self.overlay_encap_mode)
        elif self.overlay_encap_mode == 'vxlan_nsh':
            raise FeatureSupportError(feature=self.overlay_encap_mode)
        elif self.overlay_encap_mode == 'mpls':
            self._update_flow_rules_with_mpls_enc(flowrule, flowrule_status)

    def _treat_delete_flow_rules(self, flowrule, flowrule_status):
        if self.overlay_encap_mode == 'eth_nsh':
            raise FeatureSupportError(feature=self.overlay_encap_mode)
        elif self.overlay_encap_mode == 'vxlan_nsh':
            raise FeatureSupportError(feature=self.overlay_encap_mode)
        elif self.overlay_encap_mode == 'mpls':
            self._delete_flow_rule_with_mpls_enc(
                flowrule, flowrule_status)

    def update_flow_rules(self, context, **kwargs):
        try:
            flowrule_status = []
            flowrules = kwargs['flowrule_entries']
            LOG.debug("update_flow_rules received,  flowrules = %s",
                      flowrules)

            if flowrules:
                self._treat_update_flow_rules(flowrules, flowrule_status)
        except Exception as e:
            LOG.exception(e)
            LOG.error(_LE("update_flow_rules failed"))

        if flowrule_status:
            self.sfc_plugin_rpc.update_flowrules_status(
                self.context, flowrule_status)

    def delete_flow_rules(self, context, **kwargs):
        try:
            flowrule_status = []
            flowrules = kwargs['flowrule_entries']
            LOG.debug("delete_flow_rules received,  flowrules= %s", flowrules)
            if flowrules:
                self._treat_delete_flow_rules(flowrules, flowrule_status)
        except Exception as e:
            LOG.exception(e)
            LOG.error(_LE("delete_flow_rules failed"))

        if flowrule_status:
            self.sfc_plugin_rpc.update_flowrules_status(
                self.context, flowrule_status)

    def update_src_node_flow_rules(self, context, **kwargs):
        flowrule = kwargs['flowrule_entries']
        if self.overlay_encap_mode == 'mpls':
            self._setup_egress_flow_rules_with_mpls(flowrule,
                                                    match_inport=False)
            self._update_destination_ingress_flow_rules(flowrule)

    def _delete_src_node_flow_rules_with_mpls(self, flowrule,
                                              match_inport=False):
        LOG.debug("_delete_src_node_flow_rules_with_mpls, flowrule = %s",
                  flowrule)
        group_id = flowrule.get('next_group_id', None)

        # delete br-int table 0 full match flow
        self._setup_local_switch_flows_on_int_br(
            flowrule,
            flowrule['del_fcs'],
            None,
            add_flow=False,
            match_inport=False)

        # delete group table, need to check again
        if None != group_id and flowrule.get('group_refcnt', None) <= 1:
            self.int_br.delete_group(group_id=group_id)
            for item in flowrule['next_hops']:
                self.int_br.delete_flows(
                    table=ACROSS_SUBNET_TABLE,
                    dl_dst=item['mac_address'])

    def delete_src_node_flow_rules(self, context, **kwargs):
        flowrule = kwargs['flowrule_entries']
        if self.overlay_encap_mode == 'mpls':
            self._delete_src_node_flow_rules_with_mpls(flowrule,
                                                       match_inport=False)
            self._update_destination_ingress_flow_rules(flowrule)

    def sfc_treat_devices_added_updated(self, port_id):
        resync = False
        flowrule_status = []
        try:
            LOG.debug("a new device %s is found", port_id)
            flows_list = (
                self.sfc_plugin_rpc.get_flowrules_by_host_portid(
                    self.context, port_id
                )
            )
            if flows_list:
                for flow in flows_list:
                    self._treat_update_flow_rules(flow, flowrule_status)
        except Exception as e:
            LOG.exception(e)
            LOG.error(_LE("portchain_treat_devices_added_updated failed"))
            resync = True

        if flowrule_status:
            self.sfc_plugin_rpc.update_flowrules_status(
                self.context, flowrule_status)

        return resync

    def sfc_treat_devices_removed(self, port_ids):
        resync = False
        for port_id in port_ids:
            LOG.info(_LI("a device %s is removed"), port_id)
            try:
                self._delete_ports_flowrules_by_id(port_id)
            except Exception as e:
                LOG.exception(e)
                LOG.error(
                    _LE("delete port flow rule failed for %(port_id)s"),
                    {'port_id': port_id}
                )
                resync = True

        return resync

    def treat_devices_added_or_updated(self, devices, ovs_restarted):
        skipped_devices = []
        need_binding_devices = []
        security_disabled_devices = []
        devices_details_list = (
            self.plugin_rpc.get_devices_details_list_and_failed_devices(
                self.context,
                devices,
                self.agent_id,
                self.conf.host
            )
        )
        if devices_details_list.get('failed_devices'):
            # TODO(rossella_s): handle better the resync in next patches,
            # this is just to preserve the current behavior
            raise ovs_neutron_agent.DeviceListRetrievalError(devices=devices)

        devices = devices_details_list.get('devices')
        vif_by_id = self.int_br.get_vifs_by_ids(
            [vif['device'] for vif in devices])
        for details in devices:
            device = details['device']
            LOG.debug("Processing port: %s", device)
            port = vif_by_id.get(device)
            if not port:
                # The port disappeared and cannot be processed
                LOG.info(_LI("Port %s was not found on the integration bridge "
                             "and will therefore not be processed"), device)
                skipped_devices.append(device)
                continue

            if 'port_id' in details:
                LOG.info(_LI("Port %(device)s updated. Details: %(details)s"),
                         {'device': device, 'details': details})
                details['vif_port'] = port
                need_binding = self.treat_vif_port(port, details['port_id'],
                                                   details['network_id'],
                                                   details['network_type'],
                                                   details['physical_network'],
                                                   details['segmentation_id'],
                                                   details['admin_state_up'],
                                                   details['fixed_ips'],
                                                   details['device_owner'],
                                                   ovs_restarted)
                if need_binding:
                    need_binding_devices.append(details)

                port_security = details['port_security_enabled']
                has_sgs = 'security_groups' in details
                if not port_security or not has_sgs:
                    security_disabled_devices.append(device)
                self._update_port_network(details['port_id'],
                                          details['network_id'])
                self.ext_manager.handle_port(self.context, details)
                self.sfc_treat_devices_added_updated(details['port_id'])
            else:
                LOG.warn(_LW("Device %s not defined on plugin"), device)
                if (port and port.ofport != -1):
                    self.port_dead(port)
        return skipped_devices, need_binding_devices, security_disabled_devices

    def process_deleted_ports(self, port_info):
        # don't try to process removed ports as deleted ports since
        # they are already gone
        if 'removed' in port_info:
            self.deleted_ports -= port_info['removed']
        deleted_ports = list(self.deleted_ports)
        while self.deleted_ports:
            port_id = self.deleted_ports.pop()
            port = self.int_br.get_vif_port_by_id(port_id)
            self._clean_network_ports(port_id)
            self.ext_manager.delete_port(self.context,
                                         {"vif_port": port,
                                          "port_id": port_id})
            self.sfc_treat_devices_removed(port_id)
            # move to dead VLAN so deleted ports no
            # longer have access to the network
            if port:
                # don't log errors since there is a chance someone will be
                # removing the port from the bridge at the same time
                self.port_dead(port, log_errors=False)
            self.port_unbound(port_id)
        # Flush firewall rules after ports are put on dead VLAN to be
        # more secure
        self.sg_agent.remove_devices_filter(deleted_ports)


def main():
    cfg.CONF.register_opts(ip_lib.OPTS)
    config.register_root_helper(cfg.CONF)
    common_config.init(sys.argv[1:])
    common_config.setup_logging()
    q_utils.log_opt_values(LOG)

    try:
        agent_config = ovs_neutron_agent.create_agent_config_map(cfg.CONF)
    except ValueError as e:
        LOG.exception(e)
        LOG.error(_LE('Agent terminated!'))
        sys.exit(1)

    is_xen_compute_host = 'rootwrap-xen-dom0' in cfg.CONF.AGENT.root_helper
    if is_xen_compute_host:
        # Force ip_lib to always use the root helper to ensure that ip
        # commands target xen dom0 rather than domU.
        cfg.CONF.set_default('ip_lib_force_root', True)

    bridge_classes = {
        'br_int': br_int.OVSIntegrationBridge,
        'br_phys': br_phys.OVSPhysicalBridge,
        'br_tun': br_tun.OVSTunnelBridge,
    }
    try:
        agent = OVSSfcAgent(bridge_classes, **agent_config)
    except RuntimeError as e:
        LOG.exception(e)
        LOG.error(_LE("Agent terminated!"))
        sys.exit(1)
    signal.signal(signal.SIGTERM, agent._handle_sigterm)

    # Start everything.
    LOG.info(_LI("Agent initialized successfully, now running... "))
    agent.daemon_loop()


if __name__ == "__main__":
    main()
