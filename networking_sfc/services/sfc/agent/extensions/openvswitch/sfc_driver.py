# Copyright 2015 Huawei.
# Copyright 2016 Red Hat, Inc.
# Copyright 2017 Intel Corporation.
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

from neutron.plugins.ml2.drivers.openvswitch.agent import vlanmanager
from neutron_lib import constants as n_consts
from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts
from oslo_config import cfg
from oslo_log import log as logging

from networking_sfc.services.sfc.agent.extensions import sfc
from networking_sfc.services.sfc.common import ovs_ext_lib
from networking_sfc.services.sfc.drivers.ovs import constants

LOG = logging.getLogger(__name__)

cfg.CONF.import_group('OVS', 'neutron.plugins.ml2.drivers.openvswitch.agent.'
                             'common.config')

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

# Reverse group number offset for dump_group
REVERSE_GROUP_NUMBER_OFFSET = 7000

TAP_CLASSIFIER_TABLE = 7
# This table floods TAP packets on tunnel ports
TAP_TUNNEL_OUTPUT_TABLE = 25

# actions
RESUBMIT_TAP_TABLE = ',resubmit(,%s)' % TAP_CLASSIFIER_TABLE
NORMAL_ACTION = ",NORMAL"


class SfcOVSAgentDriver(sfc.SfcAgentDriver):
    """This class will support MPLS frame

    Ethernet + MPLS
    IPv4 Packet:
    +-------------------------------+---------------+--------------------+
    |Outer Ethernet, ET=0x8847      | MPLS head,    | original IP Packet |
    +-------------------------------+---------------+--------------------+
    """

    def __init__(self):
        super().__init__()
        self.agent_api = None
        self.br_int = None
        self.br_tun = None

        self.local_ip = None
        self.patch_tun_ofport = None
        self.vlan_manager = None

    def consume_api(self, agent_api):
        self.agent_api = agent_api

    def initialize(self):
        self.br_int = ovs_ext_lib.SfcOVSBridgeExt(
            self.agent_api.request_int_br())

        self.local_ip = cfg.CONF.OVS.local_ip
        self.patch_tun_ofport = self.br_int.get_port_ofport(
            cfg.CONF.OVS.int_peer_patch_port)
        self.vlan_manager = vlanmanager.LocalVlanManager()

        self._clear_sfc_flow_on_int_br()

        self.br_tun = ovs_ext_lib.SfcOVSBridgeExt(
            self.agent_api.request_tun_br())
        self.patch_int_ofport = self.br_tun.get_port_ofport(
            cfg.CONF.OVS.tun_peer_patch_port)
        self._clear_sfc_flow_on_tun_br()

    def update_flow_rules(self, flowrule, flowrule_status):
        if flowrule['fwd_path'] is False and flowrule['node_type'] == \
                'sf_node':
            flowrule['ingress'], flowrule['egress'] = flowrule['egress'], \
                flowrule['ingress']
        try:
            LOG.debug('update_flow_rule, flowrule = %s', flowrule)

            if flowrule.get('egress', None):
                self._setup_egress_flow_rules(flowrule)
            if flowrule.get('ingress', None) and not flowrule.get(
                    'skip_ingress_flow_config', None):
                self._setup_ingress_flow_rules(flowrule)
            flowrule_status_temp = {'id': flowrule['id'],
                                    'status': constants.STATUS_ACTIVE}
            flowrule_status.append(flowrule_status_temp)
        except Exception as e:
            flowrule_status_temp = {'id': flowrule['id'],
                                    'status': constants.STATUS_ERROR}
            flowrule_status.append(flowrule_status_temp)
            LOG.exception(e)
            LOG.error("update_flow_rules failed")

    def delete_flow_rule(self, flowrule, flowrule_status):
        if flowrule['fwd_path'] is False and flowrule['node_type'] == \
                'sf_node':
            flowrule['ingress'], flowrule['egress'] = flowrule['egress'], \
                flowrule['ingress']
        try:
            LOG.debug("delete_flow_rule, flowrule = %s", flowrule)
            pc_corr = flowrule['pc_corr']

            # delete tunnel table flow rule on br-int(egress match)
            if flowrule['egress'] is not None:
                self._setup_local_switch_flows_on_int_br(flowrule,
                                                         flowrule['del_fcs'],
                                                         None,
                                                         add_flow=False,
                                                         match_inport=True)
                # delete group table, need to check again
                group_id = flowrule.get('next_group_id', None)
                if group_id and flowrule.get('group_refcnt', None) <= 1:
                    if flowrule['fwd_path']:
                        self.br_int.delete_group(group_id=group_id)
                    else:
                        self.br_int.delete_group(group_id=group_id +
                                                 REVERSE_GROUP_NUMBER_OFFSET)
                    self._delete_across_subnet_table_flows(flowrule)

            if flowrule['ingress'] is not None:
                # delete table INGRESS_TABLE ingress match flow rule
                # on br-int(ingress match)
                vif_port = self.br_int.get_vif_port_by_id(flowrule['ingress'])
                if vif_port:
                    # third, install br-int flow rule on table INGRESS_TABLE
                    # for ingress traffic
                    if pc_corr == 'mpls':
                        self._delete_flows_mpls(flowrule, vif_port)
                    elif pc_corr == 'nsh':
                        self._delete_flows_nsh(flowrule, vif_port)
        except Exception as e:
            flowrule_status_temp = {'id': flowrule['id'],
                                    'status': constants.STATUS_ERROR}
            flowrule_status.append(flowrule_status_temp)
            LOG.exception(e)
            LOG.error("delete_flow_rule failed")

    def _clear_sfc_flow_on_int_br(self):
        self.br_int.delete_group(group_id='all')
        self.br_int.delete_flows(table=ACROSS_SUBNET_TABLE)
        self.br_int.delete_flows(table=INGRESS_TABLE)
        self.br_int.delete_flows(table=TAP_CLASSIFIER_TABLE)
        self.br_int.install_goto(dest_table_id=INGRESS_TABLE,
                                 priority=PC_DEF_PRI,
                                 eth_type=constants.ETH_TYPE_MPLS)
        self.br_int.install_goto(dest_table_id=INGRESS_TABLE,
                                 priority=PC_DEF_PRI,
                                 eth_type=constants.ETH_TYPE_NSH)
        self.br_int.install_drop(table_id=INGRESS_TABLE)

    def _parse_flow_classifier(self, flow_classifier):
        eth_type, nw_proto, source_port_masks, destination_port_masks = (
            (None, ) * 4)

        if (not flow_classifier['source_port_range_min'] and
                not flow_classifier['source_port_range_max']):
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

        if (not flow_classifier['destination_port_range_min'] and
                not flow_classifier['destination_port_range_max']):
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

        if flow_classifier['ethertype'] == "IPv4":
            eth_type = constants.ETH_TYPE_IP
            if n_consts.PROTO_NAME_TCP == flow_classifier['protocol']:
                nw_proto = n_consts.PROTO_NUM_TCP
            elif n_consts.PROTO_NAME_UDP == flow_classifier['protocol']:
                nw_proto = n_consts.PROTO_NUM_UDP
            elif n_consts.PROTO_NAME_ICMP == flow_classifier['protocol']:
                nw_proto = n_consts.PROTO_NUM_ICMP
            else:
                nw_proto = None
        elif flow_classifier['ethertype'] == "IPv6":
            LOG.error("Current portchain agent doesn't support IPv6")
        else:
            LOG.error("invalid protocol input")

        return (eth_type, nw_proto,
                source_port_masks,
                destination_port_masks)

    def _get_flow_infos_from_flow_classifier(self, flow_classifier, flowrule):
        flow_infos = []
        nw_src, nw_dst, tp_src, tp_dst = ((None, ) * 4)

        if flow_classifier['ethertype'] != "IPv4":
            LOG.error("Current portchain agent only supports IPv4")
            return flow_infos

        # parse and transfer flow info to match field info
        eth_type, nw_proto, source_port_masks, destination_port_masks = (
            self._parse_flow_classifier(flow_classifier))

        if flowrule['fwd_path']:
            if flow_classifier['source_ip_prefix']:
                nw_src = flow_classifier['source_ip_prefix']
            else:
                nw_src = '0.0.0.0/0.0.0.0'
            if flow_classifier['destination_ip_prefix']:
                nw_dst = flow_classifier['destination_ip_prefix']
            else:
                nw_dst = '0.0.0.0/0.0.0.0'
        else:
            if flow_classifier['source_ip_prefix']:
                nw_src = flow_classifier['destination_ip_prefix']
            else:
                nw_src = '0.0.0.0/0.0.0.0'
            if flow_classifier['destination_ip_prefix']:
                nw_dst = flow_classifier['source_ip_prefix']
            else:
                nw_dst = '0.0.0.0/0.0.0.0'

        if source_port_masks and destination_port_masks:
            for destination_port in destination_port_masks:
                for source_port in source_port_masks:
                    if flowrule['fwd_path']:
                        tp_src = '%s' % source_port
                        tp_dst = '%s' % destination_port
                    else:
                        tp_dst = '%s' % source_port
                        tp_src = '%s' % destination_port
                    flow_info = {'eth_type': eth_type,
                                 'nw_src': nw_src,
                                 'nw_dst': nw_dst,
                                 'tp_src': tp_src,
                                 'tp_dst': tp_dst}
                    if nw_proto:
                        flow_info['nw_proto'] = nw_proto
                    flow_infos.append(flow_info)

        return flow_infos

    def _get_flow_infos_from_flow_classifier_list(self, flow_classifier_list,
                                                  flowrule):
        flow_infos = []

        if not flow_classifier_list:
            return flow_infos
        for flow_classifier in flow_classifier_list:
            flow_infos.extend(
                self._get_flow_infos_from_flow_classifier(flow_classifier,
                                                          flowrule))

        return flow_infos

    def _match_by_header(self, match_info, nsp, nsi):
        match_info['reg0'] = (nsp << 8) | nsi
        # on header-matching there's no in_port
        match_info.pop('in_port', None)

    def _setup_local_switch_flows_on_int_br(self, flowrule,
                                            flow_classifier_list, actions,
                                            add_flow=True, match_inport=True):
        inport_match = {}
        priority = PC_DEF_PRI
        # no pp_corr means that classification will not be based on encap
        pp_corr = flowrule.get('pp_corr')
        node_type = flowrule['node_type']
        branch_info = flowrule.get('branch_info')
        on_add = None
        flow_count = 1
        if branch_info and node_type == constants.SRC_NODE:
            # for branching, we need as many flows (per flow info) as branches
            # because we can't AND-match the same field in a single flow
            flow_count = len(branch_info.get('matches'))
            on_add = branch_info.get('on_add')

        if match_inport is True:
            egress_port = self.br_int.get_vif_port_by_id(flowrule['egress'])
            if egress_port:
                inport_match = {'in_port': egress_port.ofport}
                priority = PC_INGRESS_PRI

        for flow_info in self._get_flow_infos_from_flow_classifier_list(
                flow_classifier_list, flowrule):
            match_info = dict(inport_match)
            match_info.update(flow_info)
            if node_type == constants.SF_NODE:
                if pp_corr:
                    match_info = {'in_port': match_info['in_port']}
                    if pp_corr == 'mpls':
                        match_info = self._build_classification_match_sfc_mpls(
                            flowrule, match_info)
                    elif pp_corr == 'nsh':
                        match_info = self._build_classification_match_sfc_nsh(
                            flowrule, match_info)

            for i in range(flow_count):
                if branch_info:
                    # for Service Graphs (branching):
                    nsp = branch_info['matches'][i][0]
                    nsi = branch_info['matches'][i][1]
                if add_flow:
                    if on_add:
                        self._match_by_header(match_info, nsp, nsi)
                    self.br_int.add_flow(table=ovs_consts.LOCAL_SWITCHING,
                                         priority=priority,
                                         actions=actions,
                                         **match_info)
                else:
                    if on_add is False:
                        self._match_by_header(match_info, nsp, nsi)
                    self.br_int.delete_flows(table=ovs_consts.LOCAL_SWITCHING,
                                             priority=priority,
                                             strict=True,
                                             **match_info)

    def _setup_egress_flow_rules(self, flowrule, match_inport=True):
        group_id = flowrule.get('next_group_id', None)
        next_hops = flowrule.get('next_hops', None)
        pc_corr = flowrule.get('pc_corr', 'mpls')
        pp_corr = flowrule.get('pp_corr', None)
        node_type = flowrule.get('node_type')
        next_hop_tap_enabled = None
        # if the group is not none, install the egress rule for this SF
        if group_id and next_hops:
            # 1st, install br-int flow rule on table ACROSS_SUBNET_TABLE
            # and group table
            buckets = []
            vlan = self._get_vlan_by_port(flowrule['egress'])

            if isinstance(next(iter(next_hops)), dict):
                next_hop_tap_enabled = next_hops[0].get('tap_enabled')

            for item in next_hops:
                # all next hops share same pp_corr, enforced by higher layers
                pp_corr_nh = item.get('pp_corr', None)
                if flowrule['fwd_path']:
                    bucket = (
                        'bucket=weight=%d, mod_dl_dst:%s, resubmit(,%d)' % (
                            item['weight'],
                            item['in_mac_address'],
                            ACROSS_SUBNET_TABLE))
                else:
                    bucket = (
                        'bucket=weight=%d, mod_dl_dst:%s, resubmit(,%d)' % (
                            item['weight'],
                            item['mac_address'],
                            ACROSS_SUBNET_TABLE))
                buckets.append(bucket)
                subnet_actions_list = []

                across_flow = "mod_vlan_vid:%d," % vlan
                # the classic encapsulation of packets in ACROSS_SUBNET_TABLE
                # is kept unchanged for the same scenarios, i.e. when the next
                # hops don't support encapsulation and neither the current one.
                if not pp_corr and pp_corr_nh is None:
                    if pc_corr == 'mpls':
                        push_encap = self._build_push_mpls(flowrule['nsp'],
                                                           flowrule['nsi'])
                    elif pc_corr == 'nsh':
                        push_encap = self._build_push_nsh(flowrule['nsp'],
                                                          flowrule['nsi'])
                    across_flow = push_encap + across_flow

                subnet_actions_list.append(across_flow)

                if item['local_endpoint'] == self.local_ip:
                    subnet_actions = 'resubmit(,%d)' % INGRESS_TABLE
                else:
                    # same subnet with next hop
                    subnet_actions = 'output:%s' % self.patch_tun_ofport
                subnet_actions_list.append(subnet_actions)

                eth_type = constants.ETH_TYPE_IP
                if pp_corr == 'mpls' or pp_corr_nh == 'mpls':
                    eth_type = constants.ETH_TYPE_MPLS
                elif pp_corr == 'nsh' or pp_corr_nh == 'nsh':
                    eth_type = constants.ETH_TYPE_NSH

                if item.get('tap_enabled'):
                    self._add_tap_classification_flows(flowrule,
                                                       item,
                                                       subnet_actions_list)
                else:
                    self._configure_across_subnet_flow(flowrule,
                                                       item,
                                                       subnet_actions_list,
                                                       eth_type)

            if not next_hop_tap_enabled:
                self._add_group_table(buckets, flowrule, group_id)

            # 2nd, install br-int flow rule on table 0 for egress traffic
            enc_actions = ""
            # we only encapsulate on table 0 if we know the next hops will
            # support that encapsulation but the current hop doesn't already.
            if not pp_corr and pp_corr_nh:
                if pc_corr == 'mpls':
                    enc_actions = self._build_push_mpls(flowrule['nsp'],
                                                        flowrule['nsi'])
                elif pc_corr == 'nsh':
                    enc_actions = self._build_push_nsh(flowrule['nsp'],
                                                       flowrule['nsi'])
            if flowrule['fwd_path']:
                enc_actions += "group:%d" % group_id
            else:
                rev_group_id = group_id + REVERSE_GROUP_NUMBER_OFFSET
                enc_actions += "group:%d" % rev_group_id

            enc_actions = self._update_enc_actions(enc_actions, flowrule,
                                                   next_hop_tap_enabled)
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
        else:
            end_of_chain_actions = 'normal'
            # at the end of the chain, the header must be removed (if used)
            if (node_type != constants.SRC_NODE) and pp_corr:
                branch_point = flowrule.get('branch_point')
                if branch_point:
                    nsp = flowrule['nsp']
                    nsi = flowrule['nsi']
                    sfpi = (nsp << 8) | nsi
                    if pc_corr == 'mpls':
                        end_of_chain_actions = (
                            'load:%s->NXM_NX_REG0[],'
                            'pop_mpls:0x%04x,resubmit(,0)' % (
                                hex(sfpi), constants.ETH_TYPE_IP))
                    elif pc_corr == 'nsh':
                        end_of_chain_actions = (
                            "load:%s->NXM_NX_REG0[],"
                            "decap(),decap(),resubmit(,0)" % (
                                hex(sfpi)))
                else:
                    if pc_corr == 'mpls':
                        end_of_chain_actions = ("pop_mpls:0x%04x,%s" % (
                                                constants.ETH_TYPE_IP,
                                                end_of_chain_actions))
                    elif pc_corr == 'nsh':
                        end_of_chain_actions = ("decap(),decap(),%s" % (
                                                end_of_chain_actions))

            if flowrule.get('tap_enabled'):
                end_of_chain_actions += RESUBMIT_TAP_TABLE

            # to uninstall the removed flow classifiers
            if 'del_fcs' in flowrule:
                self._setup_local_switch_flows_on_int_br(
                    flowrule,
                    flowrule['del_fcs'],
                    None,
                    add_flow=False,
                    match_inport=True)

            if 'add_fcs' in flowrule:
                # to install the added flow classifiers
                self._setup_local_switch_flows_on_int_br(
                    flowrule,
                    flowrule['add_fcs'],
                    actions=end_of_chain_actions,
                    add_flow=True,
                    match_inport=True)

    def _get_vlan_by_port(self, port_id):
        try:
            net_uuid, seg_id = self.vlan_manager.get_net_and_segmentation_id(
                port_id)
            return self.vlan_manager.get(net_uuid, seg_id).vlan
        except (vlanmanager.VifIdNotFound, vlanmanager.MappingNotFound):
            return None

    def _setup_ingress_flow_rules(self, flowrule):
        vif_port = self.br_int.get_vif_port_by_id(flowrule['ingress'])
        if vif_port:
            vlan = self._get_vlan_by_port(flowrule['ingress'])
            pc_corr = flowrule['pc_corr']
            pp_corr = flowrule['pp_corr']

            # install br-int flow rule on table 0 for ingress traffic
            # install an SFC Proxy if the port pair doesn't support the
            # SFC encapsulation (pc_corr) specified in the chain
            if pc_corr == 'mpls':
                if flowrule.get('tap_enabled'):
                    return self._add_tap_ingress_flow(flowrule, vif_port, vlan)
                if pp_corr is None:
                    match_field = self._build_proxy_sfc_mpls(flowrule,
                                                             vif_port, vlan)
                elif pp_corr == 'mpls':
                    match_field = self._build_forward_sfc_mpls(flowrule,
                                                               vif_port, vlan)
            elif pc_corr == 'nsh':
                if pp_corr is None:
                    match_field = self._build_proxy_sfc_nsh(flowrule,
                                                            vif_port, vlan)
                elif pp_corr == 'nsh':
                    match_field = self._build_forward_sfc_nsh(flowrule,
                                                              vif_port, vlan)
            self.br_int.add_flow(**match_field)

    def _build_classification_match_sfc_mpls(self, flowrule, match_info):
        match_info['eth_type'] = constants.ETH_TYPE_MPLS
        match_info['mpls_label'] = flowrule['nsp'] << 8 | flowrule['nsi']
        return match_info

    def _build_classification_match_sfc_nsh(self, flowrule, match_info):
        match_info['eth_type'] = constants.ETH_TYPE_NSH
        match_info['nsh_mdtype'] = 1
        match_info['nsh_spi'] = flowrule['nsp']
        match_info['nsh_si'] = flowrule['nsi']
        return match_info

    def _build_push_mpls(self, nsp, nsi):
        return (
            "push_mpls:0x%04x,"
            "set_mpls_label:%d,"
            "set_mpls_ttl:%d," %
            (constants.ETH_TYPE_MPLS, nsp << 8 | nsi, nsi))

    def _build_push_nsh(self, nsp, nsi):
        return (
            "encap(nsh,prop(class=nsh,type=md_type,val=1)),"
            "set_field:%s->nsh_spi,set_field:%s->nsh_si,"
            "encap(ethernet)," %
            (hex(nsp), hex(nsi)))

    def _build_ingress_common_match_field(self, vif_port, vlan):
        return {
            'table': INGRESS_TABLE,
            'priority': 1,
            'dl_dst': vif_port.vif_mac,
            'dl_vlan': vlan
        }

    def _build_ingress_match_field_sfc_mpls(self, flowrule, vif_port, vlan):
        match_field = self._build_ingress_common_match_field(vif_port, vlan)
        match_field['eth_type'] = constants.ETH_TYPE_MPLS
        match_field['mpls_label'] = flowrule['nsp'] << 8 | flowrule['nsi'] + 1
        return match_field

    def _build_ingress_match_field_sfc_nsh(self, flowrule, vif_port, vlan):
        match_field = self._build_ingress_common_match_field(vif_port, vlan)
        match_field['eth_type'] = constants.ETH_TYPE_NSH
        match_field['nsh_mdtype'] = 1
        match_field['nsh_spi'] = flowrule['nsp']
        match_field['nsh_si'] = flowrule['nsi'] + 1
        return match_field

    def _build_proxy_sfc_mpls(self, flowrule, vif_port, vlan):
        match_field = self._build_ingress_match_field_sfc_mpls(
            flowrule, vif_port, vlan)
        actions = ("strip_vlan, pop_mpls:0x%04x,"
                   "output:%s" % (constants.ETH_TYPE_IP, vif_port.ofport))
        match_field['actions'] = actions
        return match_field

    def _build_proxy_sfc_nsh(self, flowrule, vif_port, vlan):
        match_field = self._build_ingress_match_field_sfc_nsh(
            flowrule, vif_port, vlan)
        actions = ("strip_vlan,move:NXM_OF_ETH_DST->OXM_OF_PKT_REG0[0..47],"
                   "decap(),decap(),"
                   "move:OXM_OF_PKT_REG0[0..47]->NXM_OF_ETH_DST,output:%s"
                   "" % vif_port.ofport)
        match_field['actions'] = actions
        return match_field

    def _build_forward_sfc_mpls(self, flowrule, vif_port, vlan):
        match_field = self._build_ingress_match_field_sfc_mpls(
            flowrule, vif_port, vlan)
        actions = ("strip_vlan, output:%s" % vif_port.ofport)
        match_field['actions'] = actions
        return match_field

    def _build_forward_sfc_nsh(self, flowrule, vif_port, vlan):
        match_field = self._build_ingress_match_field_sfc_nsh(
            flowrule, vif_port, vlan)
        actions = ("strip_vlan, output:%s" % vif_port.ofport)
        match_field['actions'] = actions
        return match_field

    def _delete_flows_mpls(self, flowrule, vif_port):
        if flowrule.get('tap_enabled'):
            self.br_int.delete_flows(
                table=INGRESS_TABLE,
                eth_type=constants.ETH_TYPE_MPLS,
                dl_src=flowrule['mac_address'],
                mpls_label=flowrule['nsp'] << 8 | flowrule['nsi']
            )
        else:
            self.br_int.delete_flows(
                table=INGRESS_TABLE,
                eth_type=constants.ETH_TYPE_MPLS,
                dl_dst=vif_port.vif_mac,
                mpls_label=flowrule['nsp'] << 8 | flowrule['nsi'] + 1
            )

    def _add_group_table(self, buckets, flowrule, group_id):
        group_content = self.br_int.dump_group_for_id(group_id)
        buckets = ','.join(buckets)
        if flowrule['fwd_path']:
            if group_content.find('group_id=%d,' % group_id) == -1:
                self.br_int.add_group(group_id=group_id,
                                      type='select',
                                      buckets=buckets)
            else:
                self.br_int.mod_group(group_id=group_id,
                                      type='select',
                                      buckets=buckets)
        else:
            # set different id for rev_group
            rev_group_id = group_id + REVERSE_GROUP_NUMBER_OFFSET
            if group_content.find('group_id=%d,' % (rev_group_id)) == -1:
                self.br_int.add_group(group_id=rev_group_id,
                                      type='select',
                                      buckets=buckets)
            else:
                self.br_int.mod_group(group_id=rev_group_id,
                                      type='select',
                                      buckets=buckets)

    def _configure_across_subnet_flow(self, flowrule, item,
                                      subnet_actions_list, eth_type):
        if flowrule['fwd_path']:
            self.br_int.add_flow(
                table=ACROSS_SUBNET_TABLE,
                priority=0,
                dl_dst=item['in_mac_address'],
                eth_type=eth_type,
                actions="%s" % ','.join(subnet_actions_list))
        else:
            self.br_int.add_flow(
                table=ACROSS_SUBNET_TABLE,
                priority=0,
                dl_dst=item['mac_address'],
                eth_type=eth_type,
                actions="%s" % ','.join(subnet_actions_list))

    def _add_tap_classification_flows(self, flowrule, item,
                                      subnet_actions_list):
        egress_port = self.br_int.get_vif_port_by_id(flowrule['egress'])
        vlan = self._get_vlan_by_port(flowrule['egress'])
        if not egress_port:
            return
        in_port = egress_port.ofport
        vif_mac = egress_port.vif_mac

        tap_action = ""
        if flowrule['pc_corr'] == 'mpls':
            tap_action += self._build_push_mpls(item['nsp'], item['nsi'])
        tap_action += "mod_vlan_vid:%d," % vlan
        subnet_actions_list[0] = tap_action
        ovs_rule = {}

        self._get_eth_type(flowrule, item, ovs_rule)
        ovs_rule.update(table=TAP_CLASSIFIER_TABLE,
                        priority=0,
                        in_port=in_port,
                        dl_src=vif_mac,
                        actions="%s" % ''.join(subnet_actions_list)
                        )
        self.br_int.add_flow(**ovs_rule)
        if item['local_endpoint'] != self.local_ip:
            self._configure_tunnel_bridge_flows(flowrule, item, vif_mac)

    def _get_eth_type(self, flowrule, item, ovs_rule):
        # eth_type is decided based on current node's pp_corr and next node of
        # Tap node's pp_corr
        if flowrule['pp_corr'] == item.get('pp_corr_tap_nh') is None:
            ovs_rule.update(eth_type=constants.ETH_TYPE_IP)
        elif flowrule['pp_corr'] and not item.get('pp_corr_tap_nh'):
            ovs_rule.update(eth_type=constants.ETH_TYPE_IP)
        elif not flowrule['pp_corr'] and item.get('pp_corr_tap_nh'):
            if item['pp_corr_tap_nh'] == 'mpls':
                eth_type = constants.ETH_TYPE_MPLS
                mpls_label = flowrule['nsp'] << 8 | flowrule['nsi']
                ovs_rule.update(mpls_label=mpls_label,
                                eth_type=eth_type)
        else:
            if flowrule['pp_corr'] == 'mpls' or item.get(
                    'pp_corr_tap_nh') == 'mpls':
                ovs_rule.update(eth_type=constants.ETH_TYPE_MPLS)

    def _configure_tunnel_bridge_flows(self, flowrule, item, vif_mac):
        local_tunnel_ports = [port for port in
                              self.br_tun.get_bridge_ports()
                              if port != self.patch_int_ofport]
        match_info = {'in_port': self.patch_int_ofport,
                      'dl_src': vif_mac}
        if flowrule['pc_corr'] == 'mpls':
            self._build_classification_match_sfc_mpls(item, match_info)
        self.br_tun.add_flow(
            table=0,
            priority=30,
            actions="resubmit(,%s)" % TAP_TUNNEL_OUTPUT_TABLE,
            **match_info
        )
        output_actions = "strip_vlan,load:%s->NXM_NX_TUN_ID[]" % (
            hex(flowrule['segment_id']))
        for port in local_tunnel_ports:
            output_actions += (",output:%d" % port)
        self.br_tun.add_flow(
            table=TAP_TUNNEL_OUTPUT_TABLE,
            priority=0,
            actions=output_actions,
            **match_info
        )

    def _build_buckets(self, buckets, flowrule, item):
        if item.get('tap_enabled'):
            # Tap PPG doesn't use bucket as of now.
            return
        if flowrule['fwd_path']:
            bucket = (
                'bucket=weight=%d, mod_dl_dst:%s, resubmit(,%d)' % (
                    item['weight'],
                    item['in_mac_address'],
                    ACROSS_SUBNET_TABLE))
        else:
            bucket = (
                'bucket=weight=%d, mod_dl_dst:%s, resubmit(,%d)' % (
                    item['weight'],
                    item['mac_address'],
                    ACROSS_SUBNET_TABLE))
        buckets.append(bucket)

    def _update_enc_actions(self, enc_actions, flow_rule,
                            next_hop_tap_enabled):
        # Add resubmit action to send to TAP table.
        if next_hop_tap_enabled:
            pp_corr = flow_rule['pp_corr']
            pp_corr_tap_nh = flow_rule['next_hops'][0].get('pp_corr_tap_nh')
            tap_nh_node_type = flow_rule['next_hops'][0].get(
                'tap_nh_node_type', constants.DST_NODE)
            group_action = enc_actions.split(',')[-1]
            enc_actions = ""
            if tap_nh_node_type == constants.SF_NODE:
                if not pp_corr and pp_corr_tap_nh:
                    if flow_rule.get('pc_corr', 'mpls') == 'mpls':
                        mpls_act = self._build_push_mpls(flow_rule['nsp'],
                                                         flow_rule['nsi'])
                        enc_actions += mpls_act
                    # enc_actions += group_action
                enc_actions += group_action
            else:
                if flow_rule['pc_corr'] == 'mpls':
                    # For DST Node
                    if flow_rule['pp_corr']:
                        enc_actions = ('pop_mpls:0x%04x,%s' % (
                            constants.ETH_TYPE_IP, NORMAL_ACTION))
                    else:
                        enc_actions += NORMAL_ACTION
            return enc_actions + RESUBMIT_TAP_TABLE
        elif flow_rule.get('tap_enabled'):
            return enc_actions + RESUBMIT_TAP_TABLE
        return enc_actions

    def _delete_across_subnet_table_flows(self, flowrule):
        if not flowrule['next_hops']:
            return
        tap_enabled = flowrule['next_hops'][0].get('tap_enabled', False)
        if tap_enabled:
            egress_port = self.br_int.get_vif_port_by_id(flowrule['egress'])
            for item in flowrule['next_hops']:
                if flowrule['fwd_path']:
                    self.br_int.delete_flows(
                        table=TAP_CLASSIFIER_TABLE,
                        dl_src=egress_port.vif_mac)
                else:
                    self.br_int.delete_flows(
                        table=TAP_CLASSIFIER_TABLE,
                        dl_src=egress_port.vif_mac)

                if item['local_endpoint'] != self.local_ip:
                    self._delete_tunnel_bridge_flows(flowrule,
                                                     egress_port.vif_mac)
        else:
            for item in flowrule['next_hops']:
                if flowrule['fwd_path']:
                    self.br_int.delete_flows(
                        table=ACROSS_SUBNET_TABLE,
                        dl_dst=item['in_mac_address'])
                else:
                    self.br_int.delete_flows(
                        table=ACROSS_SUBNET_TABLE,
                        dl_dst=item['mac_address'])

    def _add_tap_ingress_flow(self, flowrule, vif_port, vlan):
        match_field = self._build_tap_ingress_match_field_sfc_mpls(
            flowrule, vif_port, vlan)
        actions = ('strip_vlan, pop_mpls:0x%04x,output:%s'
                   % (constants.ETH_TYPE_MPLS,
                      vif_port.ofport))
        match_field['actions'] = actions
        match_field.pop('dl_dst', None)
        match_field.update(dl_src=flowrule['mac_address'])
        self.br_int.add_flow(**match_field)

    def _build_tap_ingress_match_field_sfc_mpls(self, flowrule, vif_port,
                                                vlan):
        match_field = self._build_ingress_common_match_field(vif_port, vlan)
        match_field['eth_type'] = constants.ETH_TYPE_MPLS
        match_field['mpls_label'] = flowrule['nsp'] << 8 | flowrule['nsi']
        return match_field

    def _delete_tunnel_bridge_flows(self, flowrule, src_mac):
        match_info = {'in_port': self.patch_int_ofport,
                      'dl_src': src_mac}
        # Use Tap 'nsi'
        flowrule_copy = flowrule.copy()
        flowrule_copy['nsi'], flowrule_copy['nsp'] = (
            flowrule['next_hops'][0]['nsi'], flowrule['next_hops'][0]['nsp'])
        self._build_classification_match_sfc_mpls(flowrule_copy, match_info)
        self.br_tun.delete_flows(table=0,
                                 **match_info)
        self.br_tun.delete_flows(table=TAP_TUNNEL_OUTPUT_TABLE,
                                 **match_info)

    def _clear_sfc_flow_on_tun_br(self):
        self.br_tun.delete_flows(table=0, eth_type=constants.ETH_TYPE_MPLS)
        self.br_tun.delete_flows(table=TAP_TUNNEL_OUTPUT_TABLE)

    def _delete_flows_nsh(self, flowrule, vif_port):
        self.br_int.delete_flows(
            table=INGRESS_TABLE,
            eth_type=constants.ETH_TYPE_NSH,
            dl_dst=vif_port.vif_mac,
            nsh_mdtype=1,
            nsh_spi=flowrule['nsp'],
            nsh_si=flowrule['nsi'] + 1
        )
