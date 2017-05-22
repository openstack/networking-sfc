# Copyright 2017 Futurewei. All rights reserved.
# Copyright 2017 Intel Corporation. All rights reserved.
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

import neutron.common.constants as nc_const
import neutron.common.rpc as n_rpc
import neutron.db.api as db_api
from neutron.db import models_v2
import neutron.plugins.ml2.drivers.l2pop.db as l2pop_db
import neutron.plugins.ml2.drivers.l2pop.rpc as l2pop_rpc
from neutron_lib import constants as const
from neutron_lib import context as n_context
from neutron_lib.plugins import directory
from oslo_log import helpers as log_helpers
from oslo_log import log as logging
from oslo_serialization import jsonutils

from networking_sfc.extensions import flowclassifier
from networking_sfc.extensions import sfc
from networking_sfc.services.sfc.common import exceptions as exc
from networking_sfc.services.sfc.drivers import base as driver_base
from networking_sfc.services.sfc.drivers.ovs import constants as ovs_const
from networking_sfc.services.sfc.drivers.ovs import db as ovs_sfc_db
from networking_sfc.services.sfc.drivers.ovs import rpc as ovs_sfc_rpc
from networking_sfc.services.sfc.drivers.ovs import rpc_topics as sfc_topics

LOG = logging.getLogger(__name__)


class OVSSfcDriver(driver_base.SfcDriverBase,
                   ovs_sfc_db.OVSSfcDriverDB):
    """Sfc Driver Base Class."""

    def initialize(self):
        super(OVSSfcDriver, self).initialize()
        self.ovs_driver_rpc = ovs_sfc_rpc.SfcAgentRpcClient(
            sfc_topics.SFC_AGENT
        )
        self.rpc_ctx = n_context.get_admin_context_without_session()
        self._setup_rpc()

    def _setup_rpc(self):
        # Setup a rpc server
        self.topic = sfc_topics.SFC_PLUGIN
        self.endpoints = [ovs_sfc_rpc.SfcRpcCallback(self)]
        self.conn = n_rpc.create_connection()
        self.conn.create_consumer(self.topic, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

    def _get_port_infos(self, port, segment, agent_host):
        if not agent_host:
            return

        session = db_api.get_session()
        agent = l2pop_db.get_agent_by_host(session, agent_host)
        if not agent:
            return

        agent_ip = l2pop_db.get_agent_ip(agent)
        if not agent_ip:
            LOG.warning("Unable to retrieve the agent ip, check the agent "
                        "configuration.")
            return

        if not segment:
            LOG.warning("Port %(port)s updated by agent %(agent)s "
                        "isn't bound to any segment",
                        {'port': port['id'], 'agent': agent})
            return

        network_types = l2pop_db.get_agent_l2pop_network_types(agent)
        if network_types is None:
            network_types = l2pop_db.get_agent_tunnel_types(agent)
        if segment['network_type'] not in network_types:
            return

        fdb_entries = [l2pop_rpc.PortInfo(mac_address=port['mac_address'],
                                          ip_address=ip['ip_address'])
                       for ip in port['fixed_ips']]
        return agent_ip, fdb_entries

    @log_helpers.log_method_call
    def _get_agent_fdb(self, port, segment, agent_host):
        agent_ip, port_fdb_entries = self._get_port_infos(port,
                                                          segment,
                                                          agent_host)
        if not port_fdb_entries:
            return

        network_id = port['network_id']
        other_fdb_entries = {network_id:
                             {'segment_id': segment['segmentation_id'],
                              'network_type': segment['network_type'],
                              'ports': {agent_ip: []}}}

        # Agent is removing its last activated port in this network,
        # other agents needs to be notified to delete their flooding entry.
        other_fdb_entries[network_id]['ports'][agent_ip].append(
            nc_const.FLOODING_ENTRY)
        # Notify other agents to remove fdb rules for current port
        if port['device_owner'] != nc_const.DEVICE_OWNER_DVR_INTERFACE:
            fdb_entries = port_fdb_entries
            other_fdb_entries[network_id]['ports'][agent_ip] += fdb_entries

        return other_fdb_entries

    @log_helpers.log_method_call
    def _get_remote_pop_ports(self, flow_rule):
        pop_ports = []
        if not flow_rule.get('next_hops', None):
            return pop_ports
        pop_host = flow_rule['host_id']
        core_plugin = directory.get_plugin()
        drivers = core_plugin.mechanism_manager.mech_drivers
        l2pop_driver = drivers.get('l2population', None)
        if l2pop_driver is None:
            return pop_ports
        session = db_api.get_session()
        for next_hop in flow_rule['next_hops']:
            agent_active_ports = \
                l2pop_db.get_agent_network_active_port_count(
                    session,
                    pop_host,
                    next_hop['net_uuid'])
            segment = {}
            if agent_active_ports == 0:
                filters = {'network_id': [next_hop['net_uuid']],
                           'mac_address': [next_hop['mac_address']]}
                ports = core_plugin.get_ports(self.admin_context,
                                              filters=filters)
                if not ports:
                    continue
                segment['network_type'] = next_hop['network_type']
                segment['segmentation_id'] = next_hop['segment_id']
                pop_ports.append((ports[0], segment))

        return pop_ports

    @log_helpers.log_method_call
    def _get_network_other_active_entry_count(self, host, remote_port_id):
        agent_active_ports = 0
        port_detail = self.get_port_detail_by_filter(
            dict(ingress=remote_port_id))
        for assoc in port_detail['path_nodes']:
            node = self.get_path_node(assoc['pathnode_id'])
            if node['node_type'] != ovs_const.SRC_NODE:
                filter = dict(nsp=node['nsp'],
                              nsi=node['nsi'] + 1)
                pre_node = self.get_path_node_by_filter(filter)
                if not pre_node:
                    continue
                for each in pre_node['portpair_details']:
                    pre_port = self.get_port_detail_by_filter(dict(id=each))
                    if host == pre_port['host_id']:
                        agent_active_ports += 1

        return agent_active_ports

    def _call_on_l2pop_driver(self, flow_rule, method_name):
        pop_host = flow_rule['host_id']
        pop_ports = self._get_remote_pop_ports(flow_rule)
        for (port, segment) in pop_ports:
            port_id = port['id']
            host_id = port['binding:host_id']
            active_entry_count = self._get_network_other_active_entry_count(
                pop_host,
                port_id)

            if active_entry_count == 1:
                fdb_entry = self._get_agent_fdb(
                    port,
                    segment,
                    host_id)

                getattr(l2pop_rpc.L2populationAgentNotifyAPI(), method_name)(
                    self.rpc_ctx, fdb_entry, pop_host)

    def _update_agent_fdb_entries(self, flow_rule):
        self._call_on_l2pop_driver(flow_rule, "add_fdb_entries")

    def _delete_agent_fdb_entries(self, flow_rule):
        self._call_on_l2pop_driver(flow_rule, "remove_fdb_entries")

    def _get_subnet_by_port(self, id):
        core_plugin = directory.get_plugin()
        port = core_plugin.get_port(self.admin_context, id)
        subnet = None
        for ip in port['fixed_ips']:
            subnet = core_plugin.get_subnet(self.admin_context,
                                            ip["subnet_id"])
            # currently only support one subnet for a port
            break

        return subnet

    @log_helpers.log_method_call
    def _get_portgroup_members(self, context, pg_id, fwd_path):
        next_group_members = []
        ppg_obj = context._plugin._get_port_pair_group(context._plugin_context,
                                                       pg_id)
        group_intid = ppg_obj['group_id']
        LOG.debug('group_intid: %s', group_intid)
        pg = context._plugin.get_port_pair_group(context._plugin_context,
                                                 pg_id)
        for pp_id in pg['port_pairs']:
            pp = context._plugin.get_port_pair(context._plugin_context, pp_id)
            filters = {}
            if pp.get('ingress', None):
                filters.update({'ingress': pp['ingress']})
            if pp.get('egress', None):
                filters.update({'egress': pp['egress']})
            pd = self.get_port_detail_by_filter(filters)
            if pd:
                next_group_members.append(
                    dict(portpair_id=pd['id'], weight=1))
        if fwd_path is False:
            next_group_members.reverse()
        return group_intid, next_group_members

    def _get_port_pair_detail_by_port_pair(self, context, port_pair_id):
        pp = context._plugin.get_port_pair(context._plugin_context,
                                           port_pair_id)
        filters = {}
        if pp.get('ingress', None):
            filters.update({'ingress': pp['ingress']})
        if pp.get('egress', None):
            filters.update({'egress': pp['egress']})
        pd = self.get_port_detail_by_filter(filters)

        return pd

    @log_helpers.log_method_call
    def _add_flowclassifier_port_assoc(self, fc_ids, project_id,
                                       src_node):
        for fc in self._get_fcs_by_ids(fc_ids):
            need_assoc = True
            # lookup the source port, when it's reverse path
            # set logical_destination_port to be source port
            if src_node['fwd_path'] is False:
                src_pd_filter = dict(
                    egress=fc['logical_destination_port'],
                    project_id=project_id,
                )
            else:
                src_pd_filter = dict(
                    egress=fc['logical_source_port'],
                    project_id=project_id,
                )
            src_pd = self.get_port_detail_by_filter(src_pd_filter)

            if not src_pd:
                # Create source port detail
                src_pd = self._create_port_pair_detail(src_pd_filter)
                LOG.debug('create src port detail: %s', src_pd)
            else:
                for path_node in src_pd['path_nodes']:
                    if path_node['pathnode_id'] == src_node['id']:
                        need_assoc = False
            if need_assoc:
                # Create associate relationship
                assco_args = {
                    'portpair_id': src_pd['id'],
                    'pathnode_id': src_node['id'],
                    'weight': 1,
                }
                sna = self.create_pathport_assoc(assco_args)
                LOG.debug('create assoc src port with node: %s', sna)
                src_node['portpair_details'].append(src_pd['id'])

    def _remove_flowclassifier_port_assoc(self, fc_ids, project_id,
                                          src_nodes):
        if not fc_ids:
            return
        for src_node in src_nodes:
            for fc in self._get_fcs_by_ids(fc_ids):
                # delete source port detail
                if src_node['fwd_path'] is False:
                    src_pd_filter = dict(
                        egress=fc['logical_destination_port'],
                        project_id=project_id
                    )
                elif src_node['fwd_path']:
                    src_pd_filter = dict(
                        egress=fc['logical_source_port'],
                        project_id=project_id
                    )
                pds = self.get_port_details_by_filter(src_pd_filter)
                if pds:
                    for pd in pds:
                        # update src_node portpair_details refence info
                        if src_node and pd['id'] in src_node[
                            'portpair_details'
                        ]:
                            self.delete_pathport_assoc(src_node['id'],
                                                       pd['id'])
                            src_node['portpair_details'].remove(pd['id'])
                            # path_nodes is [] when passing from path_node
                            # not delete any src_node in portpair_details table
                            # why need to check len(pd['path_nodes']
                            # if len(pd['path_nodes']) == 1:
                            self.delete_port_pair_detail(pd['id'])

    @log_helpers.log_method_call
    def _create_portchain_path(self, context, port_chain, fwd_path):
        path_nodes = []
        # Create an assoc object for chain_id and path_id
        # context = context._plugin_context
        path_id = port_chain['chain_id']

        if not path_id:
            LOG.error('No path_id available for creating port chain path')
            return

        port_pair_groups = port_chain['port_pair_groups']
        sf_path_length = len(port_pair_groups)

        # Detect cross-subnet transit
        # Compare subnets for logical source ports
        # and first PPG ingress ports
        for fc in self._get_fcs_by_ids(port_chain['flow_classifiers']):
            subnet1 = self._get_subnet_by_port(fc['logical_source_port'])
            cidr1 = subnet1['cidr']
            ppg = context._plugin.get_port_pair_group(context._plugin_context,
                                                      port_pair_groups[0])
            for pp_id1 in ppg['port_pairs']:
                pp1 = context._plugin.get_port_pair(context._plugin_context,
                                                    pp_id1)
                filter1 = {}
                if pp1.get('ingress', None):
                    filter1 = dict(dict(ingress=pp1['ingress']), **filter1)
                    pd1 = self.get_port_detail_by_filter(filter1)
                    subnet2 = self._get_subnet_by_port(pd1['ingress'])
                    cidr2 = subnet2['cidr']
                    if cidr1 != cidr2:
                        LOG.error('Cross-subnet chain not supported')
                        raise exc.SfcDriverError(
                            method='create_portchain_path')

        # Compare subnets for PPG egress ports
        # and next PPG ingress ports
        for i in range(sf_path_length - 1):
            ppg = context._plugin.get_port_pair_group(context._plugin_context,
                                                      port_pair_groups[i])
            next_ppg = context._plugin.get_port_pair_group(
                context._plugin_context, port_pair_groups[i + 1])
            for pp_id1 in ppg['port_pairs']:
                pp1 = context._plugin.get_port_pair(context._plugin_context,
                                                    pp_id1)
                filter1 = {}
                cidr3 = None
                if pp1.get('egress', None):
                    filter1 = dict(dict(egress=pp1['egress']), **filter1)
                    pd1 = self.get_port_detail_by_filter(filter1)
                    subnet1 = self._get_subnet_by_port(pd1['egress'])
                    cidr3 = subnet1['cidr']

                for pp_id2 in next_ppg['port_pairs']:
                    pp2 = context._plugin.get_port_pair(
                        context._plugin_context, pp_id2)
                    filter2 = {}
                    if pp2.get('ingress', None):
                        filter2 = dict(dict(ingress=pp2['ingress']), **filter2)
                        pd2 = self.get_port_detail_by_filter(filter2)
                        subnet2 = self._get_subnet_by_port(pd2['ingress'])
                        cidr4 = subnet2['cidr']
                        if cidr3 != cidr4:
                            LOG.error('Cross-subnet chain not supported')
                            raise exc.SfcDriverError(
                                method='create_portchain_path')

        next_group_intid = None
        next_group_members = None
        # get the init and last port_pair_group
        if fwd_path:
            next_group_intid, next_group_members = self._get_portgroup_members(
                context, port_chain['port_pair_groups'][0], fwd_path)

        else:
            next_group_intid, next_group_members = self._get_portgroup_members(
                context,
                port_chain['port_pair_groups'][sf_path_length - 1],
                fwd_path)

        # Create a head node object for port chain
        src_args = {'project_id': port_chain['project_id'],
                    'node_type': ovs_const.SRC_NODE,
                    'nsp': path_id,
                    'nsi': 0xff,
                    'portchain_id': port_chain['id'],
                    'status': ovs_const.STATUS_BUILDING,
                    'next_group_id': next_group_intid,
                    'next_hop': jsonutils.dumps(next_group_members),
                    'fwd_path': fwd_path,
                    'ppg_n_tuple_mapping': None
                    }
        src_node = self.create_path_node(src_args)
        LOG.debug('create src node: %s', src_node)
        path_nodes.append(src_node)

        # Create a destination node object for port chain
        dst_args = {
            'project_id': port_chain['project_id'],
            'node_type': ovs_const.DST_NODE,
            'nsp': path_id,
            'nsi': 0xff - sf_path_length - 1,
            'portchain_id': port_chain['id'],
            'status': ovs_const.STATUS_BUILDING,
            'next_group_id': None,
            'next_hop': None,
            'fwd_path': fwd_path,
            'ppg_n_tuple_mapping': None
        }
        dst_node = self.create_path_node(dst_args)
        LOG.debug('create dst node: %s', dst_node)
        path_nodes.append(dst_node)

        # need to pass project_id here
        self._add_flowclassifier_port_assoc(
            port_chain['flow_classifiers'],
            port_chain['project_id'],
            src_node
        )

        curr_group = context._plugin.get_port_pair_group(
            context._plugin_context, port_pair_groups[0])
        for i in range(sf_path_length):
            cur_group_members = next_group_members
            # next_group for next hop
            if i < sf_path_length - 1:
                if fwd_path:
                    next_group_intid, next_group_members = (
                        self._get_portgroup_members(
                            context, port_pair_groups[i + 1], fwd_path)
                    )
                elif fwd_path is False:
                    next_group_intid, next_group_members = (
                        self._get_portgroup_members(
                            context,
                            port_pair_groups[sf_path_length - 2 - i],
                            fwd_path)
                    )
            else:
                next_group_intid = None
                next_group_members = None

            # Get current port_pair_group based on current port_pair_group id
            if i < sf_path_length:
                if fwd_path:
                    curr_group = context._plugin.get_port_pair_group(
                        context._plugin_context, port_pair_groups[i])
                elif fwd_path is False:
                    curr_group = context._plugin.get_port_pair_group(
                        context._plugin_context,
                        port_pair_groups[sf_path_length - 1 - i])

            # Set curr_ppg_flag = 1, when current port_pair_group has
            # ppg_n_tuple_mapping dict in port_pair_group_parameters
            ppg_n_tuple_mapping = curr_group.get(
                'port_pair_group_parameters', None)
            if ppg_n_tuple_mapping:
                ppg_n_tuple_mapping = ppg_n_tuple_mapping.get(
                    'ppg_n_tuple_mapping', None)
                if ppg_n_tuple_mapping:
                    if ppg_n_tuple_mapping.get('ingress_n_tuple', None) or \
                            ppg_n_tuple_mapping.get('egress_n_tuple', None):
                        ppg_n_tuple_mapping['curr_ppg_flag'] = 1
                    else:
                        ppg_n_tuple_mapping = None

            # Create a node object
            node_args = {
                'project_id': port_chain['project_id'],
                'node_type': ovs_const.SF_NODE,
                'nsp': path_id,
                'nsi': 0xfe - i,
                'portchain_id': port_chain['id'],
                'status': ovs_const.STATUS_BUILDING,
                'next_group_id': next_group_intid,
                'next_hop': (
                    None if not next_group_members else
                    jsonutils.dumps(next_group_members)
                ),
                'fwd_path': fwd_path,
                'ppg_n_tuple_mapping': (
                    None if not ppg_n_tuple_mapping else
                    jsonutils.dumps(ppg_n_tuple_mapping))
            }
            sf_node = self.create_path_node(node_args)
            LOG.debug('chain path node: %s', sf_node)
            # Create the assocation objects that combine the pathnode_id with
            # the ingress of the port_pairs in the current group
            # when port_group does not reach tail
            for member in cur_group_members:
                assco_args = {'portpair_id': member['portpair_id'],
                              'pathnode_id': sf_node['id'],
                              'weight': member['weight'], }
                sfna = self.create_pathport_assoc(assco_args)
                LOG.debug('create assoc port with node: %s', sfna)
                sf_node['portpair_details'].append(member['portpair_id'])
            path_nodes.append(sf_node)

            path_nodes = self._update_ppg_n_tuple_in_flow_rule(
                path_nodes, fwd_path, sf_path_length)

        return path_nodes

    # Function to update adjacent node ppg_n_tuple_mapping values if have
    # ppg_n_tuple_mapping in path_nodes
    def _update_ppg_n_tuple_in_flow_rule(self, path_nodes,
                                         fwd_path, sf_path_length):
        for index, node in enumerate(path_nodes):
            if not node['ppg_n_tuple_mapping']:
                # Update reverse SRC_NODE ppg_n_tuple_mapping based on last
                # forward SF_NODE ppg_n_tuple_mapping
                if (
                    node['node_type'] == ovs_const.SRC_NODE and
                    fwd_path is False
                ):
                    last_fwd_sf_node = self.get_path_node_by_filter(
                        filters={'portchain_id': node['portchain_id'],
                                 'nsi': 0xff - sf_path_length,
                                 'fwd_path': True}
                    )
                    if last_fwd_sf_node:
                        if last_fwd_sf_node['ppg_n_tuple_mapping']:
                            ppg_n_tuple_mapping = jsonutils.loads(
                                last_fwd_sf_node['ppg_n_tuple_mapping'])
                            if (
                                ppg_n_tuple_mapping.get(
                                    'ingress_n_tuple', None) or
                                ppg_n_tuple_mapping.get('egress_n_tuple', None)
                            ):
                                # Set curr_ppg_flag = 2 when
                                # ppg_n_tuple_mapping inherits from
                                # last_fwd_sf_node
                                ppg_n_tuple_mapping['curr_ppg_flag'] = 2
                                node = self.update_path_node(
                                    node['id'],
                                    {'ppg_n_tuple_mapping':
                                     None if not ppg_n_tuple_mapping else
                                     jsonutils.dumps(ppg_n_tuple_mapping)}
                                )
                                path_nodes[index] = node
                # Update SF_NODE ppg_n_tuple_mapping based on current
                # ppg_n_tuple_mapping and prev_node ppg_n_tuple_mapping
                elif node['node_type'] == ovs_const.SF_NODE:
                    if node['nsi'] == 0xfe:
                        prev_node = path_nodes[index - 2]
                    else:
                        prev_node = path_nodes[index - 1]
                    if prev_node:
                        if prev_node['ppg_n_tuple_mapping']:
                            ppg_n_tuple_mapping = jsonutils.loads(
                                prev_node['ppg_n_tuple_mapping'])
                            # Set curr_ppg_flag = 2 when
                            # ppg_n_tuple_mapping inherits from previous
                            # sf_node. Set curr_ppg_flag = 3 when
                            # ppg_n_tuple_mapping inherits from previous
                            # sf_node, and fwd_path is False
                            if (
                                ppg_n_tuple_mapping.get(
                                    'ingress_n_tuple', None) or
                                ppg_n_tuple_mapping.get('egress_n_tuple', None)
                            ):
                                if (
                                    ppg_n_tuple_mapping['curr_ppg_flag'] == 1
                                    and fwd_path is False
                                ):
                                    ppg_n_tuple_mapping['curr_ppg_flag'] = 3
                                else:
                                    ppg_n_tuple_mapping['curr_ppg_flag'] = 2
                                node = self.update_path_node(
                                    node['id'],
                                    {'ppg_n_tuple_mapping':
                                     None if not ppg_n_tuple_mapping else
                                     jsonutils.dumps(ppg_n_tuple_mapping)}
                                )
                                path_nodes[index] = node
        return path_nodes

    def _delete_path_node_port_flowrule(self, node, port, pc_corr, fc_ids):
        # if this port is not binding, don't to generate flow rule
        if not port['host_id']:
            return
        flow_rule = self._build_portchain_flowrule_body(node,
                                                        port,
                                                        pc_corr,
                                                        del_fc_ids=fc_ids)
        self.ovs_driver_rpc.ask_agent_to_delete_flow_rules(self.admin_context,
                                                           flow_rule)
        self._delete_agent_fdb_entries(flow_rule)

    def _delete_path_node_flowrule(self, node, pc_corr, fc_ids):
        if node['portpair_details'] is None:
            return
        for each in node['portpair_details']:
            port = self.get_port_detail_by_filter(dict(id=each))
            if port:
                self._delete_path_node_port_flowrule(
                    node, port, pc_corr, fc_ids)

    @log_helpers.log_method_call
    def _delete_portchain_path(self, port_chain):
        pds = self.get_path_nodes_by_filter(
            dict(portchain_id=port_chain['id']))
        src_nodes = []
        if pds:
            for pd in pds:
                if pd['node_type'] == ovs_const.SRC_NODE:
                    src_nodes.append(pd)
                pc_corr = port_chain['chain_parameters']['correlation']
                self._delete_path_node_flowrule(
                    pd,
                    pc_corr,
                    port_chain['flow_classifiers']
                )
            for pd in pds:
                self.delete_path_node(pd['id'])

        # delete the ports on the traffic classifier
        self._remove_flowclassifier_port_assoc(
            port_chain['flow_classifiers'],
            port_chain['project_id'],
            src_nodes
        )

    def _update_path_node_next_hops(self, flow_rule):
        node_next_hops = []
        if not flow_rule['next_hop']:
            return None
        next_hops = jsonutils.loads(flow_rule['next_hop'])
        if not next_hops:
            return None
        core_plugin = directory.get_plugin()
        for member in next_hops:
            detail = {}
            port_detail = self.get_port_detail_by_filter(
                dict(id=member['portpair_id']))
            if not port_detail or not port_detail['host_id']:
                continue
            detail['local_endpoint'] = port_detail['local_endpoint']
            detail['weight'] = member['weight']
            detail['mac_address'] = port_detail['mac_address']
            detail['in_mac_address'] = port_detail['in_mac_address']
            detail['segment_id'] = port_detail['segment_id']
            detail['network_type'] = port_detail['network_type']
            detail['pp_corr'] = port_detail['correlation']
            port = core_plugin.get_port(
                self.admin_context, port_detail['ingress'])
            detail['net_uuid'] = port['network_id']
            node_next_hops.append(detail)
        flow_rule['next_hops'] = node_next_hops
        flow_rule.pop('next_hop')

        return node_next_hops

    # As of the "no-SFC-proxy" MPLS correlation support, pc_corr is passed.
    # pc_corr is expected to be the port-chain's correlation parameter, i.e.
    # the chain-wide SFC Encapsulation protocol. This is necessary to compare
    # with port-pairs' correlations and decide whether SFC Proxy is needed.
    def _build_portchain_flowrule_body(self, node, port, pc_corr,
                                       add_fc_ids=None, del_fc_ids=None):
        node_info = node.copy()
        node_info.pop('project_id')
        node_info.pop('portpair_details')

        port_info = port.copy()
        port_info.pop('project_id')
        port_info.pop('id')
        port_info.pop('path_nodes')
        # port_info.pop('host_id')

        # change egress port in src_nodes
        if(
            node_info['fwd_path'] is False and node_info['node_type'] ==
            ovs_const.SRC_NODE
        ):
            if add_fc_ids is not None:
                fcs = self._get_fcs_by_ids(add_fc_ids)
            elif del_fc_ids is not None:
                fcs = self._get_fcs_by_ids(del_fc_ids)
            for fc in fcs:
                if fc['logical_source_port'] == port_info['egress']:
                    port_info['egress'] = fc['logical_destination_port']

        flow_rule = dict(node_info, **port_info)
        flow_rule['pc_corr'] = pc_corr
        if node_info['node_type'] != ovs_const.SRC_NODE:
            flow_rule['pp_corr'] = port_info.get('correlation', None)
        else:
            # there's no correlation for src nodes
            flow_rule['pp_corr'] = None
        flow_rule.pop('correlation')  # correlation becomes simply pp_corr

        # if this port belongs to an SFC Encapsulation-aware VM,
        # only notify the flow classifier for the 1st SF.
        flow_rule['add_fcs'] = self._filter_flow_classifiers(
            flow_rule, add_fc_ids)
        flow_rule['del_fcs'] = self._filter_flow_classifiers(
            flow_rule, del_fc_ids)

        self._update_portchain_group_reference_count(flow_rule,
                                                     port['host_id'])
        # update next hop info
        self._update_path_node_next_hops(flow_rule)

        return flow_rule

    def _filter_flow_classifiers(self, flow_rule, fc_ids):
        """Filter flow classifiers.

        @return: list of the flow classifiers
        """

        fc_return = []

        if not fc_ids:
            return fc_return
        fcs = self._get_fcs_by_ids(fc_ids)
        for fc in fcs:
            new_fc = fc.copy()
            new_fc.pop('id')
            new_fc.pop('name')
            new_fc.pop('project_id')
            new_fc.pop('description')
            router_ints = const.ROUTER_INTERFACE_OWNERS
            logical_source_port = new_fc['logical_source_port']
            if logical_source_port is not None:
                port_src = self._get_by_id(
                    self.admin_context, models_v2.Port, logical_source_port
                )
                if (
                    new_fc['source_ip_prefix'] is None and
                    port_src['device_owner'] not in router_ints
                ):
                    src_ips = port_src['fixed_ips']
                    # For now, only handle when the port has a single IP
                    if len(src_ips) == 1:
                        new_fc['source_ip_prefix'] = src_ips[0]['ip_address']

            logical_destination_port = new_fc['logical_destination_port']
            if logical_destination_port is not None:
                port_dst = self._get_by_id(
                    self.admin_context, models_v2.Port,
                    logical_destination_port
                )
                if (
                    new_fc['destination_ip_prefix'] is None and
                    port_dst['device_owner'] not in router_ints
                ):
                    dst_ips = port_dst['fixed_ips']
                    # For now, only handle when the port has a single IP
                    if len(dst_ips) == 1:
                        new_fc['destination_ip_prefix'] = (
                            dst_ips[0]['ip_address']
                        )
            # Update new_fc n tuple info based flow_rule['ppg_n_tuple_mapping']
            # and flow_rule['fwd_path']
            if flow_rule['ppg_n_tuple_mapping']:
                ppg_n_tuple_mapping = jsonutils.loads(
                    flow_rule['ppg_n_tuple_mapping'])
                if (
                    flow_rule['fwd_path'] is False and
                    ppg_n_tuple_mapping['curr_ppg_flag'] == 1 or
                    ppg_n_tuple_mapping['curr_ppg_flag'] == 3
                ):
                    for ingress_key, ingress_value in \
                            ppg_n_tuple_mapping['ingress_n_tuple'].items():
                        new_fc[ingress_key] = ingress_value
                else:
                    for egress_key, egress_value in \
                            ppg_n_tuple_mapping['egress_n_tuple'].items():
                        new_fc[egress_key] = egress_value

            if flow_rule['fwd_path'] is False:
                # swap logical_source_port & logical_destination_port
                new_fc['logical_source_port'] = fc['logical_destination_port']
                new_fc['logical_destination_port'] = fc['logical_source_port']

            if (
                # add_flow & del_flow in flowrule pass into agent
                flow_rule['node_type'] == ovs_const.SRC_NODE and
                flow_rule['egress'] == new_fc['logical_source_port']
            ):
                fc_return.append(new_fc)

            elif flow_rule['node_type'] == ovs_const.SF_NODE:
                fc_return.append(new_fc)

        return fc_return

    def _update_path_node_port_flowrules(self, node, port, pc_corr,
                                         add_fc_ids=None, del_fc_ids=None):
        # if this port is not binding, don't to generate flow rule
        if not port['host_id']:
            return
        flow_rule = self._build_portchain_flowrule_body(node,
                                                        port,
                                                        pc_corr,
                                                        add_fc_ids=add_fc_ids,
                                                        del_fc_ids=del_fc_ids)
        self.ovs_driver_rpc.ask_agent_to_update_flow_rules(self.admin_context,
                                                           flow_rule)
        self._update_agent_fdb_entries(flow_rule)

    def _update_path_node_flowrules(self, node, pc_corr,
                                    add_fc_ids=None, del_fc_ids=None):
        if node['portpair_details'] is None:
            return
        for each in node['portpair_details']:
            port = self.get_port_detail_by_filter(dict(id=each))
            if port:
                self._update_path_node_port_flowrules(
                    node, port, pc_corr, add_fc_ids, del_fc_ids)

    def _update_path_nodes(self, nodes, pc_corr,
                           add_fc_ids=None, del_fc_ids=None):
        for node in nodes:
            self._update_path_node_flowrules(node, pc_corr,
                                             add_fc_ids, del_fc_ids)

    def _get_portchain_fcs(self, port_chain):
        return self._get_fcs_by_ids(port_chain['flow_classifiers'])

    def _get_fcs_by_ids(self, fc_ids):
        flow_classifiers = []
        if not fc_ids:
            return flow_classifiers

        # Get the portchain flow classifiers
        fc_plugin = (
            directory.get_plugin(flowclassifier.FLOW_CLASSIFIER_EXT)
        )
        if not fc_plugin:
            LOG.warning("Not found the flow classifier service plugin")
            return flow_classifiers

        for fc_id in fc_ids:
            fc = fc_plugin.get_flow_classifier(self.admin_context, fc_id)
            flow_classifiers.append(fc)

        return flow_classifiers

    @log_helpers.log_method_call
    def create_port_chain_precommit(self, context):
        """OVS Driver precommit before transaction committed.

        Make sure the logical_destination_port has been set when
        create symmetric port_chain
        """
        port_chain = context.current
        symmetric = port_chain['chain_parameters'].get('symmetric')
        if symmetric:
            for fc in self._get_fcs_by_ids(port_chain['flow_classifiers']):
                if fc['logical_destination_port'] is None:
                    raise exc.SfcBadRequest(message=(
                        'FlowClassifier %s does not set'
                        'logical_destination_port. logical_destination_port '
                        'needed when symmetric has been set. Please recreate '
                        'FlowClassifier with logical_destination_port and '
                        'destination_ip_prefix.' % fc['id']
                    ))

    @log_helpers.log_method_call
    def create_port_chain(self, context):
        port_chain = context.current
        symmetric = port_chain['chain_parameters'].get('symmetric')
        if symmetric:
            fwd_path_nodes = self._create_portchain_path(context, port_chain,
                                                         True)
            rev_path_nodes = self._create_portchain_path(context, port_chain,
                                                         False)
            self._update_path_nodes(
                fwd_path_nodes,
                port_chain['chain_parameters']['correlation'],
                port_chain['flow_classifiers'],
                None)
            self._update_path_nodes(
                rev_path_nodes,
                port_chain['chain_parameters']['correlation'],
                port_chain['flow_classifiers'],
                None)
        elif symmetric is False:
            path_nodes = self._create_portchain_path(context, port_chain, True)
            self._update_path_nodes(
                path_nodes,
                port_chain['chain_parameters']['correlation'],
                port_chain['flow_classifiers'],
                None)

    @log_helpers.log_method_call
    def delete_port_chain(self, context):
        port_chain = context.current
        LOG.debug("to delete portchain path")
        self._delete_portchain_path(port_chain)

    def _get_diff_set(self, orig, cur):
        orig_set = set(item for item in orig)
        cur_set = set(item for item in cur)

        to_del = orig_set.difference(cur_set)
        to_add = cur_set.difference(orig_set)

        return to_del, to_add

    @log_helpers.log_method_call
    def update_port_chain(self, context):
        port_chain = context.current
        orig = context.original
        self._delete_portchain_path(orig)
        # recreate port_chain after delete the orig
        symmetric = port_chain['chain_parameters'].get('symmetric')
        if symmetric:
            fwd_path_nodes = self._create_portchain_path(context, port_chain,
                                                         True)
            rev_path_nodes = self._create_portchain_path(context, port_chain,
                                                         False)
            self._update_path_nodes(
                fwd_path_nodes,
                port_chain['chain_parameters']['correlation'],
                port_chain['flow_classifiers'],
                None)
            self._update_path_nodes(
                rev_path_nodes,
                port_chain['chain_parameters']['correlation'],
                port_chain['flow_classifiers'],
                None)

        elif symmetric is False:
            path_nodes = self._create_portchain_path(context, port_chain, True)
            self._update_path_nodes(
                path_nodes,
                port_chain['chain_parameters']['correlation'],
                port_chain['flow_classifiers'],
                None)

    @log_helpers.log_method_call
    def create_port_pair_group(self, context):
        pass

    @log_helpers.log_method_call
    def delete_port_pair_group(self, context):
        pass

    @log_helpers.log_method_call
    def update_port_pair_group(self, context):
        current = context.current
        original = context.original

        if set(current['port_pairs']) == set(original['port_pairs']):
            return

        # Update the path_nodes and flows for each port chain that
        # contains this port_pair_group
        # Note: _get_port_pair_group is temporarily used here.
        ppg_obj = context._plugin._get_port_pair_group(context._plugin_context,
                                                       current['id'])
        port_chains = [assoc.portchain_id for assoc in
                       ppg_obj.chain_group_associations]

        for chain_id in port_chains:
            pc = context._plugin.get_port_chain(
                context._plugin_context, chain_id)
            pc_corr = pc['chain_parameters']['correlation']
            group_intid = current['group_id']
            # Get the previous node
            prev_nodes = self.get_path_nodes_by_filter(
                filters={'portchain_id': chain_id,
                         'next_group_id': group_intid})
            if not prev_nodes:
                continue

            for prev_node in prev_nodes:
                before_update_prev_node = prev_node.copy()
                # Update the previous node
                curr_group_intid, curr_group_members = \
                    self._get_portgroup_members(
                        context, current['id'], prev_node['fwd_path'])
                prev_node['next_hop'] = (
                    jsonutils.dumps(curr_group_members)
                    if curr_group_members else None
                )
                # update next hop to database
                self.update_path_node(prev_node['id'], prev_node)
                self._delete_path_node_flowrule(before_update_prev_node,
                                                pc_corr,
                                                pc['flow_classifiers'])
                self._update_path_node_flowrules(prev_node,
                                                 pc_corr,
                                                 pc['flow_classifiers'],
                                                 None)

            # Update the current node
            # to find the current node by using the node's next_group_id
            # if this node is the last, next_group_id would be None
            curr_pos = pc['port_pair_groups'].index(current['id'])
            curr_nodes = self.get_path_nodes_by_filter(
                filters={'portchain_id': chain_id,
                         'nsi': 0xfe - curr_pos})

            if not curr_nodes:
                continue
            curr_node = None
            for temp_node in curr_nodes:
                if temp_node['fwd_path']:
                    curr_node = temp_node

            rev_curr_pos = len(pc['port_pair_groups']) - 1 - curr_pos
            rev_curr_nodes = self.get_path_nodes_by_filter(
                filters={'portchain_id': chain_id,
                         'nsi': 0xfe - rev_curr_pos})
            rev_curr_node = None
            if rev_curr_nodes is not None:
                for temp_node in rev_curr_nodes:
                    if temp_node['fwd_path'] is False:
                        rev_curr_node = temp_node

            # Add the port-pair-details into the current node
            for pp_id in (
                set(current['port_pairs']) - set(original['port_pairs'])
            ):
                ppd = self._get_port_pair_detail_by_port_pair(context,
                                                              pp_id)
                if not ppd:
                    LOG.debug('No port_pair_detail for the port_pair: %s',
                              pp_id)
                    LOG.debug("Failed to update port-pair-group")
                    return

                assco_args = {'portpair_id': ppd['id'],
                              'pathnode_id': curr_node['id'],
                              'weight': 1, }
                self.create_pathport_assoc(assco_args)
                self._update_path_node_port_flowrules(
                    curr_node, ppd, pc_corr, pc['flow_classifiers'])

                if not rev_curr_node:
                    continue
                assco_args = {'portpair_id': ppd['id'],
                              'pathnode_id': rev_curr_node['id'],
                              'weight': 1, }
                self.create_pathport_assoc(assco_args)
                self._update_path_node_port_flowrules(
                    rev_curr_node, ppd, pc_corr, pc['flow_classifiers'])

            # Delete the port-pair-details from the current node
            for pp_id in (
                set(original['port_pairs']) - set(current['port_pairs'])
            ):
                ppd = self._get_port_pair_detail_by_port_pair(context,
                                                              pp_id)
                if not ppd:
                    LOG.debug('No port_pair_detail for the port_pair: %s',
                              pp_id)
                    LOG.debug("Failed to update port-pair-group")
                    return
                self._delete_path_node_port_flowrule(
                    curr_node,
                    ppd,
                    pc_corr,
                    pc['flow_classifiers'])
                self.delete_pathport_assoc(curr_node['id'], ppd['id'])

                if not rev_curr_node:
                    continue

                self._delete_path_node_port_flowrule(
                    rev_curr_node,
                    ppd,
                    pc['flow_classifiers'])
                self.delete_pathport_assoc(rev_curr_node['id'], ppd['id'])

    @log_helpers.log_method_call
    def _get_port_detail_info(self, port_id):
        """Get port detail.

        @param: port_id: uuid
        @return: (host_id, local_ip, network_type, segment_id,
        service_insert_type): tuple
        """

        core_plugin = directory.get_plugin()
        port_detail = core_plugin.get_port(self.admin_context, port_id)
        host_id, local_ip, network_type, segment_id, mac_address = (
            (None, ) * 5)

        if port_detail:
            host_id = port_detail['binding:host_id']
            network_id = port_detail['network_id']
            mac_address = port_detail['mac_address']
            network_info = core_plugin.get_network(
                self.admin_context, network_id)
            network_type = network_info['provider:network_type']
            segment_id = network_info['provider:segmentation_id']

        if network_type != const.TYPE_VXLAN:
            LOG.warning("Currently only support vxlan network")
            return ((None, ) * 5)
        elif not host_id:
            LOG.warning("This port has not been binding")
            return ((None, ) * 5)
        else:
            driver = core_plugin.type_manager.drivers.get(network_type)
            host_endpoint = driver.obj.get_endpoint_by_host(host_id)
            if host_endpoint:
                local_ip = host_endpoint['ip_address']
            else:
                local_ip = None

        return host_id, local_ip, network_type, segment_id, mac_address

    @log_helpers.log_method_call
    def _create_port_pair_detail(self, port_pair):
        # since first node may not assign the ingress port, and last node
        # is not saved in the portpair_detail. we store the major egress port
        # info as the key to get the SF information.
        # mac_address stands for egress mac_address, and in_mac_address stands
        # for ingress_port mac_address
        in_port, e_port, host_id, local_endpoint, network_type, segment_id, \
            mac_address, in_mac_address = (
                (None, ) * 8)

        if port_pair.get('ingress', None):
            in_port = port_pair['ingress']
            in_host_id, in_local_endpoint, in_network_type, in_segment_id, \
                in_mac_address = (
                    self._get_port_detail_info(in_port))
        if port_pair.get('egress', None):
            e_port = port_pair['egress']
            host_id, local_endpoint, network_type, segment_id, mac_address = (
                self._get_port_detail_info(e_port))

        pp_corr = port_pair.get('service_function_parameters')
        if pp_corr:
            pp_corr = pp_corr.get('correlation', None)

        portpair_detail = {
            'ingress': port_pair.get('ingress', None),
            'egress': port_pair.get('egress', None),
            'correlation': pp_corr,
            'project_id': port_pair['project_id'],
            'host_id': host_id,
            'segment_id': segment_id,
            'network_type': network_type,
            'local_endpoint': local_endpoint,
            'mac_address': mac_address,
            'in_mac_address': in_mac_address
        }
        r = self.create_port_pair_detail(portpair_detail)
        LOG.debug('create port-pair detail: %s', r)
        return r

    @log_helpers.log_method_call
    def create_port_pair(self, context):
        port_pair = context.current
        self._create_port_pair_detail(port_pair)

    @log_helpers.log_method_call
    def delete_port_pair(self, context):
        port_pair = context.current

        pd_filter = dict(ingress=port_pair.get('ingress', None),
                         egress=port_pair.get('egress', None),
                         project_id=port_pair['project_id']
                         )
        pds = self.get_port_details_by_filter(pd_filter)
        if pds:
            for pd in pds:
                self.delete_port_pair_detail(pd['id'])

    @log_helpers.log_method_call
    def update_port_pair(self, context):
        pass

    def get_flowrules_by_host_portid(self, context, host, port_id):
        port_chain_flowrules = []
        sfc_plugin = directory.get_plugin(sfc.SFC_EXT)
        if not sfc_plugin:
            return port_chain_flowrules
        try:
            port_detail_list = []
            # one port only may be in egress/ingress port once time.
            ingress_port = self.get_port_detail_by_filter(
                dict(ingress=port_id))
            egress_port = self.get_port_detail_by_filter(
                dict(egress=port_id))
            if not ingress_port and not egress_port:
                return None
            # SF migrate to other host
            if ingress_port:
                port_detail_list.append(ingress_port)
                if ingress_port['host_id'] != host:
                    ingress_port.update(dict(host_id=host))

            if egress_port:
                port_detail_list.append(egress_port)
                if egress_port['host_id'] != host:
                    egress_port.update(dict(host_id=host))

            # this is a SF if there are both egress and engress.
            for i, ports in enumerate(port_detail_list):
                nodes_assocs = ports['path_nodes']
                for assoc in nodes_assocs:
                    # update current path flow rule
                    node = self.get_path_node(assoc['pathnode_id'])
                    port_chain = sfc_plugin.get_port_chain(
                        context,
                        node['portchain_id'])
                    flow_rule = self._build_portchain_flowrule_body(
                        node,
                        ports,
                        port_chain['chain_parameters']['correlation'],
                        add_fc_ids=port_chain['flow_classifiers']
                    )
                    port_chain_flowrules.append(flow_rule)

            return port_chain_flowrules

        except Exception as e:
            LOG.exception(e)
            LOG.error("get_flowrules_by_host_portid failed")

    def update_flowrule_status(self, context, id, status):
        """FIXME

        drivers/ovs/db.py will be removed in the future with 4 ovs tables

        This function raise:
            RuntimeError: reentrant call
            DBError: reentrant call
            DBConnectionError: (pymysql.err.OperationalError)
                (2014, 'Command Out of Sync'))
        """
        pass
        # try:
        #     flowrule_status = dict(status=status)
        #     self.update_path_node(id, flowrule_status)
        # except Exception as e:
        #     LOG.exception(e)
        #     LOG.error("update_flowrule_status failed")

    def _update_portchain_group_reference_count(self, flow_rule, host):
        group_refcnt = 0
        flow_rule['host'] = host

        if flow_rule['next_group_id'] is not None:
            all_nodes = self.get_path_nodes_by_filter(
                filters={'next_group_id': flow_rule['next_group_id'],
                         'nsi': 0xff})
            if all_nodes is not None:
                for node in all_nodes:
                    if not node['portpair_details']:
                        if flow_rule['fwd_path'] == node['fwd_path']:
                            group_refcnt += 1

            port_details = self.get_port_details_by_filter(
                dict(host_id=flow_rule['host']))
            if port_details is not None:
                for pd in port_details:
                    for path in pd['path_nodes']:
                        path_node = self.get_path_node(path['pathnode_id'])
                        if (
                            path_node['next_group_id'] ==
                            flow_rule['next_group_id']
                            and path_node['fwd_path']
                        ):
                            group_refcnt += 1
        flow_rule['group_refcnt'] = group_refcnt

        return group_refcnt
