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

import collections
import six

from neutron_lib import exceptions
from oslo_log import log as logging

from neutron.agent.common import ovs_lib
from neutron.agent.common import utils
from neutron.plugins.common import constants
from neutron.plugins.ml2.drivers.openvswitch.agent.openflow.ovs_ofctl import (
    ovs_bridge)

from networking_sfc._i18n import _, _LE

# Special return value for an invalid OVS ofport
INVALID_OFPORT = '-1'

LOG = logging.getLogger(__name__)


def get_port_mask(min_port, max_port):
    """get port/mask serial by port range."""
    if min_port < 1 or max_port > 0xffff or min_port > max_port:
        msg = _("the port range is invalid")
        raise exceptions.InvalidInput(error_message=msg)
    masks = []
    while min_port <= max_port:
        mask = 0xffff
        while mask != 0:
            next_mask = (mask << 1) & 0xffff
            port_start = min_port & next_mask
            port_end = min_port + (next_mask ^ 0xffff)
            if port_start == min_port and port_end <= max_port:
                mask = next_mask
            else:
                break
        masks.append('0x%x/0x%x' % (min_port, mask))
        min_port = min_port + (mask ^ 0xffff) + 1

    return masks


class OVSBridgeExt(ovs_bridge.OVSAgentBridge):
    def setup_controllers(self, conf):
        self.set_protocols("[]")
        self.del_controller()

    def dump_flows_full_match(self, flow_str):
        retval = None
        flows = self.run_ofctl("dump-flows", [flow_str])
        if flows:
            retval = '\n'.join(item for item in flows.splitlines()
                               if 'NXST' not in item and 'OFPST' not in item)
        return retval

    def mod_flow(self, **kwargs):
        flow_copy = kwargs.copy()
        flow_copy.pop('actions')
        flow_str = ovs_lib._build_flow_expr_str(flow_copy, 'del')
        dump_flows = self.dump_flows_full_match(flow_str)
        if dump_flows == '':
            self.do_action_flows('add', [kwargs])
        else:
            self.do_action_flows('mod', [kwargs])

    def add_nsh_tunnel_port(self, port_name, remote_ip, local_ip,
                            tunnel_type=constants.TYPE_GRE,
                            vxlan_udp_port=constants.VXLAN_UDP_PORT,
                            dont_fragment=True,
                            in_nsp=None,
                            in_nsi=None):
        attrs = [('type', tunnel_type)]
        # This is an OrderedDict solely to make a test happy
        options = collections.OrderedDict()
        vxlan_uses_custom_udp_port = (
            tunnel_type == constants.TYPE_VXLAN and
            vxlan_udp_port != constants.VXLAN_UDP_PORT
        )
        if vxlan_uses_custom_udp_port:
            options['dst_port'] = vxlan_udp_port
        options['df_default'] = str(dont_fragment).lower()
        options['remote_ip'] = 'flow'
        options['local_ip'] = local_ip
        options['in_key'] = 'flow'
        options['out_key'] = 'flow'
        if in_nsp is not None and in_nsi is not None:
            options['nsp'] = str(in_nsp)
            options['nsi'] = str(in_nsi)
        elif in_nsp is None and in_nsi is None:
            options['nsp'] = 'flow'
            options['nsi'] = 'flow'
        attrs.append(('options', options))
        ofport = self.add_port(port_name, *attrs)
        if (
            tunnel_type == constants.TYPE_VXLAN and
            ofport == INVALID_OFPORT
        ):
            LOG.error(
                _LE('Unable to create VXLAN tunnel port for service chain. '
                    'Please ensure that an openvswitch version that supports '
                    'VXLAN for service chain is installed.')
            )
        return ofport

    def run_ofctl(self, cmd, args, process_input=None):
        # We need to dump-groups according to group Id,
        # which is a feature of OpenFlow1.5
        full_args = [
            "ovs-ofctl", "-O openflow13", cmd, self.br_name
        ] + args
        LOG.debug('execute ovs command %s %s', full_args, process_input)
        try:
            return utils.execute(full_args, run_as_root=True,
                                 process_input=process_input)
        except Exception as e:
            LOG.exception(e)
            LOG.error(_LE("Unable to execute %(args)s."),
                      {'args': full_args})

    def do_action_groups(self, action, kwargs_list):
        group_strs = [_build_group_expr_str(kw, action) for kw in kwargs_list]
        if action == 'add' or action == 'del':
            self.run_ofctl('%s-groups' % action, ['-'], '\n'.join(group_strs))
        elif action == 'mod':
            self.run_ofctl('%s-group' % action, ['-'], '\n'.join(group_strs))
        else:
            msg = _("Action is illegal")
            raise exceptions.InvalidInput(error_message=msg)

    def add_group(self, **kwargs):
        self.do_action_groups('add', [kwargs])

    def mod_group(self, **kwargs):
        self.do_action_groups('mod', [kwargs])

    def delete_group(self, **kwargs):
        self.do_action_groups('del', [kwargs])

    def dump_group_for_id(self, group_id):
        retval = None
        group_str = "%d" % group_id
        group = self.run_ofctl("dump-groups", [group_str])
        if group:
            retval = '\n'.join(item for item in group.splitlines()
                               if 'NXST' not in item)
        return retval


def _build_group_expr_str(group_dict, cmd):
    group_expr_arr = []
    buckets = None
    groupId = None

    if cmd != 'del':
        if "group_id" not in group_dict:
            msg = _("Must specify one group Id on group addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        groupId = "group_id=%s" % group_dict.pop('group_id')

        if "buckets" not in group_dict:
            msg = _("Must specify one or more buckets on group addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        buckets = "%s" % group_dict.pop('buckets')

    if groupId:
        group_expr_arr.append(groupId)

    for key, value in six.iteritems(group_dict):
        group_expr_arr.append("%s=%s" % (key, value))

    if buckets:
        group_expr_arr.append(buckets)

    return ','.join(group_expr_arr)
