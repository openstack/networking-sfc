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

from neutron.agent.common import ovs_lib
from neutron_lib import exceptions
from neutron_lib.plugins.ml2 import ovs_constants as ovs_consts
from oslo_log import log as logging

from networking_sfc._i18n import _

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


class SfcOVSBridgeExt():

    def __init__(self, ovs_bridge):
        self.bridge = ovs_bridge

        # OpenFlow 1.3 is needed to manipulate groups
        # To support NSH feature, OpenFlow 1.3 is also needed
        self.bridge.use_at_least_protocol(ovs_consts.OPENFLOW13)

    # proxy most methods to self.bridge
    def __getattr__(self, name):
        return getattr(self.bridge, name)

    def do_action_groups(self, action, kwargs_list):
        group_strs = [_build_group_expr_str(kw, action) for kw in kwargs_list]
        if action in ('add', 'del'):
            cmd = '%s-groups' % action
        elif action == 'mod':
            cmd = '%s-group' % action
        else:
            msg = _("Action is illegal")
            raise exceptions.InvalidInput(error_message=msg)
        self.run_ofctl(cmd, ['-'], '\n'.join(group_strs))

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
                               if ovs_lib.is_a_flow_line(item))
        return retval

    def get_bridge_ports(self):
        port_name_list = self.bridge.get_port_name_list()
        of_portno_list = []
        for port_name in port_name_list:
            of_portno_list.append(self.bridge.get_port_ofport(port_name))
        return of_portno_list


def _build_group_expr_str(group_dict, cmd):
    group_expr_arr = []
    buckets = None
    group_id = None

    if cmd != 'del':
        if "group_id" not in group_dict:
            msg = _("Must specify one group Id on group addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        group_id = "group_id=%s" % group_dict.pop('group_id')

        if "buckets" not in group_dict:
            msg = _("Must specify one or more buckets on group addition"
                    " or modification")
            raise exceptions.InvalidInput(error_message=msg)
        buckets = "%s" % group_dict.pop('buckets')

    if group_id:
        group_expr_arr.append(group_id)

    for key, value in group_dict.items():
        group_expr_arr.append("%s=%s" % (key, value))

    if buckets:
        group_expr_arr.append(buckets)

    return ','.join(group_expr_arr)
