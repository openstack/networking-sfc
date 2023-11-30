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

from neutron_lib import constants as n_const


STATUS_BUILDING = 'building'
STATUS_ACTIVE = 'active'
STATUS_ERROR = 'error'

SRC_NODE = 'src_node'
DST_NODE = 'dst_node'
SF_NODE = 'sf_node'

INSERTION_TYPE_L2 = 'l2'
INSERTION_TYPE_L3 = 'l3'
INSERTION_TYPE_BITW = 'bitw'
INSERTION_TYPE_TAP = 'tap'

MAX_HASH = 16

INSERTION_TYPE_DICT = {
    n_const.DEVICE_OWNER_ROUTER_HA_INTF: INSERTION_TYPE_L3,
    n_const.DEVICE_OWNER_ROUTER_INTF: INSERTION_TYPE_L3,
    n_const.DEVICE_OWNER_ROUTER_GW: INSERTION_TYPE_L3,
    n_const.DEVICE_OWNER_FLOATINGIP: INSERTION_TYPE_L3,
    n_const.DEVICE_OWNER_DHCP: INSERTION_TYPE_TAP,
    n_const.DEVICE_OWNER_DVR_INTERFACE: INSERTION_TYPE_L3,
    n_const.DEVICE_OWNER_AGENT_GW: INSERTION_TYPE_L3,
    n_const.DEVICE_OWNER_ROUTER_SNAT: INSERTION_TYPE_TAP,
    'compute': INSERTION_TYPE_L2
}

ETH_TYPE_IP = 0x0800
ETH_TYPE_MPLS = 0x8847
ETH_TYPE_NSH = 0x894f
