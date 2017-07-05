..
      Copyright 2015 Futurewei. All rights reserved.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


      Convention for heading levels in Neutron devref:
      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4
      (Avoid deeper levels because they do not render well.)


=============================
OVS Driver and Agent Workflow
=============================

Blueprint about `Common Service chaining driver <https://blueprints.launchpad.net/neutron/+spec/common-service-chaining-driver-api>`_ describes the OVS driver and agent necessity for realizing service function chaining.

Problem Description
===================

The service chain OVS driver and agents are used to configure back-end
Openvswitch devices to render service chaining in the data-plane. The driver
manager controls a common service chain API which provides a consistent interface
between the service chain manager and different device drivers.

Proposed Change
===============


Design::

       Port Chain Plugin
      +-------------------------------+
      |  +-------------------------+  |
      |  |    Port Chain API       |  |
      |  +-------------------------+  |
      |  |    Port Chain Database  |  |
      |  +-------------------------+  |
      |  |    Driver Manager       |  |
      |  +-------------------------+  |
      |  |    Common Driver API    |  |
      |  +-------------------------+  |
      |               |               |
      |  +-------------------------+  |
      |  |        OVS Driver       |  |
      |  +-------------------------+  |
      +-------|----------------|------+
              |rpc             |rpc
         +-----------+   +-----------+
         | OVS Agent |   | OVS Agent |
         +-----------+   +-----------+

A OVS service chain driver and agents communicate via rpc.

OVS Driver
----------
The OVS Driver is extended to support service chaining. The driver interfaces
with the OVS agents that reside on each Compute node. The OVS driver is responsible
for the following:

* Identify the OVS agents that directly connects to the SF instances and establish
  communication with OVS agents on the Compute nodes.
* Send commands to the OVS agents to create bridges, flow tables and flows to steer
  chain traffic to the SF instances.

OVS Agent
---------
The OVS agent will manage the OVS using OVSDB commands to create bridges and tables,
and install flows to steer chain traffic to the SF instances.

Existing tunnels between the Tunnel bridges on each Compute node are used to
transport Port Chain traffic between the CNs.

The OVS Agent will create these tunnels to transport SFC traffic between Compute
nodes on which there are SFs. Each tunnel port has the following attributes:

* Name
* Local tunnel IP address
* Remote tunnel IP address
* Tunnel Type: VXLAN, GRE

The OVS agent installs additional flows on the Integration bridge and the Tunnel bridge
to perform the following functions:

* Traffic classification. The Integration bridge classifies traffic from a VM port or
  Service VM port attached to the Integration bridge. The flow classification is based on
  the n-tuple rules.
* Service function forwarding. The Tunnel bridge forwards service chain
  packets to the next-hop Compute node via tunnels, or to the next Service VM port
  on that Compute node. Integration bridge will terminate a Service Function Path.

The OVS Agent will use the MPLS header to transport the chain path identifier
and chain hop index. The MPLS label will transport the chain path identifier,
and the MPLS ttl will transport the chain hop index. The following packet encapsulation
will be used::

    IPv4 Packet:
    +----------+------------------------+-------+
    |L2 header | IP + UDP dst port=4790 | VXLAN |
    +----------+------------------------+-------+
    -----------------------------+---------------+--------------------+
    Original Ethernet, ET=0x8847 | MPLS header   | Original IP Packet |
    -----------------------------+---------------+--------------------+

This is not intended as a general purpose MPLS implementation but rather as a
temporary internal mechanism. It is anticipated that the MPLS label will be
replaced with an NSH encapsulation
(https://datatracker.ietf.org/doc/draft-ietf-sfc-nsh/) once NSH support is
available upstream in Open vSwitch. If the service function does not support
the header, then the vSwitch will act as Service Function Forwarder (SFF)
Proxy which will strip off the header when forwarding the packet to the SF
and re-add the header when receiving the packet from the SF.

OVS Bridge and Tunnel
---------------------
Existing tunnels between the Tunnel bridges on each Compute node are used to
transport Port Chain traffic between the CNs::

         CN1                                 CN2
        +--------------------------+        +-------------------------+
        |  +-----+       +-----+   |        |  +-----+      +-----+   |
        |  | VM1 |       | SF1 |   |        |  | SF2 |      | SF3 |   |
        |  +-----+       +-----+   |        |  +-----+      +-----+   |
        |     |.           ^|.     |        |   ^| |.         ^|.     |
        | +----.-----------.-.--+  |        | +-.---.---------.-.---+ |
        | |    ............. .. |  |        | | .   ........... .   | |
        | | Integration Bridge. |  |        | | .Integration Bridge | |
        | |           ......... |  |        | | ......   ........   | |
        | +-----------.---------+  |        | +-------.--.----------+ |
        |            |.            |        |         .| .            |
        | +-----------.---------+  |        | +-------.--.----------+ |
        | |           .................................  ..................>
        | |    Tunnel Bridge    |-------------|   Tunnel Bridge     | |
        | +---------------------+  | Tunnel | +---------------------+ |
        |                          |        |                         |
        +--------------------=-----+        +-------------------------+



Flow Tables and Flow Rules
--------------------------
The OVS Agent adds additional flows (shown above) on the Integration bridge to support
Port Chains:

1. Egress Port Chain flows to steer traffic from SFs attached to the Integration bridge to a
   Tunnel bridge to the next-hop Compute node. These flows may be handled using the OpenFlow
   Group in the case where there are multiple port-pairs in the next-hop port-pair group.
2. Ingress Port Chain flows on the Tunnel bridge to steer service chain traffic from a
   tunnel from a previous Compute node to SFs attached to the Integration bridge.
3. Internal Port Chain flows are used to steer service chain traffic from one SF to another SF
   on the same Compute Node.

The Port Chain flow rules have the higher priority, and will not impact
the existing flow rules on the Integration bridge. If traffic from SF is not part of
a service chain, e.g.,  DHCP messages, ARP packets etc., it will match the existing
flow rules on the Integration bridge.

The following tables are used to process Port Chain traffic:

* Local Switching Table (Table 0). This existing table has two new flows to handle
  incoming traffic from the SF egress port and the tunnel port between Compute nodes.

* Group Table. This new table is used to select multiple paths for load-balancing across
  multiple port-pairs in a port-pair group. There are multiple buckets in the group if the next
  hop is a port-pair group with multiple port-pairs. The group actions will be to send the packet
  to next hop SF instance.
  If the next hop port-pair is on another Compute node, the action output to the tunnel port to the
  next hop Compute node. If the next hop port-pair is on the same Compute node, then the
  action will be to resubmit to the TUN_TABLE for local chaining process.

Local Switching Table (Table 0) Flows
-------------------------------------
Traffic from SF Egress port: classify for chain and direct to group::

 priority=10,in_port=SF_EGRESS_port,traffic_match_field,
  actions=strip_vlan,set_tunnel:VNI,group:gid.

Traffic from Tunnel port::

 priority=10,in_port=TUNNEL_port,
  actions=resubmit(,TUN_TABLE[type]).


Group Table Flows
-----------------
The Group table is used for load distribution to spread the traffic load across a port-pair group of
multiple port-pairs (SFs of the same type). This uses the hashing of several fields in the packet.
There are multiple buckets in the group if the next hop is a port-pair group with multiple port-pairs.

The group actions will be to send the packet to next hop SF instances. If the next hop port-pair
is on another Compute node, the action output to the tunnel port to the next hop Compute node.
If the next hop port-pair is on the same Compute node, then the action will be to resubmit
to the TUN_TABLE for local chaining process.

The OVSDB command to create a group of type Select with a hash selection method and two buckets
is shown below. This is existing OVS functionality. The ip_src,nw_proto,tp_src packet fields are
used for the hash::

 group_id=gid,type=select,selection_method=hash,fields=ip_src,nw_proto,tp_src
  bucket=set_field:10.1.1.3->ip_dst,output:10,
  bucket=set_field:10.1.1.4->ip_dst,output:10


Data Model Impact
-----------------
None

Alternatives
------------

None

Security Impact
---------------

None.

Notifications Impact
--------------------

There will be logging to trouble-shoot and verify correct operation.

Other End User Impact
---------------------

None.

Performance Impact
------------------

It is not expected that these flows will have a significant performance impact.

IPv6 Impact
-----------

None.

Other Deployer Impact
---------------------

None

Developer Impact
----------------

None

Community Impact
----------------

Existing OVS driver and agent functionality will not be affected.

Implementation
==============

Assignee(s)
-----------

* Cathy Zhang (cathy.h.zhang@huawei.com)
* Louis Fourie (louis.fourie@huawei.com)
* Stephen Wong (stephen.kf.wong@gmail.com)

Work Items
----------

* Port Chain OVS driver.
* Port Chain OVS agent.
* Unit test.

Dependencies
============

This design depends upon the proposed `Neutron Service Chaining API extensions <https://blueprints.launchpad.net/neutron/+spec/neutron-api-extension-for-service-chaining>`_

Openvswitch.

Testing
=======

Tempest and functional tests will be created.

Documentation Impact
====================

Documented as extension.

User Documentation
------------------

Update networking API reference.
Update admin guide.

Developer Documentation
-----------------------

None

