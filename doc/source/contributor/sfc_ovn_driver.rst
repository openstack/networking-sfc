..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode


===========================
Networking-sfc / OVN Driver
===========================

https://blueprints.launchpad.net/networking-sfc/+spec/networking-sfc-ovn-driver

This specification describes a networking-sfc driver that will interface with
a new Logical Port Chain resource API for the `OVN <http://openvswitch.org/support/dist-docs-2.5/ovn-architecture.7.html>`_ infrastructure. The driver will
translate networking-sfc requests into Logical Port Chain resources in the OVN
northbound DB. These Logical Port Chain resources are created in OVN by updating
the appropriate tables in the OVN northbound database (an ovsdb database).

Problem Description
===================

networking-sfc allows various drivers to be used. Currently, drivers exist for
OVS, ONOS and ODL infrastructures. Service chaining is being added to OVN and a
driver is required to interface between networking-sfc and the OVN
infrastructure.

Proposed Changes
================
The proposed extensions to the OVN northbound DB schema and API are described
briefly here. Refer to openvswitch documentation for details. In addition the
new OVN driver for networking-sfc will map from networking-sfc requests
to Logical Port Chain resources in the OVN northbound DB via the networking-ovn
driver.

The OVN driver for networking-sfc is shown below.

::

    +-------------------------------------------------------+
    |  +-----------------------+  +----------------------+  |
    |  |   Port Chain API      |  |  Neutron API         |  |
    |  +-----------------------+  +----------------------+  |
    |  |   Driver Manager      |  |  ML2 Manager         |  |
    |  +-----------------------+  +----------------------+  |
    |  |   Common Driver API   |  |  ML2 Driver API      |  |
    |  +-----------------------+  +----------------------+  |
    |             |                         |               |
    |             v                         v               |
    |  +=======================+  +----------------------+  |
    |  |     networking-sfc /  |->|  networking-ovn      |  |
    |  |      OVN Driver       |  |   ML2 Driver         |  |
    |  +=======================+  +----------------------+  |
    |                                   |     Neutron Server|
    +-----------------------------------|-------------------+
                                        |
    +-----------------------------------|-------------------+
    |                                   v                   |
    |                  +-----------------------+            |
    |                  |   OVN Northbound DB   |            |
    |                  +-----------------------+ OVS Server |
    +-------------------------------------------------------+


OVN Northbound Port Chain DB
============================

The proposed OVN northbound DB extensions for Logical Port Chains are
shown below with three new resources:

- Logical Port Chain
- Logical Port Pair Group
- Logical Port Pair


::

               action=sfc         port-pair-
    +---------+       +=========+  groups +===========+
    |         |       | Logical |         |  Logical  |
    |  ACL    |------>| Port    |-------->| Port Pair |
    |         |1     1| Chain   |1       *|   Group   |
    +---------+       +=========+         +===========+
         ^*                           port-pairs |1
         |                                       |
    acls |1                                      v*
    +---------+ports  +---------+1      1 +===========+
    | Logical |------>| Logical |<--------|  Logical  |
    | Switch  |1     *| Switch  | inport/ | Port Pair |
    |         |       | Port    | outport |           |
    +---------+       +---------+         +===========+


The OVN ACL actions are extended to include a SFC action with an external_id
to reference the name of the Logical Port Chain (lchain) with which the ACL is
associated.
The sfc action means that the packet is allowed and steered into the port-chain.

Logical Port Chain
------------------
A Logical Port Chain can contain one or more Logical Port Pair Groups.
The order of Logical Port Pair Groups in the Logical Port Chain
specifies the order of steering packets through the Port Chain from
the outport of a Logical Port Pair in one Logical Port Pair Group
to the inport of a Logical Port Pair in the next Logical Port Pair Group.

Logical Port Pair Group
-----------------------
A Logical Port Pair Group can contain one or more Logical Port Pairs and
is used to load balance traffic across the Service Functions (Logical Port
Pairs) in the Logical Port Pair Group.
A Logical Port Pair Group can be a member of multiple Logical Port Chains.

Logical Port Pair
-----------------
A Logical Port Pair represents the ingress Logical Switch Port and the egress
Logical Switch Port of a Service Function. A Logical Port Pair can be a member
of only one Logical Port Pair Group. An OVN Logical Switch Port can be a member
of only one Logical Port Pair.

ACL
---

The existing OVN ACL action will be extended to add a sfc action with an
external_id to reference the name of the Logical Port Chain with which
the ACL is associated.

Networking-sfc / OVN Driver
===========================
The networking-sfc / OVN driver maps the Port Chain commands to OVN ovn-nbctl commands.

Port-chain to lport-chain Mapping
---------------------------------
A Port-chain is mapped to a single lport-chain.

Port-pair-group to lport-pair-group Mapping
-------------------------------------------
A Port-pair-group is mapped to a single lport-pair-group.

Port-pair to lport-pair Mapping
-------------------------------
A Port-pair is mapped to a single lport-pair.


Flow-classifier to OVN ACL Mapping
----------------------------------
Flow-classifers will be mapped to OVN ACLs as follows. A flow-classifier
is mapped to a single OVN ACL.

When a flow-classifier is created its OVN ACL is created at that time.
The OVN ACL is only created when the flow-classifier is associated with
the port-chain: Then the driver does:

    acl-add lswitch direction priority match sfc [lchain=<lport-chain>]

When a port-chain is updated to add/remove flow-classifiers then the necessary
OVN ACLs are created and deleted.

If a port-chain that has flow-classifiers associated with it is deleted, then
the OVN ACLs associated with those flow-classifiers are deleted.


Function Mapping
----------------

+------------------------+----------------------+----------------------------+
| Port Chain Function    | OVN Command          |  Description               |
+========================+======================+============================+
| create_port_chain      | lchain-add, acl-add  |Use acl-add when a          |
|                        |                      |port-chain is created       |
|                        |                      |with flow-classifiers       |
+------------------------+----------------------+----------------------------+
| delete_port_chain      | lchain-del, acl-del  |Use acl-del to delete all   |
|                        |                      |flow-classifiers associated |
|                        |                      |with a port-chain           |
+------------------------+----------------------+----------------------------+
| update_port_chain      | lchain-set-port-     |Use this OVN command when   |
|                        | pair-group           |PPGs are added to or        |
|                        |                      |removed from a port-chain   |
+------------------------+----------------------+----------------------------+
| "                      | acl-add, acl-del     |Use acl-add/del when        |
|                        |                      |flow-classifiers are added  |
|                        |                      |or removed to a port-chain  |
+------------------------+----------------------+----------------------------+
| create_port_pair_group | lport-pair-group-add |                            |
+------------------------+----------------------+----------------------------+
| delete_port_pair_group | lport-pair-group-del |                            |
+------------------------+----------------------+----------------------------+
| update_port_pair_group | lport-pair-group-    |Use this command to add /   |
|                        |  set-port-pair       |port-pairs to a PPG         |
+------------------------+----------------------+----------------------------+
| create_port_pair       | lport-pair-add       |                            |
+------------------------+----------------------+----------------------------+
| delete_port_pair       | lport-pair-del       |                            |
+------------------------+----------------------+----------------------------+
| create_flow_classifier | No action            |OVN ACLs are only created   |
|                        |                      |when flow-classifiers are   |
|                        |                      |attached to a port-chain    |
+------------------------+----------------------+----------------------------+
| delete_flow_classifier | No action            | "                          |
+------------------------+----------------------+----------------------------+

Flow-Classifier Mapping
-----------------------

+--------------------------------+-------------------------------------------+
| Flow Classifier                | OVN ACL Field                             |
+================================+===========================================+
| protocol                       | ip.protocol                               |
+--------------------------------+-------------------------------------------+
| ethertype                      | eth.type                                  |
+--------------------------------+-------------------------------------------+
| source_port_range_min/max      | If protocol = "tcp": min < tcp.src < max, |
|                                | if protocol = "udp": min < udp.src < max  |
+--------------------------------+-------------------------------------------+
| destination_port_range_min/max | If protocol = "tcp": min < tcp.dst < max, |
|                                | if protocol = "udp": min < udp.dst < max  |
+--------------------------------+-------------------------------------------+
| src_ip_prefix                  | If ethertype = "IPv4": ip4.src/mask,      |
|                                | if ethertype = "IPv6": ip6.src/mask       |
+--------------------------------+-------------------------------------------+
| destination_ip_prefix          | If ethertype = "IPv4": ip4.dst/mask,      |
|                                | if ethertype = "IPv6"  ip6.dst/mask       |
+--------------------------------+-------------------------------------------+
| logical_source_port            | If the logical-source-port is specified in|
|                                | the classifier then OVN ACL inport=       |
|                                | "logical_source_port.id" and OVN ACL      |
|                                | direction=from-port                       |
+--------------------------------+-------------------------------------------+
| logical_destination_port       | A single asymmetric  port chain will use  |
|                                | only the logical-source-port, and not the |
|                                | logical-destination-port                  |
+--------------------------------+-------------------------------------------+

A symmetric port chain is defined with a classifier that must have both a
logical-source-port and a logical-destination-port. In this case, symmetric
forward and reverse OVN port chains are created. The OVN ACL for the forward
chain uses the logical-source-port, and the OVN ACL for the reverse chain uses
the logical-destination-port.

The OVN ACL for the forward chain has inport="logical-source-port.id" and
OVN ACL direction=from-port. The OVN ACL for the reverse chain has
inport="logical-destination-port.id" and OVN ACL direction=from-port.


Implementation
==============

Assignee(s)
-----------
Authors of the Specification and Primary contributors:
 * Cathy Zhang (cathy.h.zhang@huawei.com)
 * Louis Fourie (louis.fourie@huawei.com)
 * Farhad Sunavala (farhad.sunavala@huawei.com)
 * John McDowall (jmcdowall@paloaltonetworks.com)
