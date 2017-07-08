..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

===============================================================
Exclusive Port-Pair Group for Non-Transparent Service Functions
===============================================================

URL of the launchpad blueprint:

https://blueprints.launchpad.net/networking-sfc/+spec/sfc-proxy-port-correlation

This specification describes the support for non-transparent Service Functions
in SFC Port Chains using a SFC Port Pair Group that is used exclusively by one
Port Chain. Non-transparent Service Functions modify the N-tuple header fields
of a packet.

Problem Description
===================

Most legacy Service Functions (SF) do not support SFC encapsulation, such as
NSH, and therefore require an SFC Proxy to re-classify a packet that is
returned from the egress port of the SF. The SFC Proxy uses the N-tuple values
of a packet header to re-classify a packet. The packet N-tuple consists of the
following:

* Source IP address
* Destination IP address
* Source TCP/UDP port
* Destination TCP/UDP port
* IP Protocol

However, if the SF is non-transparent (it modifies a part of the N-tuple of
a packet), then re-classification cannot be done correctly.
See https://datatracker.ietf.org/doc/draft-song-sfc-legacy-sf-mapping/

In addition the SF may dynamically change the mapping of the N-tuple values
as the SF operations progress. A mechanism that uses a static N-tuple mapping
to adjust for N-tuple changes cannot be employed.

Proposed Changes
================

This is an enhancement to the SFC proxy so that it can handle the dynamic
changes to N-tuple translation rules of the SF.

A solution to the non-transparent SF is to use a SF VM that has multiple
instances and assign the port-pairs for each SF instance to a separate Port
Chain.

This can be done by adding these ports to a SFC Proxy Port Pair Group which
operates as a Port Pair Correlation Map instead of a normal Load Distribution
function. The Proxy Port Pair Group is configured with multiple Port Pairs
that are attached to the SF Instances of a specific non-transparent SF type,
such as a Firewall SF. This Port Pair Group is configured to operate as a
Port Pair Correlation Map.

Each non-transparent SF instance is attached to a single Port Pair. These SF
instances may either run on a VM or on a container within a VM. If an SF
instance runs within a container, the container sub-port ([1][2]) is used as
the ingress and/or egress port of the Port Pair.

Each Port Chain is mapped to one of these port-pairs. Packets for a Port Chain
arriving at the OVS Integration bridge are steered to the ingress port of the
Port Pair assigned to that Port Chain. Packets received back from the SF on
its egress port are then mapped back to the corresponding Port Chain.
This mechanism avoids the  need for the SFC Proxy to re-classify packets
returned from the egress port of the non-transparent SF.

For example, in the figure below, packets on Port Chain A are steered to Port
Pair 1 and sent to the ingress port of SF Instance 1. Packets from the egress
port of SF Instance 1 are then mapped back to Port Chain A and are delivered
to the next hop in the chain.

When a Port Chain is created (or updated) that uses a SFC Proxy PPG, the Port
Chain is assigned to one of the Port Pairs in the PPG and the Port Pair is
reserved for that Port Chain. If the Port Chain is deleted or the PPG is
removed from the Port Chain, its Port Pair becomes available for use by another
Port Chain.

The Port Pairs in the SFC Proxy Port Pair Group may be hosted on different
Compute Nodes as shown in the diagram below.

If a Port Chain is created that uses a SFC Proxy Port Pair Group and all the
Pairs in that PPG are in use by other Port Chains, an error 'Maximum number of
Port Chains reached' is returned.

This obviously requires that multiple instances of the non-transparent SF be
deployed in either VMs or containers. The number of SF instances that must be
deployed and configured as Port Pairs depends on the maximum number of Port
Chains that are expected to use that particular SF. However, deploying multiple
instances of a SF is easily done in modern data centers.

A Port Chain may include multiple SFC Proxy PPGs, each one for a different
type of non-transparent SF. For example PPG1 may be a group of non-transparent
Firewall SF instances and PPG2 may be a group of non-transparent HTTP Optimizer
SF instances.


::

         Compute Node 1
 +------------------------------------------------------------+
 |                                                            |
 |     OVS Integration Bridge          Non-transparent SF     |
 |  +--------------------------+  +.........................+ |
 |  |   SFC Proxy Port Pair    |  .                         . |
 |  |   Correlation Map PPG    |  .        VM/Container1    . |
 |  | +.....................+  |  . pp1+------------------+ . |
 |  | .Port Chain A <-> pp1 .--------->| Non-transparent  | . |
 |  | .                     .<---------|  SF Instance  1  | . |
 |  | .                     .  |  .    +------------------+ . |
 |  | .                     .  |  .        VM/Container2    . |
 |  | .                     .  |  . pp2+------------------+ . |
 |  | .Port Chain C <-> pp2 .--------->| Non-transparent  | . |
 |  | .                     .<---------|  SF Instance 2   | . |
 |  | .                     .  |  .    +------------------+ . |
 |  +-.---------------------.--+  .                         . |
 +----.---------------------.-----.-------------------------.-+
      .  Compute Node 2     .     .                         .
 +----.---------------------.-----.-------------------------.-+
 |    .                     .     .                         . |
 |    .OVS Integration Bridge     .                         . |
 |  +-.---------------------.--+  .                         . |
 |  | .                     .  |  .        VM/Container3    . |
 |  | .                     .  |  . pp3+------------------+ . |
 |  | .Port chain X <-> pp3 .--------->| Non-transparent  | . |
 |  | .                     .<---------|  SF Instance 3   | . |
 |  | +.....................+  |  .    +------------------+ . |
 |  |                          |  +.........................+ |
 |  +--------------------------+                              |
 +------------------------------------------------------------+

Alternatives
------------

An alternative mechanism for non-transparent SFs is to mark PPG as exclusive so
that it is assigned to one port chain only. This would require a PPG be created
for each port chain. The advantage to this approach is that the PPG can be used
for load balancing.

Data model impact
-----------------

Add a "proxy-correlation-map" attribute to the Port Pair Group. This
is a Boolean that will enable the Proxy Port Correlation.
Add an "exclusive" attribute to the Port Pair Group. This
is a Boolean that will enable exclusive use of a Port Pair Group by one
Port Chain.

REST API impact
---------------

Add "proxy-correlation-map": true to the Port Pair Group.
Add "exclusive": true to the Port Pair Group.

Security impact
---------------

None

Notifications impact
--------------------

None

Other end user impact
---------------------

None

Performance Impact
------------------

None

Other deployer impact
---------------------

None.

Developer impact
----------------

None.

Implementation
==============

Assignee(s)
-----------

* Cathy Zhang (cathy.h.zhang@huawei.com)
* Louis Fourie (louis.fourie@huawei.com)

Work Items
----------

1. Extend API port-pair-group-parameter to support "proxy-correlation-map"
and the "exclusive" attributes.
2. Extend networking-sfc OVS driver to support "proxy-correlation-map"
and "exclusive" attributes.
3. Add unit and functional tests.
4. Update documentation.

Dependencies
============

None

Testing
=======

Unit tests and functional tests will be added.

Documentation Impact
====================

None

References
==========
[1] Neutron Trunk-port https://wiki.openstack.org/wiki/Neutron/TrunkPort

[2] VLAN aware VMs https://review.openstack.org/#/c/243786/11/specs/mitaka/vlan-aware-vms.rst
