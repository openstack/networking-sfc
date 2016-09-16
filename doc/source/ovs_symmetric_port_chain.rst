..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

==============================================
OVS Driver and Agent for Symmetric Port Chains
==============================================

Include the URL of your launchpad blueprint:

https://blueprints.launchpad.net/networking-sfc/+spec/symmetric-port-chain-ovs-agent

This specification describes OVS driver and agent enhancements to support
symmetric Port Chains.

Problem Description
===================

Work to add the symmetric parameter to the Port Chain API [1] is in progress.
This describes the extensions to the networking-sfc OVS driver and agent to
support symmetric Port Chain paths.

Proposed Changes
================

Two port chain paths are created for a symmetric Port Chain: one path for the
forward direction and one for the reverse direction. The SFs in the reverse
path (from destination to source) are traversed in reverse order to the SFs in
the forward path (from source to destination).

Forward path: SF1 ... SFn

Reverse path: SFn ... SF1

A symmetric Port Chain is defined with the 'symmetric' attribute. Both the
source and destination Logical Ports must be defined for a symmetric Port
Chain. If a Port Chain terminates externally via a vrouter the vrouter port
attached to the local subnet is used as the destination Logical Port. When a
symmetric Port Chain is deleted both the forward and reverse paths are deleted.

The steering of chain traffic in the data-plane ensures symmetry:

* The source Logical Port in the flow-classifier is used to install OVS
  rules to match traffic for the forward path. The destination Logical Port in
  the flow-classifier is used to install OVS rules to match traffic for the
  reverse path.

* Rules must be installed so that the SFs in the reverse path are traversed in
  reverse order to that of the forward path.

* Each Port Pair Group must have a Load Balancer pair: one for the forward
  direction and the other for the reverse direction. In addition, to ensure
  that traffic in the forward and reverse directions is delivered to the same
  SF in a Port Pair Group, these LB pairs must use symmetric hash functions.

For symmetric hashing, the source and destination fields from packet header
used in the hash function of the reverse LB must be the reverse of the packet
header fields used in the hash function of the forward LB. If a source field,
such as the source IP address, is used as a hash field in the forward
direction, the corresponding destination field, the destination IP address,
must be used as the hash field in the reverse direction.

The example below shows a symmetric Port Chain that has a forward path
and a symmetric reverse path. The Port Chain transits Port Pair Group 1 and
Port Pair Group 2. PPG1 consists of service functions SF1a - SF1c, and PPG2
has service functions SF2a - SF2d.

Classification rule CLf matches traffic from the source Logical Port and
steers it to the forward path. Classification rule CLr matches traffic from the
destination Logical Port and steers it to the reverse path.

Port Pair Group 1 has a pair of Load Balancers, LB1f to load balance traffic
in the forward direction, and LB1r to load balance traffic in the reverse
direction. Port Pair Group 2 also has a pair of Load Balancers, LB2f and LB2r.

LB1f hashes a certain forward traffic flow to SF1c, and LB1r, using symmetric
hashing, hashes the reverse traffic for the same flow to the same SF, SF1c.
Similarly, LB2f hashes that forward traffic flow to SF2a, and LB2r hashes the
reverse traffic for the same flow to SF2a.

::

                       Port Pair           Port Pair
                        Group 1            Group 2
      Reverse path
   ...................  +----+              +----+     Forward path
   .                  . |SF1a|        ----->|SF2a|-----------------------
   v                  . |    |       | +----|    |<....                  |
 +---+  +---+----+    . +----+   ....|.|LB1r+----+    .                  |
 |VM1|->|CLf|LB1f|--  . |SF1b|   .   | +----|SF2b|    .                  v
 +---+  +---+----+  | . |    |   .   |      |    |    .   +----+---+   +---+
                    | . +----+   .   |      +----|    ....|LB2r|CLr|<..|VM2|
                    | ..|SF1c|<...   |      |SF2c|        +----+---+   +---+
                     -->|    |----+  |      |    |
                        +----|LB2f|--       +----+
                             +----+         |SF2d|
                                            |    |
                                            +----+

The Load Balancers of the LB pairs may reside on different Compute Nodes.
For example, LB1f may be hosted on one Compute Node and LB1r on another
Compute Node.

Alternatives
------------

None

Data model impact
-----------------

None

REST API impact
---------------

None

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
* Farhad Sunavala (farhad.sunavala@huawei.com)

Work Items
----------

1. Extend 'networking-sfc' OVS driver to support symmetric port chains.
2. Add unit tests.
3. Add tempest tests.
4. Update documentation.

Dependencies
============

None

Testing
=======

Unit tests and function tests will be added.

Documentation Impact
====================

None

References
==========

[1] https://review.openstack.org/#/c/308274/
