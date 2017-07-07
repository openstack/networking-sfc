..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

====================================
Service Function Tap for Port Chains
====================================

Include the URL of your launchpad blueprint:

https://blueprints.launchpad.net/networking-sfc/+spec/sfc-tap-port-pair

This specification describes the support for passive Service Functions
in SFC Port Chains.

Problem Description
===================

There are some Service Functions (SF) that operate in a passive mode and only
receive packets on the ingress port but do not send packets on an egress port.
An example of this is a Service Function that has an Intrusion Detection
Service (IDS). In order to include such a SF in a port chain, the packets must
be delivered to this SF and also forwarded on to the next downstream SF in the
port chain.

Proposed Changes
================

The Port Pair Group port-pair-group-parameter attribute allows service specific
configuration to be applied to all Service Functions (Port Pairs) in a Port
Pair Group.

The port-pair-group-parameter will be enhanced to add a "tap-enabled"
field. The "tap-enabled" field will apply to all Service Functions in the
Port Pair Group. This field is set to "true" to indicate that the data-plane
switch behavior will be to send the packets to the ingress port of the SF
and also forward these packets to the next hop SF. Each Port Pair in the
Port Pair Group will act as a tap by passing packets to the passive SF and also
forwarding these packets to the next downstream SF. This Port Pair will
only send packets to the ingress port of the SF and not receive any packets
from the egress port of the SF.

If "tap-enabled" is set to "false" or is not present then default behavior
will occur. The tap may be applied at any hop (Port Pair Group) in a Port
Chain. Every hop in a Port Chain may be configured as a tap.

OVS Driver Implementation
-------------------------

If a SF is configured as a tap the OVS Integration bridge will add a tap
to replicate packets received from upstream SFs. One copy is sent to the
ingress port (P1) of the passive Service Function (SF 1 on VM1). The other
copy is sent to the ingress port (P2) of the next downstream Service
Function (SF 2 on VM2).

::

                   Compute Node
 +--------------------------------------------------+
 |           VM1                     VM2            |
 |  +--------------------+  +--------------------+  |
 |  | Service Function 1 |  | Service Function 2 |  |
 |  |      (Passive)     |  |                    |  |
 |  +--------------------+  +--------------------+  |
 |         P1 |^               P2 |^    P3 |.       |
 |            |.                  |.       |.       |
 |            |.                  |.       |.       |
 |  +----------.-------------------.--------.----+  |
 |  |       Tap.                   .        .    |  |
 |  |  ...>....x.........>..........        ...> |  |
 |  |                                            |  |
 |  |               OVS Integration              |  |
 |  |                   Bridge                   |  |
 |  +--------------------------------------------+  |
 |                                                  |
 +--------------------------------------------------+

The tap will work regardless of whether the next hop SF is hosted on the
same Compute node as the tap Port Pair as shown above or on another Compute
node as shown below.

::

        Compute Node 1              Compute Node 2
 +-------------------------+   +-------------------------+
 |           VM1           |   |          VM2            |
 |  +--------------------+ |   | +--------------------+  |
 |  | Service Function 1 | |   | | Service Function 2 |  |
 |  |      (Passive)     | |   | |                    |  |
 |  +--------------------+ |   | +--------------------+  |
 |         P1 |^           |   |    P2 |^    P3 |.       |
 |            |.           |   |       |.       |.       |
 |            |.           |   |       |.       |.       |
 |  +----------.---------+ |   | +------.--------.----+  |
 |  |       Tap.         | |   | |      .        .    |  |
 |  |  ...>....x........ | |   | | ......        ..>  |  |
 |  |                  . | |   | | .                  |  |
 |  |  OVS Integration . | |   | | . OVS Integration  |  |
 |  |      Bridge      . | |   | | .     Bridge       |  |
 |  +------------------.-+ |   | +-.------------------+  |
 |                     .   |   |   .                     |
 +---------------------.---+   +---.---------------------+
                       .............


Alternatives
------------

None

Data model impact
-----------------

Add "tap-enabled" to the Port Pair Group port-pair-group-parameter attribute.
The "tap-enabled" field is set to "true" to enable the tap feature.
The "tap-enabled" field is set to "false" to disable the tap feature.

REST API impact
---------------

Add "tap-enabled": "true" to the port-pair-group-parameter.

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

1. Extend API port-pair-group-parameter to support "tap-enabled" field.
2. Extend 'networking-sfc' OVS driver to support "tap-enabled" field.
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

None
