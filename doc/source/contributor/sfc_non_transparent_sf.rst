..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

=================================================
Non-Transparent Service Functions for Port Chains
=================================================

URL of the launchpad blueprint:

https://blueprints.launchpad.net/networking-sfc/+spec/sfc-non-transparent-sf

This specification describes the support for non-transparent Service Functions
in SFC Port Chains.

Problem Description
===================

Service Functions (SF) that do not support SFC encapsulation, such as NSH,
require an SFC Proxy to re-classify a packet that is returned from the egress
port of the SF. The SFC Proxy uses the N-tuple values of a packet header to
re-classify a packet. The packet N-tuple consists of the following:

* Source IP address
* Destination IP address
* Source TCP/UDP port
* Destination TCP/UDP port
* IP Protocol

However, if the SF is non-transparent (it modifies a part of the N-tuple of
a packet), then re-classification cannot be done correctly.
See https://datatracker.ietf.org/doc/draft-song-sfc-legacy-sf-mapping/

Proposed Changes
================

This is an enhancement to the SFC proxy so that it is configured with the
N-tuple translation rules of the SF. In other words how the SF translates the
ingress Port N-tuple to the egress Port N-tuple of a packet:

  SF Ingress port N-tuple => SF Egress port N-Tuple

The SFC Proxy can then adjust for the SF translation rules by using this
N-tuple mapping. The SFC Proxy applies the N-tuple mapping to packets
received from the egress port of the SF before the re-classification
function.

The Port Pair Group port-pair-group-parameter attribute allows service specific
configuration to be applied to all Service Functions (Port Pairs) in a Port
Pair Group.

The port-pair-group-parameter will be enhanced to add an "n-tuple-map".
This is an array of ingress-egress N-tuple value pairs:
{ingress-N-tuple-value, egress-N-tuple-value} that are the same as the
actual translation done by the SF itself.

An example of the CLI format is shown below:

  n_tuple_map='source_ip_prefix_ingress=10.0.0.9&
               source_ip_prefix_egress=10.0.0.12&
               protocol_ingress=icmp&
               protocol_egress=tcp'

The SFC Proxy in the OVS Integration Bridge will apply the "n-tuple-map" to
the N-tuple of packets received from the egress port of the SF before they
are passed to the re-classification function so that the re-classification
rules are matched correctly.

::

            Compute Node
 +--------------------------------+
 |               VM               |
 |  +--------------------------+  |
 |  |     Non-transparent      |  |
 |  |     Service Function     |  |
 |  +--------------------------+  |
 |     P1 |^        P2 |.         |
 |        |.           |.         |
 |  +------.------------.------+  |
 |  |      .  SFC Proxy v      |  |
 |  |      .    +-----------+  |  |
 |  |      .    |N-tuple Map|  |  |
 |  |      .    +-----------+  |  |
 |  |      .    |Re-classify|  |  |
 |  |      .    +-----------+  |  |
 |  |      .            .      |  |
 |  | .>....            ...>   |  |
 |  |                          |  |
 |  |      OVS Integration     |  |
 |  |          Bridge          |  |
 |  +--------------------------+  |
 |                                |
 +--------------------------------+

Alternatives
------------

None

Data model impact
-----------------

Add "n-tuple-map" to the Port Pair Group port-pair-group-parameter attribute.

REST API impact
---------------

Add "n-tuple-map": "N-TUPLE-MAP" to the port-pair-group-parameter.

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

1. Extend API port-pair-group-parameter to support "n-tuple-map" attribute.
2. Extend 'networking-sfc' OVS driver to support "n-tuple-map" attribute.
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
