============================================================
Service Function Chaining Extension for OpenStack Networking
============================================================

Service Function Chaining API Status
------------------------------------

This project has not been released yet, and as such, the API should be
considered experimental. This means the SFC API could undergo changes which
could be backwards incompatible while it is under development. The goal is to
allow backend implementations to experiment with the API at the same time as
it is being developed. Once a release is made, this documentation will be
updated to remove this warning.

This project provides APIs and implementations to support
Service Function Chaining in Neutron.

Service Function Chaining is a mechanism for overriding the basic destination
based forwarding that is typical of IP networks. It is conceptually related
to Policy Based Routing in physical networks but it is typically thought of as
a Software Defined Networking technology. It is often used in conjunction with
security functions although it may be used for a broader range of features.
Fundamentally SFC is the ability to cause network packet flows to route through
a network via a path other than the one that would be chosen by routing table
lookups on the packet's destination IP address. It is most commonly used in
conjunction with Network Function Virtualization when recreating in a virtual
environment a series of network functions that would have traditionally been
implemented as a collection of physical network devices connected in series
by cables.

A very simple example of a service chain would be one that forces all traffic
from point A to point B to go through a firewall even though the firewall is
not literally between point A and B from a routing table perspective.

A more complex example is an ordered series of functions, each implemented in
multiple VMs, such that traffic must flow through one VM at each hop in the
chain but the network uses a hashing algorithm to distribute different flows
across multiple VMs at each hop.

* Free software: Apache license
* Source: http://git.openstack.org/cgit/openstack/networking-sfc
* Overview: https://launchpad.net/networking-sfc
* Bugs: http://bugs.launchpad.net/networking-sfc
* Blueprints: https://blueprints.launchpad.net/networking-sfc

Features
--------

* Creation of Service Function Chains consisting of an ordered sequence of Service Functions. SFs are virtual machines (or potentially physical devices) that perform a network function such as firewall, content cache, packet inspection, or any other function that requires processing of packets in a flow from point A to point B.
* Reference implementation with Open vSwitch
* Flow classification mechanism (ability to select and act on traffic)
* Vendor neutral API
* Modular plugin driver architecture

Background on the Subject of Service Function Chaining
------------------------------------------------------
* Original Neutron bug (request for enhancement): https://bugs.launchpad.net/neutron/+bug/1450617
* https://blueprints.launchpad.net/neutron/+spec/neutron-api-extension-for-service-chaining
* https://blueprints.launchpad.net/neutron/+spec/common-service-chaining-driver-api
* https://wiki.opnfv.org/requirements_projects/openstack_based_vnf_forwarding_graph
