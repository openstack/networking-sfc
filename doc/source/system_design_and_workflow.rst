..
      Copyright 2015 Futurewei. All rights reserved.
      Copyright 2017 Intel Corporation. All rights reserved.

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


==========================
System Design and Workflow
==========================

Problem Description
===================
The `Service Chaining API specification <api.html>`_ proposes a Neutron port
based solution for setting up a service chain. A specification on the system
architecture and related API work flow is needed to guide the code design.

System Architecture
===================
The following figure shows the generic architecture of the Port Chain
Plugin. As shown in the diagram, Port Chain Plugin can be backed by
different service providers such as OVS Driver and/or different types of
SDN Controller Drivers. Through the "Common Driver API", these
different drivers can provide different implementations for the service
chain path rendering. In the first release and deployment based on this
release, we will only deliver codes for the OVS driver. In the next release,
we can add codes to support multiple active drivers::

    Port Chain Plugin With Different Types of Drivers
   +-----------------------------------------------------------------+
   |  +-----------------------------------------------------------+  |
   |  |                        Port Chain API                     |  |
   |  +-----------------------------------------------------------+  |
   |  |                        Port Chain Database                |  |
   |  +-----------------------------------------------------------+  |
   |  |                        Driver Manager                     |  |
   |  +-----------------------------------------------------------+  |
   |  |                        Common Driver API                  |  |
   |  +-----------------------------------------------------------+  |
   |                                   |                             |
   |  +------------+------------------------+---------------------+  |
   |  | OVS Driver |   Controller Driver1   |  Controller Driver2 |  |
   |  +------------+------------------------+---------------------+  |
   +-------|------------------|-------------------------|------------+
           |                  |                         |
      +-----------+   +-----------------+      +-----------------+
      | OVS Agent |   | SDN Controller1 |      | SDN Controller2 |
      +-----------+   +-----------------+      +-----------------+

The second figure below shows the reference implementation architecture,
which is through the OVS Driver path. The figure shows the components
that will be added on the Neutron Server and the compute nodes to
support this Neutron Based SFC functionality. As shown in the diagram,
a new Port Chain Plugin will be added to the Neutron Server.
The existing "OVS Driver" and "OVS Agent" will be extended to support
the service chain functionality. The OVS Driver will communicate with
each OVS Agent to program its OVS forwarding table properly so that a
tenant's traffic flow can be steered through the user defined sequence
of Neutron ports to get the desired service treatment from the Service
Function running on the VMs.

A separate `OVS Driver and Agent specification <ovs_driver_and_agent_workflow.html>`_ will describe in more
detail on the design consideration of the Driver, Agent, and how to set up the
classification rules on the OVS to identify different flows and how to
set up the OVS forwarding table. In the reference implementation, the OVS Driver
communicates with OVS Agent through RPC to program the OVS. The communication
between the OVS Agent and the OVS is through OVSDB/Openflow::


       Port Chain Plugin With OVS Driver
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
      |              |                |
      |  +-------------------------+  |
      |  |        OVS Driver       |  |
      |  +-------------------------+  |
      +-------|----------------|------+
              |                |
         +-----------+   +-----------+
         | OVS Agent |   | OVS Agent |
         +-----------+   +-----------+

Port Chain Creation Workflow
============================
The following example shows how the Neutron CLI commands may be used to
create a port-chain consisting of a service VM vm1 and a service VM
vm2. The user can be an Admin/Tenant or an Application built on top.

Traffic flow into the Port Chain will be from source IP address
22.1.20.1 TCP port 23 to destination IP address 171.4.5.6 TCP port 100.
The flow needs to be treated by SF1 running on VM1 identified by
Neutron port pair [p1, p2], SF2 running on VM2 identified by Neutron
port pair [p3, p4], and SF3 running on VM3 identified by Neutron port
pair [p5, p6].

The net1 should be created before creating Neutron port using existing
Neutron API. The design has no restriction on the type of net1, i.e. it
can be any type of Neutron network since SFC traffic will be tunneled
transparently through the type of communication channels of net1.
If the transport between vSwitches is VXLAN, then we will use that VXLAN
tunnel (and NOT create another new tunnel) to transport the SFC traffic
through. If the transport between vSwitches is Ethernet, then the SFC
traffic will be transported through Ethernet. In other words, the SFC
traffic will be carried over existing transport channel between vSwitches
and the external transport channel between vSwitches is set up for net1
through existing Neutron API and ML2. The built-in OVS backend
implements tunneling the original flow packets over VXLAN tunnel. The detailed
outer VXLAN tunnel transport format and inner SFC flow format including
how to leverage existing OVS's support for MPLS label to carry chain ID
will be described in the `Port Chain OVS Driver and Agent specification <ovs_driver_and_agent_workflow.html>`_.
In the future we can add implementation of tunneling the SFC flow packets over
flat L2 Ethernet or L3 IP network or GRE tunnel etc.

Boot service VMs and attach ports
---------------------------------
Create Neutron ports on network net1::

   neutron port-create --name p1 net1
   neutron port-create --name p2 net1
   neutron port-create --name p3 net1
   neutron port-create --name p4 net1
   neutron port-create --name p5 net1
   neutron port-create --name p6 net1

Boot VM1 from Nova with ports p1 and p2 using two --nic options::

 nova boot --image xxx --nic port-id=p1-id --nic port-id=p2-id vm1 --flavor <image-flavour>

Boot VM2 from Nova with ports p3 and p4 using two --nic options::

 nova boot --image yyy --nic port-id=p3-id --nic port-id=p4-id vm2 --flavor <image-flavour>

Boot VM3 from Nova with ports p5 and p6 using two --nic options::

 nova boot --image zzz --nic port-id=p5-id --nic port-id=p6-id vm3 --flavor <image-flavour>

Alternatively, the user can create each VM with one VNIC and then
attach another Neutron port to the VM::

 nova boot --image xxx --nic port-id=p1-id vm1
 nova interface-attach --port-id p2-id vm1
 nova boot --image yyy --nic port-id=p3-id vm2
 nova interface-attach --port-id p4-id vm2
 nova boot --image zzz --nic port-id=p5-id vm3
 nova interface-attach --port-id p6-id vm3

Once the Neutron ports p1 - p6 exist, the Port Chain is created using
the steps described below.

Create Flow Classifier
----------------------
Create flow-classifier FC1 that matches on source IP address 22.1.20.1
(ingress direction) and destination IP address 171.4.5.6 (egress
direction) with TCP connection, source port 23 and destination port
100::

 neutron flow-classifier-create \
  --ethertype IPv4 \
  --source-ip-prefix 22.1.20.1/32 \
  --destination-ip-prefix 172.4.5.6/32 \
  --protocol tcp \
  --source-port 23:23 \
  --destination-port 100:100 FC1

Create Port Pair
----------------
Create port-pair PP1 with ports p1 and p2, port-pair PP2 with
ports p3 and p4, port-pair PP3 with ports P5 and P6::

 neutron port-pair-create \
        --ingress=p1 \
        --egress=p2 PP1

 neutron port-pair-create \
        --ingress=p3 \
        --egress=p4 PP2

 neutron port-pair-create \
        --ingress=p5 \
        --egress=p6 PP3

Create Port Group
-----------------
Create port-pair-group PG1 with port-pair PP1 and PP2, and
port-pair-group PG2 with port-pair PP3::

 neutron port-pair-group-create \
        --port-pair PP1 --port-pair PP2 PG1 \
 neutron port-pair-group-create \
        --port-pair PP3 PG2

Create Port Chain
-----------------

Create port-chain PC1 with port-group PG1 and PG2, and flow
classifier FC1::

 neutron port-chain-create \
        --port-pair-group PG1 --port-pair-group PG2 --flow-classifier FC1 PC1

This will result in the Port chain driver being invoked to create the
Port Chain.

The following diagram illustrates the code execution flow (not the
exact codes) for the port chain creation::

 PortChainAPIParsingAndValidation: create_port_chain
                |
                V
 PortChainPlugin: create_port_chain
                |
                V
 PortChainDbPlugin: create_port_chain
                |
                V
 DriverManager: create_port_chain
                |
                V
 portchain.drivers.OVSDriver: create_port_chain

The vSwitch Driver needs to figure out which switch VM1 is connecting
with and which switch VM2 is connecting with (for OVS case, the OVS
driver has that information given the VMs' port info). As to the
connection setup between the two vSwitches, it should be done through
existing ML2 plugin mechanism. The connection between these two
vSwitches should already be set up before the user initiates the SFC
request. The service chain flow packets will be tunneled through the
connecting type/technology (e.g. VXLAN or GRE) between the two
vSwitches. For our reference code implementation, we will use VXLAN to
show a complete data path setup. Please refer to the `OVS Driver and OVS
Agent specification <ovs_driver_and_agent_workflow.html>`_ for more detail info.

SFC Encapsulation
=================

This section explains SFC Encapsulation support in networking-sfc.

The link to Launchpad at [4] is an umbrella for SFC Encapsulation work with the
following scope:

* MPLS correlation support in networking (labels exposed to SFs)

* SFC Graphs allowing port-chains to be linked together

* The IETF SFC Encapsulation protocol, NSH, support

* No NSH Metadata support

Currently, networking-sfc only supports the MPLS correlation outlined above.
The remaining points are work in progress. As such, this documentation only
covers MPLS correlation.

To clarify, MPLS correlation cannot be strictly
called SFC Encapsulation since it doesn't fully encapsulate the packets,
amongst other limitations such as available space to carry metadata [1].
However, since it can be used for SFP identification, it is a good
workaround to exercise the IETF SFC Encapsulation architectural concept in
networking-sfc.


Problem Description
-------------------

SFC Encapsulation is an architectural concept from IETF SFC, which states [1]:

*"The SFC Encapsulation provides, at a minimum, SFP identification, and is used
by the SFC-aware functions, such as the SFF and SFC-aware SFs. The SFC
encapsulation is not used for network packet forwarding. In addition to SFP
identification, the SFC Encapsulation carries metadata including data-plane
context information."*

Metadata is a very important capability of SFC Encapsulation, but it's out of
scope for this first umbrella of work in networking-sfc.


Usage
-----

In order to create port-chains with port-pairs that make use of the MPLS
correlation (i.e. the MPLS labels are exposed to the SFs, so no SFC Proxy is
logically instantiated by the the networking-sfc backend), the port-pair's
``correlation`` service function parameter can be used, by setting it to
``mpls``:

``service_function_parameters: {correlation: 'mpls'}``

Enabling the MPLS correlation doesn't fully encapsulate frames like NSH would,
since the MPLS labels are inserted between the Ethernet header and the L3
protocol.

By default, port-chains always have their correlation set to MPLS:

``chain_parameters: {correlation: 'mpls'}``

A port-chain can have port-pair-groups with MPLS-correlated port-pairs or
port-pairs with no correlation. However, each port-pair-group can only group
port-pairs that share the same correlation type (to process each hop and expose
their feature set in a consistent and predictable way). The SFC OVS driver and
agent are smart enough to only apply SFC Proxies to the hops that require so.


Implementation
--------------

At the API side, the MPLS correlation is defined as a possible option to the
``correlation`` key in the ``service_function_parameters`` field of the
``port_pair`` resource.

The parameter is saved in the database in the same way as any other port-pair
parameter, inside the ``sfc_service_function_params`` table::

 keyword='correlation'
 value='mpls'
 pair_id=PORT_PAIR_UUID

The MPLS correlation parameter will eventually be fed to the enabled backend,
such as Open vSwitch. Through the OVS SFC driver and agent, the vswitches
on the multiple nodes where networking-sfc is deployed will be configured
with the set of flows that allow classification, encapsulation, decapsulation
and forwarding of MPLS tagged or untagged packets. Applying the IETF SFC view
to this, Open vSwitch switches thus implement the logical elements
of Classifier, Service Function Forwarder (SFF) and SFC Proxy (stateless) [1].

In networking-sfc, the OVS driver talks to the agents on the multiple compute
nodes by sending "flow rule" messages to them across the RPC channels.

In flow rules, correlation parameters of both port-chains and port-pairs are
specified using the ``pc_corr`` and ``pp_corr`` flow rule keys, respectively.
Moreover, a ``pp_corr`` key is also specified in each of the hops of the
``next_hops`` flow rule key.

Remember: a port-pair-group contains port-pairs that all share the same
correlation type, so the comparison between ``pc_corr`` and each of the
``pp_corr`` of the next hops will yield the same result.

``pc_corr`` is the correlation mechanism (SFC Encapsulation) to be used for
the entire  port-chain. The values may be ``None``, ``'mpls'``, or ``'nsh'``
(when supported).

``pp_corr`` is the correlation mechanism supported by an individual SF. The
values may be ``'None'``, ``'mpls'``, or ``'nsh'`` (when supported).

The backend driver compares ``pc_corr`` and ``pp_corr`` to determine if SFC
Proxy is needed for a SF that is not capable of processing the
SFC Encapsulation mechanism. For example, if ``pc_corr`` is
``'mpls'`` and ``pp_corr`` is ``None``, then SFC Proxy is needed.

The following is an example of an sf_node flow
rule (taken from one of the SFC OVS agent's unit tests)::

                'nsi': 255,
                'ingress': '6331a00d-779b-462b-b0e4-6a65aa3164ef',
                'next_hops': [{
                    'local_endpoint': '10.0.0.1',
                    'ingress': '8768d2b3-746d-4868-ae0e-e81861c2b4e6',
                    'weight': 1,
                    'net_uuid': '8768d2b3-746d-4868-ae0e-e81861c2b4e7',
                    'network_type': 'vxlan',
                    'segment_id': 33,
                    'gw_mac': '00:01:02:03:06:09',
                    'cidr': '10.0.0.0/8',
                    'mac_address': '12:34:56:78:cf:23',
                    'pp_corr': 'mpls'
                }],
                'del_fcs': [],
                'group_refcnt': 1,
                'node_type': 'sf_node',
                'egress': '29e38fb2-a643-43b1-baa8-a86596461cd5',
                'next_group_id': 1,
                'nsp': 256,
                'add_fcs': [{
                    'source_port_range_min': 100,
                    'destination_ip_prefix': u'10.200.0.0/16',
                    'protocol': u'tcp',
                    'l7_parameters': {},
                    'source_port_range_max': 100,
                    'source_ip_prefix': '10.100.0.0/16',
                    'destination_port_range_min': 100,
                    'ethertype': 'IPv4',
                    'destination_port_range_max': 100,
                }],
                'pc_corr': 'mpls',
                'pp_corr': 'mpls',
                'id': uuidutils.generate_uuid()

It can be seen that ``'mpls'`` appears three times in the flow rule, twice in
the root (specifying the correlation of port-chain and port-pair of the current
hop) and once inside the single hop of ``next_hops``, regarding its port-pair.

The three appearances will dictate how flows (both matches and actions) will
be added by the OVS agent.

Currently, the only allowed protocol for chain correlation is MPLS, in which
case ``pc_corr`` gets set to ``'mpls'``. With ``pc_corr='mpls'``,
let's take a look at the possible scenarios:

+-+------------------+------------------+-------------------------------------+
| | Curr Hop pp_corr | Next Hop pp_corr |              Action                 |
+=+==================+==================+=====================================+
|1| MPLS             | MPLS             | Egress from SF: match on MPLS       |
| |                  |                  | to determine next hop               |
| |                  |                  | Ingress to next SF: send MPLS to SF |
+-+------------------+------------------+-------------------------------------+
|2| MPLS             | None             | Egress from SF: match on MPLS       |
| |                  |                  | to determine next hop               |
| |                  |                  | Ingress to next SF: pop MPLS first  |
+-+------------------+------------------+-------------------------------------+
|3| None             | MPLS             | Egress from SF: reclassify packet   |
| |                  |                  | and add new MPLS                    |
| |                  |                  | Ingress to next SF: send MPLS to SF |
+-+------------------+------------------+-------------------------------------+
|4| None             | None             | Egress from SF: reclassify packet   |
| |                  |                  | and add new MPLS                    |
| |                  |                  | Ingress to next SF: pop MPLS first  |
+-+------------------+------------------+-------------------------------------+

The following further explains each of the possibilities from the table above.

1. **pp_corr=mpls and every next_hop's pp_corr=mpls**

The ingress of this sf_node will not remove the MPLS labels. When
egressing from this sf_node, OVS will not attempt to match on the
flow_classifier defined in ``add_fcs``, but rather the expected MPLS labels
after the SF is done processing the packet (the NSI is supposed to be
decremented by 1 by the SF). When preparing the packet to go to the next hop,
no attempt at inserting MPLS labels will be done,
since the packet already has the correct labels.

2. **pp_corr=mpls and every next_hop's pp_corr=None**

The ingress of this sf_node will not remove the MPLS labels. When
egressing from this sf_node, OVS will not attempt to match on the
flow_classifier defined in ``add_fcs``, but rather the expected MPLS labels
after the SF is done processing the packet (the NSI is supposed to be
decremented by 1 by the SF). When preparing the packet to go to the next hop,
no attempt at inserting MPLS labels will be done,
since the packet already has the correct labels.
The next hop's own flow rule (not the one shown above) will have an action to
first remove the MPLS labels and then forward to the SF.

3. **pp_corr=None and every next_hop's pp_corr=mpls**

The ingress of this sf_node will first remove the MPLS labels and then forward
to the SF, as its actions. When egressing from this sf_node, OVS will match on
the flow-classifier defined in ``add_fcs``, effectively implementing an SFC
Proxy and running networking-sfc's "classic" mode.
When preparing the packet to go to the next hop, a new MPLS header needs to be
inserted. This is done on Table 0, the same table where ``add_fcs`` was
matched. Right before the packets are submitted to the Groups Table, they
receive the expected MPLS labels for the next hop. The reason why this can't
be done on the ``ACROSS_SUBNET_TABLE`` like when the next_hop's correlation is
set to None, is the fact that the choice of labels would be ambiguous.
If multiple port-chains share the same port-pair-group at a given hop, then
encapsulating/adding MPLS labels as one of ``ACROSS_SUBNET_TABLE``'s actions
means that at least one of port-chains will be fed the wrong label and,
consequently, leak into a different port-chain. This is due to the fact that,
in ``ACROSS_SUBNET_TABLE``, the flow matches only on the destination MAC
address of the frame (and that isn't enough to know what chain the frame is
part of). So, again, the encapsulation/adding of MPLS labels will have to be
done in Table 0 for this specific scenario where in the current hop the packets
don't have labels but on the next hop they are expected to.

4. **pp_corr=None and every next_hop's pp_corr=None**

This is "classic" networking-sfc. The ingress of this sf_node will first remove
the MPLS labels and then forward to the SF, as its actions. When egressing from
this sf_node, OVS will match on the flow-classifier defined in ``add_fcs``
effectively implementing an SFC Proxy and running networking-sfc's
"classic" mode.
When preparing the packet to go to the next hop, a new MPLS header needs to be
inserted, which is done at the ``ACROSS_SUBNET_TABLE``, after a destination
port-pair has been chosen with the help of the Groups Table.


References
----------

[1] https://datatracker.ietf.org/doc/rfc7665/?include_text=1

[2] http://i.imgur.com/rxzNNUZ.png

[3] http://i.imgur.com/nzgatKB.png

[4] https://bugs.launchpad.net/networking-sfc/+bug/1587486
