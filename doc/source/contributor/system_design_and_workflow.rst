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

   openstack port create --network net1 p1
   openstack port create --network net1 p2
   openstack port create --network net1 p3
   openstack port create --network net1 p4
   openstack port create --network net1 p5
   openstack port create --network net1 p6

Boot VM1 from Nova with ports p1 and p2 using two --nic options::

 openstack server create --image xxx --nic port-id=p1-id --nic port-id=p2-id vm1 --flavor <image-flavour>

Boot VM2 from Nova with ports p3 and p4 using two --nic options::

 openstack server create --image yyy --nic port-id=p3-id --nic port-id=p4-id vm2 --flavor <image-flavour>

Boot VM3 from Nova with ports p5 and p6 using two --nic options::

 openstack server create --image zzz --nic port-id=p5-id --nic port-id=p6-id vm3 --flavor <image-flavour>

Alternatively, the user can create each VM with one VNIC and then
attach another Neutron port to the VM::

 openstack server create --image xxx --nic port-id=p1-id vm1
 openstack server add port vm1 p2-id
 openstack server create --image yyy --nic port-id=p3-id vm2
 openstack server add port vm2 p4-id
 openstack server create --image zzz --nic port-id=p5-id vm3
 openstack server add port vm3 p6-id

Once the Neutron ports p1 - p6 exist, the Port Chain is created using
the steps described below.

Create Flow Classifier
----------------------
Create flow-classifier FC1 that matches on source IP address 22.1.20.1
(ingress direction) and destination IP address 171.4.5.6 (egress
direction) with TCP connection, source port 23 and destination port
100::

 openstack sfc flow classifier create \
  --ethertype IPv4 \
  --source-ip-prefix 22.1.20.1/32 \
  --destination-ip-prefix 172.4.5.6/32 \
  --protocol tcp \
  --source-port 23:23 \
  --destination-port 100:100 FC1

.. note::

   When using the (default) OVS driver, the ``--logical-source-port``
   parameter is also required

Create Port Pair
----------------
Create port-pair PP1 with ports p1 and p2, port-pair PP2 with
ports p3 and p4, port-pair PP3 with ports P5 and P6::

 openstack sfc port pair create \
        --ingress=p1 \
        --egress=p2 PP1

 openstack sfc port pair create \
        --ingress=p3 \
        --egress=p4 PP2

 openstack sfc port pair create \
        --ingress=p5 \
        --egress=p6 PP3

Create Port Group
-----------------
Create port-pair-group PG1 with port-pair PP1 and PP2, and
port-pair-group PG2 with port-pair PP3::

 openstack sfc port pair group create \
        --port-pair PP1 --port-pair PP2 PG1

 openstack sfc port pair group create \
        --port-pair PP3 PG2

Create Port Chain
-----------------

Create port-chain PC1 with port-group PG1 and PG2, and flow
classifier FC1::

 openstack sfc port chain create \
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
