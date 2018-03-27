..
      Copyright 2017 Intel Corporation.

      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.


IETF SFC Encapsulation
======================

This section explains SFC Encapsulation support in networking-sfc.

The link to Launchpad at [4] is an umbrella for SFC Encapsulation work with the
following scope:

* MPLS correlation support (labels exposed to SFs)

* Service Graphs allowing port-chains to be linked together

* The IETF SFC Encapsulation protocol, NSH (exposed to SFs), support

* No NSH Metadata support

SFC Encapsulation is an architectural concept from IETF SFC, which states [1]:

*"The SFC Encapsulation provides, at a minimum, SFP identification, and is used
by the SFC-aware functions, such as the SFF and SFC-aware SFs. The SFC
encapsulation is not used for network packet forwarding. In addition to SFP
identification, the SFC Encapsulation carries metadata including data-plane
context information."*

Metadata is a very important capability of SFC Encapsulation, but it's out of
scope for this umbrella of work in networking-sfc.

Correlation is the term used to correlate packets to chains, in essence it is
the Service Function Path (SFP) information that is part of the
SFC Encapsulation. Correlation can be MPLS or NSH (SFC Encapsulation).

To clarify, MPLS correlation cannot be strictly called SFC Encapsulation
since it doesn't fully encapsulate the packets, amongst other limitations
such as available space to carry metadata [1]. However, since it can be
used for Service Function Path identification, it is
a good workaround to exercise the IETF SFC Encapsulation architectural
concept in networking-sfc, when NSH is not desired.

Service Graphs is a concept mentioned in [1] but further defined and
refined in [5] that builds on top of Reclassification and Branching (from [1]).
Service Graphs make use of the full encapsulation of frames the SFC
Encapsulation provides, and the Service Function Path information that is
carried by it, to create dependencies between SFPs, making sure that there's
no "leakage" of frames between paths. The figure below outlines the key
elements in a Service Graph::

       Branch1       Join1
    pc1 --+--> pc2 ------>  pc4
          |           ^
          |           |
           --> pc3 ---

 Branch1: pc1 = initial (source)
          pc2 = destination
          pc3 = destination
 Join1:   pc2 = source
          pc3 = source
          pc4 = destination

Since Port Chains resemble Service Function Paths, with the ``chain_id``
attribute mapping to a Service Path Identifier (SPI), they are used as the
SFPs for the Service Graph, and consequently Service Graphs in networking-sfc
allow the creation of dependencies between Port Chains (alongside traffic
classification criteria, just like a normal Port Chain, via Flow Classifier).


Terminology
-----------
* **Branching Point**: Or branch point, is a point in a Service Graph that
  leads to new SFPs.

* **Correlation**: Related to SFC Encapsulation, but focused on the fact that
  a Port Chain (an **SFP**) will be mapped to a unique identifier (the **SPI**)
  and that the hops of that chain will also have a unique index associated
  (the **SI**), with the forwarding of traffic based on those two parameters.

* **Destination Chain**: A Port Chain that branches from a previous chain
  (the **Source Chain**), i.e. a dependent chain.
  A Destination Chain may also be a **Source Chain**.
  For traffic to be accepted into a Destination Chain, it has to have come
  from the **Source Chains** that the Destination Chain depends on plus
  the Destination Chain's own flow classifier (except logical source ports,
  which will be ignored as that would clash with the traffic coming out of
  respective Source Chains).

* **Initial Chain**: A Port Chain that is not a **Destination Chain**, but
  may be a **Source Chain** if it's included in a Service Graph. In other
  words, this chain only matches on a Flow Classifier and takes into account
  the Logical Source Port defined by it (unlike **Destination Chains**).

* **Joining Point**: A point in a Service Graph that merges
  multiple incoming branches (**Source Chains**) into the same
  **Destination Chain**.

* **NSP**: Network Service Path (same as **SPI**).

* **NSI**: Network Service Index (same as **SI**).

* **SFP**: Service Function Path.

* **SI**: Service Index.

* **Source Chain**: The Port Chain that provides a branching point
  to Destination Chains. A Source Chain may also be
  an **Initial Chain** or a **Destination Chain**.
  Traffic that leaves a Source Chain, i.e. the egressing traffic
  from the last SF of the chain (and encapsulated for that particular chain)
  will be put into either one or no Destination Chains respective to this
  Source Chain, depending on whether the flow classifiers of the Destination
  Chains successfully match on the egressing traffic of the Source Chain.

* **SPI**: Service Path Identifier (numerically identifies an **SFP**).


Usage
-----

In order to create Port Chains with Port Pairs that make use of the NSH
correlation (i.e. the Network Service Header (NSH) is exposed to the SFs,
so no SFC Proxy is logically instantiated by the networking-sfc backend),
the Port Pair's ``correlation`` service function parameter can be used,
by setting it to ``nsh`` (default is set to ``None``):

``service_function_parameters: {correlation: 'nsh'}``

Alternatively, the MPLS correlation can be used as a workaround to NSH:

``service_function_parameters: {correlation: 'mpls'}``

Enabling the MPLS correlation doesn't fully encapsulate frames like NSH would,
since the MPLS labels are inserted between the Ethernet header and the L3
protocol.

By default, port-chains always have their correlation set to ``mpls``:

``chain_parameters: {correlation: 'mpls'}``

A Port Chain can have Port Pair Groups with MPLS-correlated Port Pairs or
Port Pairs with no correlation. However, each Port Pair Group can only group
Port Pairs that share the same correlation type (to process each hop and expose
their feature set in a consistent and predictable way). The SFC OVS driver and
agent are smart enough to only apply SFC Proxies to the hops that require so.

The MPLS correlation is only recommended when using SFC-proxied Port Pair
Groups. In order to use NSH, the Port Chain correlation must be set to ``nsh``
(to clarify, SFC Proxies can also be used with NSH Port Chains, as long as
the Port Pairs have no correlation set):

``chain_parameters: {correlation: 'nsh'}``

To create a Service Graph, first create the set of Port Chains that will
compose the Service Graph. Then, create the Service Graph itself by referencing
the Port Chains needed as a dictionary of source to (list of) destination
chains, essentially describing each of the branching points of the chain.
The following example, using the OpenStack Client, illustrates this (by
creating a graph that starts from an initial chain ``pc1`` which forks into
``pc2`` and ``pc3``, and then joins back into a single chain ``pc4`` (if
that's what the user intended) using the MPLS correlation (if using NSH, the
flows are equivalent but OpenFlow NSH actions and matches are used instead)::

  # we assume that the Neutron ports p0..p4 are already created and bound
  $ openstack sfc port pair create --ingress p1 --egress p1  --service-function-parameters correlation=mpls pp1
  $ openstack sfc port pair create --ingress p2 --egress p2  --service-function-parameters correlation=mpls pp2
  $ openstack sfc port pair create --ingress p3 --egress p3  --service-function-parameters correlation=mpls pp3
  $ openstack sfc port pair create --ingress p4 --egress p4  --service-function-parameters correlation=mpls pp4
  $ openstack sfc port pair group create --port-pair pp1 ppg1
  $ openstack sfc port pair group create --port-pair pp2 ppg2
  $ openstack sfc port pair group create --port-pair pp3 ppg3
  $ openstack sfc port pair group create --port-pair pp4 ppg4
  $ openstack sfc flow classifier create --protocol udp --source-port 2001 --logical-source-port p0 fc1
  $ openstack sfc flow classifier create --protocol udp --source-port 2002 --logical-source-port p0 fc2
  $ openstack sfc flow classifier create --protocol udp --source-port 2003 --logical-source-port p0 fc3
  $ openstack sfc flow classifier create --protocol udp --source-port 2004 --logical-source-port p0 fc4
  $ openstack sfc port chain create --port-pair-group ppg1 --flow-classifier --chain-parameters correlation=mpls fc1 pc1
  $ openstack sfc port chain create --port-pair-group ppg2 --flow-classifier --chain-parameters correlation=mpls fc2 pc2
  $ openstack sfc port chain create --port-pair-group ppg3 --flow-classifier --chain-parameters correlation=mpls fc3 pc3
  $ openstack sfc port chain create --port-pair-group ppg4 --flow-classifier --chain-parameters correlation=mpls fc4 pc4
  $ openstack sfc service graph create --branching-point pc1:pc2,pc3 --branching-point pc2:pc4 --branching-point pc3:pc4 sg1

In the Python language, the dictionary of Port Chains provided above via the
OpenStack Client would look like this::

  {
      'port_chains': {
          'pc1': ['pc2', 'pc3'],
          'pc2': ['pc4'],
          'pc3': ['pc4']
      }
  }

Note that, because pc2, pc3 and pc4 depend on other chains, their Flow
Classifiers' Logical Source Ports will be ignored.

To clarify what happens under the hood when using the Open vSwitch driver,
let's look at the relevant flows that are generated for the above example:

**Table 0**::

 priority=30,udp,tp_src=2001,in_port=10 actions=push_mpls:0x8847,set_field:511->mpls_label,set_mpls_ttl(255),group:1
 priority=30,udp,tp_src=2002,reg0=0x1fe actions=push_mpls:0x8847,set_field:767->mpls_label,set_mpls_ttl(255),group:2
 priority=30,udp,tp_src=2003,reg0=0x1fe actions=push_mpls:0x8847,set_field:1023->mpls_label,set_mpls_ttl(255),group:3
 priority=30,udp,tp_src=2004,reg0=0x2fe actions=push_mpls:0x8847,set_field:1279->mpls_label,set_mpls_ttl(255),group:4
 priority=30,udp,tp_src=2004,reg0=0x3fe actions=push_mpls:0x8847,set_field:1279->mpls_label,set_mpls_ttl(255),group:4
 priority=30,mpls,in_port=11,mpls_label=510 actions=load:0x1fe->NXM_NX_REG0[],pop_mpls:0x0800,resubmit(,0)
 priority=30,mpls,in_port=12,mpls_label=766 actions=load:0x2fe->NXM_NX_REG0[],pop_mpls:0x0800,resubmit(,0)
 priority=30,mpls,in_port=13,mpls_label=1022 actions=load:0x3fe->NXM_NX_REG0[],pop_mpls:0x0800,resubmit(,0)
 priority=30,mpls,in_port=14,mpls_label=1278 actions=pop_mpls:0x0800,NORMAL

**Table 5**:
(usual flows for sending to table 10 or across tunnel, without proxying)

**Table 10**:
(usual flows to make traffic ingress into the Service Functions, shown below)::

 priority=1,mpls,dl_vlan=1,dl_dst=fa:16:3e:97:91:a2,mpls_label=511 actions=pop_vlan,output:11
 priority=1,mpls,dl_vlan=1,dl_dst=fa:16:3e:87:2a:ad,mpls_label=767 actions=pop_vlan,output:12
 priority=1,mpls,dl_vlan=1,dl_dst=fa:16:3e:77:59:f1,mpls_label=1023 actions=pop_vlan,output:13
 priority=1,mpls,dl_vlan=1,dl_dst=fa:16:3e:34:07:f5,mpls_label=1279 actions=pop_vlan,output:14

**Groups Table**:
(usual flows for load-balancing and re-writing the destination MAC addresses)

Considering that the OF port 10 is p0, 11 is p1, and so on with 14 being p4,
there are three important things to notice from the Service Graphs flows above:

* At the end of the Source Chains (pc1, pc2 and pc3), instead of the typical
  flow (in table 0) that would remove the MPLS shim (with ``pop_mpls``) and
  then use the NORMAL action, the chain's SFP information is written to a
  register (e.g. ``actions=load:0x1fe->NXM_NX_REG0[]``) and the packet
  is sent back to the same table to be matched by a Destination Chain.

* At the beginning of the Destination Chains (pc2, pc3 and pc4), instead of
  the typical flow (in table 0) that would match solely on the Flow Classifier
  (specifically the ingress OF port that comes from the Logical Source Port
  together with the actual traffic classification definition), a specific
  SFP information register value will be matched on (e.g. ``reg0=0x1fe``)
  together with the traffic classification definition from the Flow Classifier
  but not OF ingress port will be used (i.e. Logical Source Port ignored).

* For the case of Joining Points, where a chain is Destination to multiple
  Source Chains, there will be one flow matching on the register value per
  Source Chain, the only difference in the entire flow being the value of
  that register (reflecting each of the Source Chains' SFP infos). Two flows
  can be seen above in table 0, matching on traffic meant for pc4.

Implementation
--------------

PPG/SF Correlation
~~~~~~~~~~~~~~~~~~

At the API side, both MPLS and NSH correlations are defined as possible options
(values) to the ``correlation`` key in the ``service_function_parameters``
field of the ``port_pair`` resource. Furthermore, Port Pair Groups must include
Port Pairs of the same correlation type.

The parameter is saved in the database in the same way as any other port-pair
parameter, inside the ``sfc_service_function_params`` table (example for NSH)::

 keyword='correlation'
 value='nsh'
 pair_id=PORT_PAIR_UUID

The NSH correlation parameter will eventually be fed to the enabled backend,
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
the entire  port-chain. The values may be ``None``, ``'mpls'``, or ``'nsh'``.

``pp_corr`` is the correlation mechanism supported by an individual SF. The
values may be ``'None'``, ``'mpls'``, or ``'nsh'``.

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
                    'pp_corr': 'nsh'
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
                'pc_corr': 'nsh',
                'pp_corr': 'nsh',
                'id': uuidutils.generate_uuid()

It can be seen that ``'nsh'`` appears three times in the flow rule, twice in
the root (specifying the correlation of port-chain and port-pair of the current
hop) and once inside the single hop of ``next_hops``, regarding its port-pair.

The three appearances will dictate how flows (both matches and actions) will
be added by the OVS agent.

Let's take a look at the possible scenarios:

+-+------------------+------------------+-----------------------------------------+
| | Curr Hop pp_corr | Next Hop pp_corr |              Action                     |
+=+==================+==================+=========================================+
|1| NSH/MPLS         | NSH/MPLS         | Egress from SF: match on NSH/MPLS       |
| |                  |                  | to determine next hop                   |
| |                  |                  | Ingress to next SF: send NSH/MPLS to SF |
+-+------------------+------------------+-----------------------------------------+
|2| NSH/MPLS         | None             | Egress from SF: match on NSH/MPLS       |
| |                  |                  | to determine next hop                   |
| |                  |                  | Ingress to next SF: pop NSH/MPLS first  |
+-+------------------+------------------+-----------------------------------------+
|3| None             | NSH/MPLS         | Egress from SF: reclassify packet       |
| |                  |                  | and add new NSH/MPLS                    |
| |                  |                  | Ingress to next SF: send NSH/MPLS to SF |
+-+------------------+------------------+-----------------------------------------+
|4| None             | None             | Egress from SF: reclassify packet       |
| |                  |                  | and add new NSH/MPLS                    |
| |                  |                  | Ingress to next SF: pop NSH/MPLS first  |
+-+------------------+------------------+-----------------------------------------+

An important point to make is that correlations cannot be mixed, i.e. if the
Port Chain uses the MPLS correlation, then its PPGs cannot include Port Pairs
using the NSH correlation, and vice-versa. So, on the table above, consider
either NSH or MPLS for any given row, but not both.

The following further explains each of the possibilities from the table above.
To simplify, the NSH correlation is considered (MPLS is equivalent here).

1. **pp_corr=nsh and every next_hop's pp_corr=nsh**

The ingress of this sf_node will not remove the NSH. When
egressing from this sf_node, OVS will not attempt to match on the
flow_classifier defined in ``add_fcs``, but rather the expected NSH
after the SF is done processing the packet (the NSI is supposed to be
decremented by 1 by the SF). When preparing the packet to go to the next hop,
no attempt at inserting NSH will be done,
since the packet already has the correct labels.

2. **pp_corr=nsh and every next_hop's pp_corr=None**

The ingress of this sf_node will not remove the NSH. When
egressing from this sf_node, OVS will not attempt to match on the
flow_classifier defined in ``add_fcs``, but rather the expected NSH
after the SF is done processing the packet (the NSI is supposed to be
decremented by 1 by the SF). When preparing the packet to go to the next hop,
no attempt at inserting NSH will be done,
since the packet already has the correct labels.
The next hop's own flow rule (not the one shown above) will have an action to
first remove the NSH and then forward to the SF.

3. **pp_corr=None and every next_hop's pp_corr=nsh**

The ingress of this sf_node will first remove the NSH and then forward
to the SF, as its actions. When egressing from this sf_node, OVS will match on
the flow-classifier defined in ``add_fcs``, effectively implementing an SFC
Proxy and running networking-sfc's "classic" mode.
When preparing the packet to go to the next hop, a new NSH needs to be
inserted. This is done on Table 0, the same table where ``add_fcs`` was
matched. Right before the packets are submitted to the Groups Table, they
receive the expected NSH for the next hop. The reason why this can't
be done on the ``ACROSS_SUBNET_TABLE`` like when the next_hop's correlation is
set to None, is the fact that the choice of labels would be ambiguous.
If multiple port-chains share the same port-pair-group at a given hop, then
encapsulating/adding NSH as one of ``ACROSS_SUBNET_TABLE``'s actions
means that at least one of port-chains will be fed the wrong label and,
consequently, leak into a different port-chain. This is due to the fact that,
in ``ACROSS_SUBNET_TABLE``, the flow matches only on the destination MAC
address of the frame (and that isn't enough to know what chain the frame is
part of). So, again, the encapsulation/adding of NSH will have to be
done in Table 0 for this specific scenario where in the current hop the packets
don't have labels but on the next hop they are expected to.

4. **pp_corr=None and every next_hop's pp_corr=None**

This is "classic" networking-sfc. The ingress of this sf_node will first remove
the NSH and then forward to the SF, as its actions. When egressing from
this sf_node, OVS will match on the flow-classifier defined in ``add_fcs``
effectively implementing an SFC Proxy and running networking-sfc's "classic"
mode.
When preparing the packet to go to the next hop, a new NSH needs to be
inserted, which is done at the ``ACROSS_SUBNET_TABLE``, after a destination
port-pair has been chosen with the help of the Groups Table.

Service Graphs
~~~~~~~~~~~~~~

At the API side, Service Graphs are presented as a specific resource called
``service_graph``. Besides the attributes ``id``, ``name``, ``description``
and ``project_id``, this resource expects to have a dictionary called
``port_chains`` that maps source chains to (lists of) destination chains.

Service Graphs "glue" existing Port Chains, creating dependencies between them,
in effect changing the criteria to get into each of the chains by not relying
solely on the Flow Classifier anymore (except for the initial chain of the
graph). Traffic entering a destination chain of a Service Graph is dependent
on its source chain and its own flow classifiers.

In the database, Service Graphs are stored as 2 tables:

* ``sfc_service_graphs``:
  This table stores the independent data of each of the Service Graph
  resources, specifically the name, description and project ID.

* ``sfc_service_graph_chain_associations``:
  This table stores the actual associations between Service Graphs and Port
  Chains, stating which ones are source chains and which ones are destination
  chains. Besides the ``service_graph_id`` field (primary key, and foreign key
  to ``sfc_service_graphs.id``), there are the ``src_chain`` and the
  ``dst_chain`` fields, each pointing to an ID of a Port Chain, both being
  foreign keys to ``sfc_port_chains.id``.

So, to represent the branching points of the example graph provided in the
Usage section above, the following entries would be stored in
``sfc_service_graph_chain_associations``:

+----------------+---------+---------+
|service_graph_id|src_chain|dst_chain|
+----------------+---------+---------+
| SG1 ID         | PC1 ID  | PC2 ID  |
| SG1 ID         | PC1 ID  | PC3 ID  |
| SG1 ID         | PC2 ID  | PC4 ID  |
| SG1 ID         | PC3 ID  | PC4 ID  |
+----------------+---------+---------+

Some of the validations that occur at the database/plugin level are:

* Port Chains can't be deleted if they are in use by a graph.
* Port Chains can't be updated (to include a different set of Port Pair Groups)
  if they are in use by a graph.
* Service Graphs can't have Port Chain loops or circular paths.
* A Port Chain can't be added twice as destination of the same source chain
  (that would essentially replicate packets).
* Port Chains cannot be part of more than one graph at any given time.
* Branching points have to support a correlation protocol (MPLS or NSH).
* The correlation protocol has to be the same for every included Port Chain.
* For a given branching point (destination chain), the traffic classification
  of each branch has to be different to prevent ambiguity.

At the OVS driver level, all of the logic takes place in the postcommit methods,
``create_service_graph_postcommit`` and ``delete_service_graph_postcommit``.
At present time, the dictionary of Port Chains that a Service Graph references
cannot be updated and, as such, the drivers (not just OVS) don't have to support
the update operation.

In essence, the OVS driver will look at the ``port_chains`` dictionary of the
graph and generate flow rules for every branching point. Each branching point
includes both the last path node (the last ``sf_node``) of the respective
source chain and each first path node (the ``src_node``) of the
respective destination chains. All of these flow rules are meant to replace
the flows that the original flow rules (during creation of the Port Chains
themselves) had requested the agent to create.

The flow rules for the source chains will include a special attribute called
``branch_point``, set to the value of ``True``. This indicates to the agent
that this path node's (expected to be the last ``sf_node`` of that chain)
NSP and NSI should be saved so that the destination chains can match on them
while doing the normal traffic classification (via their own Flow Classifiers).
Example::

  'branch_point': True

The flow rules for the destination chains will include a special attribute
called ``branch_info``, a dictionary with two keys: ``matches`` and ``on_add``.
Example::

  'branch_info': {
      'matches': set([(2, 254), (3, 254)]),
      'on_add': True
  }

``matches`` contains a set of tuples with the NSP and NSI (``(<nsp>, <nsi>)``)
to be matched by the particular destination chain. ``on_add`` simply specifies
whether the ``matches`` should be used when adding the flow or otherwise when
removing the flow - in very much the same fashion as ``add_fcs``/``del_fcs``
for the Flow Classifiers, except that here it's either adding or removing
the NSP/NSI matches and never replacing/updating them.

For source chains' ``branch_point`` there is no need to have an ``on_add``
since the OpenFlow matches will not change depending on whether we are removing
or adding this branch point. Only the actions will change (for relevant flows
in Table 0).

At the OVS agent level, ``branch_point`` and ``branch_info`` are interpreted
in order to generate the appropriate set of flows, replacing the ones
originally created by the constituent Port Chains
(to clarify, only the flows at the branching points).

``'branch_point': True`` will tell the agent to replace the egress flow from the
last ``sf_node``, in Table 0, with a new one whose actions will be to:
* copy the NSP and NSI from the MPLS label or NSH into a register: ``reg0``;
* remove the MPLS label or NSH;
* send the traffic back to Table 0, now without MPLS/NSH but with ``reg0`` set.
Example of this flow (using MPLS correlation)::

  table=0,priority=30,mpls,in_port=8,mpls_label=509 actions=load:0x1fd->NXM_NX_REG0[],pop_mpls:0x0800,resubmit(,0)

When ``branch_info`` is set, with ``'on_add': True`` and
``'matches': set([(1, 253))``, the agent will replace the egress flow from the
``src_node`` of the destination chain that is specified in the flow rule,
in Table 0, with a different set of matches from a typical ``src_node``:
* it will still match on what the Flow Classifiers specify;
* but the logical source port match is ignored (there is not in_port=X);
* most importantly, it will match on a specified value of ``reg0`` (NSP/NSI).
Example of this flow (using MPLS correlation)::

  table=0,priority=30,udp,reg0=0x1fd actions=push_mpls:0x8847,set_field:767->mpls_label,set_mpls_ttl(255),group:3

With ``'on_add': False``, the agent will replace the above flow with the
original flow for the ``src_node`` of that Port Chain, matching only on the
Flow Classifiers' fields.

Known Limitations
-----------------

* Service Graphs is not compatible with Symmetric Port Chains at the moment.
  Furthermore, Service Graphs are unidirectional;
* The MPLS correlation protocol does not provide full frame encapsulation,
  so the SFC Encapsulation NSH protocol should be used instead;
* Every Port Chain has to have a different set of Flow Classifiers, even if the
  logical source ports are different, even when they are attached to Service
  Graphs. This is necessary when deploying Port Chains that have Port Pairs
  with no correlation protocol (to prevent per-hop classification ambiguity),
  but is a limitation otherwise and hasn't been addressed yet;
* SI/NSI is only available at the Open vSwitch driver level, meaning that
  the networking-sfc API can't consistently manage and persist all of the SFP
  information (only SPI/NSP) independently of the driver. SI/NSI and SPI/NSP
  are used by the logical Service Function Forwarders (SFF) that the drivers
  are expected to control.

References
----------

[1] https://datatracker.ietf.org/doc/rfc7665/?include_text=1

[2] http://i.imgur.com/rxzNNUZ.png

[3] http://i.imgur.com/nzgatKB.png

[4] https://bugs.launchpad.net/networking-sfc/+bug/1587486

[5] https://datatracker.ietf.org/doc/draft-ietf-sfc-nsh/?include_text=1
