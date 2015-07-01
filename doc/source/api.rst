..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

========================
API for Service Chaining
========================

Problem Description
===================

Currently Neutron does not support service chaining. To support
service chaining, Service VMs must be attached at points in the
network and then traffic must be steered between these attachment
points. Please also refer to the Neutron
Service Chain BP associated with this specification [1] and the
Service Chain Bug ID [2][3].

Proposed Change
===============

All Neutron network services and VMs are connected to a Neutron network
via Neutron ports. This makes it possible to create a traffic steering model
for service chaining that uses only Neutron ports. This traffic steering
model has no notion of the actual services attached to these Neutron
ports.

The service VM hosting the service functions is instantiated and configured,
then VNICs are added to the VM and then these VNICs are attached to the
network by Neutron ports. Once the service function is attached to Neutron
ports, the ports may be included in a "port chain" to allow the service
function to provide treatment to the user's traffic.

A Port Chain (Service Function Path) consists of:

* a set of Neutron ports, to define the sequence of service functions
* a set of flow classifiers, to specify the classified traffic flows to
  enter the chain

If a service function has a pair of ports, the first port in
the port-pair is the ingress port of the service function, and the second
port is the egress port of the service function.
If a service function has one bidirectional port, then both ports in
the port-pair have the same value.
A Port Chain is a directional service chain. The first port of the first port-pair
is the head of the service chain. The second port of the last port-pair is the tail
of the service chain. A bidirectional service chain would be composed of two unidirectional Port Chains.

For example, [{'p1': 'p2'}, {'p3': 'p4'}, {'p5': 'p6'}] represents::

       +------+     +------+     +------+
       | SF1  |     | SF2  |     | SF3  |
       +------+     +------+     +------+
       p1|  |p2     p3|  |p4      p5| |P6
         |  |         |  |          | |
     ----+  +---------+  +----------+-|---->

where P1 is the head of the Port Chain and P6 is the tail of the Port Chain, and
SF1 has ports p1 and p2, SF2 has ports p3 and p4, and SF3 has ports p5 and p6.

In order to create a chain, the user needs to have the actual port objects.
The work flow would typically be:

a) create the ports
b) create the chain
c) boot the vm's passing the ports as nic's parameters

The sequence of b) and c) can be switched.

A SF's Neutron port may be associated with more than one Port Chain to allow
a service function to be shared by multiple chains.

If there is more than one service function instance of a specific type
available to meet the user's service requirement, their Neutron ports are
included in the port chain as a sub-list. For example, if {p3, p4}, {p7, p8}
are the port-pairs of two FW instances, they
both may be included in a port chain for load distribution as shown below.

  [{'p1': 'p2'}, [{'p3': 'p4'},{'p7': 'p8'}], {'p5': 'p6'}]

Flow classifiers are used to select the traffic that can
access the chain. Traffic that matches any flow classifier will be
directed to the first port in the chain. The flow classifier will be a generic
independent module and may be used by other projects like FW, QOS, etc.

A flow classifier cannot be part of two different port-chains otherwise ambiguity
will arise as to which chain path that flow's packets should go. A check will be
made to ensure no ambiguity. But multiple flow classifiers can be associated with
a port chain since multiple different types of flows can request the same service
treatment path.

CLI Commands

Syntax::

 neutron port-chain-create [-h]
         [--description <description>]
          --port-group <port-group-id>
         [--flow-classifier <classifier-id>]
         [--parameter <chain-parameter-id>] PORTCHAIN-NAME

 neutron port-group-create [-h]
         [-–description <description>]
         --port-pair ingress=<port-id> egress=<port-id> PORTGROUP-NAME

 neutron flow-classifier-create [-h]
         [--description <description>]
         [--protocol <protocol>]
         [--source-port min=<Minimum source protocol port> max=<Maximum source protocol port>]
         [--destination-port min=<Minimum destination protocol port> max=<Maximum destination protocol port>]
         [--source-ip-prefix <Source IP prefix>]
         [--destination-ip-prefix <Destination IP prefix>]
         [--source-port-id <Source Neutron port Id>]
         [--destination-port-id <Destination Neutron port Id>]
         [--l7-parameter <L7 parameter>] FLOW-CLASSIFIER-NAME

 neutron chain-parameter-create [-h]
         [--description <description>]
         [--parameter <parameters>] CHAIN-PARAMETER-NAME

1. neutron port-chain-create
The port-chain-create returns the id of the Port Chain.

Each "port-group" attribute specifies a type of SF. If a chain consists of a sequence
of different types of SFs, then the chain will have multiple "port-group"s.

The "flow-classifier" attribute may be repeated to associate multiple flow classifiers
with a port chain, with each classifier identifying a flow.

The "parameter" attribute in the Port Chain command references the Chain Parameter resource.
One field in the Chain Parameter resource is the encapsulation mechanism. In a service chain,
each SF may support multipel chain-ID encapsulation mechanisms(NSH, VLAN etc.). To support
interoperability between these SFs in the chain, a common encapsulation format needs to be
specified for the chain through the API. Different chains might have different common
encapsulation mechanism, so it does not make sense to specify this in the config files.
Note that we will not implement and support any encap mechanism in the first code release.

A port chain can be created, read, updated and deleted, and when a chain is
created/updated/read/deleted, the attributes that are involved would be based on
the CRUD in the "Port Chain" resource table below.

2. neutron port-group-create
Inside each "port-group", there could be one or more port-pairs.
Multiple port-pairs may be included in a "port-group" to allow the specification of
a set of like SFs that can be be used for load distribution, i.e., the "ingress" and
"egress" fields may be repeated for multiple port-pairs of like SFs.

3. neutron flow-classifier-create
A combination of the "source" attributes defines the source of the flow.
A combination of the "destination" attributes defines the destination of the flow.
The l7_parameter is a place-holder that may be used to support flow classification
using L7 fields, such as URL.

4. neutron chain-parameter-create
chain-parameter-create returns a chain parameter id which is referenced in the port-chain command.
The Chain Parameter resource table below specifies two parameter options currently defined.
More parameter options can be added in future extension to accomodate future requirements.
The "correlation" parameter is used to specify the type of chain correlation mechanism.
This will be set to none for now to be consistent with current OVS capability.
The "failure_policy" parameter is used to specify the action to be taken on a SF failure.

Data Model Impact
-----------------

Data model::

        +-------+        +--------+        +------------+
        | Port  |--------| Port   |--------| Neutron    |
        | Chain |*      *| Groups | 1     *| Port pairs |
        +-------+        +--------+        +------------+
          |1  |1
          |    --------------
          |*                 |1
       +--------------+  +----------+
       | Flow         |  | Chain    |
       | Classifiers  |  |Parameters|
       +--------------+  +----------+

New objects:

Port Chain
  * id - Port chain id.
  * tenant_id - Tenant id.
  * name - Readable name.
  * description - Description.
  * port-groups - List of port-group ids.
  * flow-classifiers - List of flow-classifier ids.
  * parameters - Id of optional Chain parameters.

Port Group
  * id - Port group id.
  * tenant_id - Tenant id.
  * name - Readable name.
  * description - Description.
  * port-pairs - List of service function (Neutron) port-pairs.

Flow Classifier
  * id - Flow classifier id.
  * tenant_id - Tenant id.
  * name - Readable name.
  * description - Description.
  * protocol - IP protocol.
  * src_port_range_min - Minimum source protocol port.
  * src_port_range_max - Maximum source protocol port.
  * dst_port_range_min - Minimum destination protocol port.
  * dst_port_range_max - Maximum destination protocol port.
  * src_ip_prefix - Source IP address or prefix.
  * dst_ip_prefix - Destination IP address or prefix.
  * src_port_id - Source Neutron port Id.
  * dst_port_id - Destination Neutron port Id.
  * l7_parameter - Dict. of L7 parameters.

Chain Parameters
  * id - Chain parameters id.
  * tenant_id - Tenant id.
  * name - Readable name.
  * description - Description.
  * parameters - Dict of optional Chain parameters.

REST API Impact
---------------

The following new resources will be created as a result of the API handling.

Port Chain resource:

+----------------+----------+--------+---------+----+------------------------+
|Attribute       |Type      |Access  |Default  |CRUD|Description             |
|Name            |          |        |Value    |    |                        |
+================+==========+========+=========+====+========================+
|id              |uuid      |RO, all |generated|R   |identity                |
+----------------+----------+--------+---------+----+------------------------+
|tenant_id       |uuid      |RO, all |from auth|CR  |Tenant Id               |
|                |          |        |token    |    |                        |
+----------------+----------+--------+---------+----+------------------------+
|name            |string    |RW, all |''       |CRU |human-readable          |
|                |          |        |         |    |name                    |
+----------------+----------+--------+---------+----+------------------------+
|description     |string    |RW, all |''       |CRU |human-readable          |
+----------------+----------+--------+---------+----+------------------------+
|port_group      |list(uuid)|RW, all |[]       |CR  |List of port-groups     |
+----------------+----------+--------+---------+----+------------------------+
|flow_classifier |list(uuid)|RW, all |[]       |CRU |List of flow            |
|                |          |        |         |    | classifiers            |
+----------------+----------+--------+---------+----+------------------------+
|parameter       |uuid      |RW, all |N/A      |CR  |Id. of chain parameters |
+----------------+----------+--------+---------+----+------------------------+

Port Group resource:

+-------------+--------+---------+---------+----+--------------------+
|Attribute    |Type    |Access   |Default  |CRUD|Description         |
|Name         |        |         |Value    |    |                    |
+=============+========+=========+=========+====+====================+
|id           |uuid    |RO, all  |generated|R   |identity            |
+-------------+--------+---------+---------+----+--------------------+
|tenant_id    |uuid    |RO, all  |from auth|CR  |Tenant Id           |
|             |        |         |token    |    |                    |
+-------------+--------+---------+---------+----+--------------------+
|name         |string  |RW, all  |''       |CRU |human-readable name |
+-------------+--------+---------+---------+----+--------------------+
|description  |string  |RW, all  |''       |CRU |human-readable      |
+-------------+--------+---------+---------+----+--------------------+
|port_pair    |list    |RW, all  |[]       |CRU |list of port-pairs  |
+-------------+--------+---------+---------+----+--------------------+

Flow Classifier resource:

+-------------+--------+---------+---------+----+--------------------+
|Attribute    |Type    |Access   |Default  |CRUD|Description         |
|Name         |        |         |Value    |    |                    |
+=============+========+=========+=========+====+====================+
|id           |uuid    |RO, all  |generated|R   |identity            |
+-------------+--------+---------+---------+----+--------------------+
|tenant_id    |uuid    |RO, all  |from auth|CR  |Tenant Id           |
|             |        |         |token    |    |                    |
+-------------+--------+---------+---------+----+--------------------+
|name         |string  |RW, all  |''       |CRU |human-readable name |
+-------------+--------+---------+---------+----+--------------------+
|description  |string  |RW, all  |''       |CRU |human-readable      |
+-------------+--------+---------+---------+----+--------------------+
|protocol     |integer |RW, all  |N/A      |CR  |0-255, the protocol |
|             |        |         |         |    |field in IP header  |
+-------------+--------+---------+---------+----+--------------------+
|src_port     |integer |RW, all  |N/A      |CR  |Min. source         |
|_range_min   |        |         |         |    | protocol port      |
+-------------+--------+---------+---------+----+--------------------+
|src_port     |integer |RW, all  |N/A      |CR  |Max. source         |
|_range_max   |        |         |         |    | protocol port      |
+-------------+--------+---------+---------+----+--------------------+
|dst_port     |integer |RW, all  |N/A      |CR  |Min. destination    |
|_range_min   |        |         |         |    | protocol port      |
+-------------+--------+---------+---------+----+--------------------+
|dst_port     |integer |RW, all  |N/A      |CR  |Max. destination    |
|_range_max   |        |         |         |    | protocol port      |
+-------------+--------+---------+---------+----+--------------------+
|src_ip_prefix|CIDR    |RW, all  |N/A      |CR  |Source IP address or|
|             |        |         |         |    |prefix, IPV4 or IPV6|
+-------------+--------+---------+---------+----+--------------------+
|dst_ip_prefix|CIDR    |RW, all  |N/A      |CR  |Destination IP      |
|             |        |         |         |    | address or prefix  |
|             |        |         |         |    | IPV4 or IPV6       |
+-------------+--------+---------+---------+----+--------------------+
|src_port_id  |uuid    |RW, all  |N/A      |CR  |Source Neutron      |
|             |        |         |         |    | port Id            |
+-------------+--------+---------+---------+----+--------------------+
|dst_port_id  |uuid    |RW, all  |N/A      |CR  |Destination Neutron |
|             |        |         |         |    | port Id            |
+-------------+--------+---------+---------+----+--------------------+
|l7_parameters|dict    |RW, all  |N/A      |CR  |Dict. of            |
|             |        |         |         |    | L7 parameters      |
+-------------+--------+---------+---------+----+--------------------+

Chain Parameter resource:

+------------+------+---------+---------+----+------------------------+
|Attribute   |Type  |Access   |Default  |CRUD|Description             |
|Name        |      |         |Value    |    |                        |
+============+======+=========+=========+====+========================+
|id          |uuid  |RO, all  |generated|R   |identity                |
+------------+------+---------+---------+----+------------------------+
|tenant_id   |uuid  |RO, all  |from auth|CR  |Tenant Id               |
|            |      |         |token    |    |                        |
+------------+------+---------+---------+----+------------------------+
|name        |string|RW, all  |''       |CRU |human-readable name     |
+------------+------+---------+---------+----+------------------------+
|description |string|RW, all  |''       |CRU |human-readable          |
+------------+------+---------+---------+----+------------------------+
|parameters  |dict  |RW, all  |N/A      |CRU |Dict. of parameters:    |
|            |      |         |         |    |'correlation':String    |
|            |      |         |         |    |'failure_policy':String |
+------------+------+---------+---------+----+------------------------+


Json Port Chain Request Example::

 {"port_chain": {"name": "PC2",
        "tenant_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Two flows and three port-pairs",
        "flow-classifier": [
            "456a4a34-2e9c-14ae-37fb-765feae2eb05",
            "4a334cd4-fe9c-4fae-af4b-321c5e2eb051"
        ],
        "port-group": [
            "4512d643-24fc-4fae-af4b-321c5e2eb3d1",
            "4a634d49-76dc-4fae-af4b-321c5e23d651"
        ],
    }
 }

Json Port Chain Response Example::

 {"port_chain": {"name": "PC2",
        "tenant_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Two flows and three port-pairs",
        "flow-classifier": [
            "456a4a34-2e9c-14ae-37fb-765feae2eb05",
            "4a334cd4-fe9c-4fae-af4b-321c5e2eb051"
        ],
        "port-group": [
            "4512d643-24fc-4fae-af4b-321c5e2eb3d1",
            "4a634d49-76dc-4fae-af4b-321c5e23d651"
        ],
         "id": "1278dcd4-459f-62ed-754b-87fc5e4a6751"
    }
 }

Json Flow Classifier Request Example::

 {"flow_classifier": {"name": "flow1",
        "tenant_id": "1814726e2d22407b8ca76db5e567dcf1",
        "protocol": "tcp",
        "src_port_range_min": 22, "src_port_range_max": 4000,
        "dst_port_range_min": 80, "dst_port_range_max": 80,
        "src_ip_prefix": null, "dst_ip_prefix": "22.12.34.45"
    }
 }

Json Flow Classifier Response Example::

 {"flow_classifier": {"name": "flow1",
        "tenant_id": "1814726e2d22407b8ca76db5e567dcf1",
        "protocol": "tcp",
        "src_port_range_min": 22, "src_port_range_max": 4000,
        "dst_port_range_min": 80, "dst_port_range_max": 80,
        "src_ip_prefix": null , "dst_ip_prefix": "22.12.34.45",
        "id": "4a334cd4-fe9c-4fae-af4b-321c5e2eb051"
    }
 }

Implementation
==============

Assignee(s)
-----------
Authors of the Specification and Primary contributors:
 * Cathy Zhang (cathy.h.zhang@huawei.com)
 * Louis Fourie (louis.fourie@huawei.com)

Other contributors:
 * Vikram Choudhary (vikram.choudhary@huawei.com)
 * Swaminathan Vasudevan (swaminathan.vasudevan@hp.com)
 * Yuji Azama (yuj-azama@rc.jp.nec.com)
 * Mohankumar (nmohankumar1011@gmail.com)
 * Ramanjaneya (ramanjieee@gmail.com)
 * Stephen Wong (stephen.kf.wong@gmail.com)
 * Nicolas Bouthors (Nicolas.BOUTHORS@qosmos.com)

References
==========

.. [1] https://blueprints.launchpad.net/neutron/+spec/neutron-api-extension-for-service-chaining
.. [2] https://bugs.launchpad.net/neutron/+bug/1450617
.. [3] https://bugs.launchpad.net/neutron/+bug/1450625
