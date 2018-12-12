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


=========
API Model
=========

Problem Description
===================

Currently Neutron does not support service function chaining. To support
service function chaining, Service VMs must be attached at points in the
network and then traffic must be steered between these attachment
points. Please refer to `Neutron Service Chain blue-print <https://blueprints.launchpad.net/neutron/+spec/neutron-api-extension-for-service-chaining>`_ and Bugs `[1] <https://bugs.launchpad.net/neutron/+bug/1450617>`_ `[2] <https://bugs.launchpad.net/neutron/+bug/1450625>`_
related to this specification for more information.

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
       p1|  |p2     p3|  |p4      p5| |p6
         |  |         |  |          | |
    ->---+  +---------+  +----------+ +---->

where p1 is the head of the Port Chain and p6 is the tail of the Port Chain, and
SF1 has ports p1 and p2, SF2 has ports p3 and p4, and SF3 has ports p5 and p6.

In order to create a chain, the user needs to have the actual port objects.
The work flow would typically be:

1. create the ports
2. create the chain
3. boot the vm's passing the ports as nic's parameters

The sequence of 2. and 3. can be switched.

A SF's Neutron port may be associated with more than one Port Chain to allow
a service function to be shared by multiple chains.

If there is more than one service function instance of a specific type
available to meet the user's service requirement, their Neutron ports are
included in the port chain as a sub-list. For example, if {p3, p4}, {p7, p8}
are the port-pairs of two FW instances, they
both may be included in a port chain for load distribution as shown below::

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
~~~~~~~~~~~~

Syntax::

 openstack sfc port pair create [-h]
         [--description <description>]
         --ingress <port-id>
         --egress <port-id>
         [--service-function-parameters <parameter>] PORT-PAIR-NAME

 openstack sfc port pair group create [-h]
         [--description <description>]
         --port-pair <port-pair-id>
         [--port-pair-group-parameters <parameter>] PORT-PAIR-GROUP-NAME

 openstack sfc flow classifier create [-h]
         [--description <description>]
         [--protocol <protocol>]
         [--ethertype <Ethertype>]
         [--source-port <Minimum source protocol port>:<Maximum source protocol port>]
         [--destination-port <Minimum destination protocol port>:<Maximum destination protocol port>]
         [--source-ip-prefix <Source IP prefix>]
         [--destination-ip-prefix <Destination IP prefix>]
         [--logical-source-port <Neutron source port>]
         [--logical-destination-port <Neutron destination port>]
         [--l7-parameters <L7 parameter>] FLOW-CLASSIFIER-NAME

 openstack sfc port chain create [-h]
         [--description <description>]
          --port-pair-group <port-pair-group-id>
         [--flow-classifier <classifier-id>]
         [--chain-parameters <chain-parameter>] PORT-CHAIN-NAME

openstack sfc port chain create
-------------------------------

The ``sfc port chain create`` command returns the ID of the Port Chain.

Each ``--port-pair-group`` option specifies a type of SF. If a chain consists of a sequence
of different types of SFs, then the chain will have multiple "port-pair-group"s.
There must be at least one "port-pair-group" in the Port Chain.

The ``-flow-classifier`` option may be repeated to associate multiple flow classifiers
with a port chain, with each classifier identifying a flow. If the flow-classifier is not
specified, then no traffic will be steered through the chain.

One chain parameter option is currently defined. More parameter options can be added
in future extensions to accommodate new requirements.
The ``correlation`` parameter is used to specify the type of chain correlation mechanism.
This parameter allows different correlation mechanisms to be selected.
The chain correlation concept is equivalent to SFC Encapsulation,
as defined in RFC 7665.
The default is "mpls", but "nsh" is also supported.

The ``sfc port chain create`` command returns the ID of a Port chain.

A port chain can be created, read, updated and deleted, and when a chain is
created/read/updated/deleted, the options that are involved would be based on
the CRUD in the "Port Chain" resource table below.

openstack sfc port pair group create
------------------------------------

Inside each "port-pair-group", there could be one or more port-pairs.
Multiple port-pairs may be included in a "port-pair-group" to allow the specification of
a set of functionally equivalent SFs that can be used for load distribution,
i.e., the ``--port-pair`` option may be repeated for multiple port-pairs of
functionally equivalent SFs.

The ``sfc port pair group create`` command returns the ID of a Port Pair group.

openstack sfc port pair create
------------------------------

A Port Pair represents a service function instance. The ingress port and the
egress port of the service function may be specified.  If a service function
has one bidirectional port, the ingress port has the same value as the egress port.
The ``--service-function-parameters`` option allows the passing of SF specific parameter
information to the data path. These include:

* The ``correlation`` parameter is used to specify the type of chain correlation
  mechanism supported by a specific SF. This is needed by the data plane
  switch to determine how to associate a packet with a chain. This will be set
  to "none" for now since there is no correlation mechanism supported by the
  SF. In the future, it can be extended to include "mpls", "nsh", etc.. If
  this parameter is not specified, it will default to "none".

* The ``weight`` parameter is used to specify the weight for each SF for
  load distribution in a port pair group. This represents a percentage of the
  traffic to be sent to each SF.

The ``sfc port pair create`` command returns the ID of a Port Pair.

openstack sfc flow classifier create
------------------------------------

A combination of the "source" options defines the source of the flow.
A combination of the "destination" options defines the destination of the flow.
The l7_parameter is a place-holder that may be used to support flow classification
using L7 fields, such as URL. If an option is not specified, it will default to wildcard value
except for ethertype which defaults to 'IPv4', for logical-source-port and
logical-destination-port which defaults to none.

The ``sfc flow classifier create`` command returns the ID of a flow classifier.


Data Model Impact
~~~~~~~~~~~~~~~~~

Data model::

        +-------+        +----------+        +------------+
        | Port  |--------| Port Pair|--------| Port Pairs |
        | Chain |*      *| Groups   | 1     *|            |
        +-------+        +----------+        +------------+
          |1
          |
          |*
       +--------------+
       | Flow         |
       | Classifiers  |
       +--------------+

New objects:

Port Chain
  * id - Port chain ID.
  * project_id - Tenant ID.
  * name - Readable name.
  * description - Readable description.
  * port_pair_groups - List of port-pair-group IDs.
  * flow_classifiers - List of flow-classifier IDs.
  * chain_parameters - Dict. of chain parameters.
  * chain_id - Data-plane chain path ID.

Port Pair Group
  * id - Port pair group ID.
  * project_id - Tenant ID.
  * name - Readable name.
  * description - Readable description.
  * port_pairs - List of service function (Neutron) port-pairs.
  * port_pair_group_parameters - Dict. of port pair group parameters.

Port Pair
  * id - Port pair ID.
  * project_id - Tenant ID.
  * name - Readable name.
  * description - Readable description.
  * ingress - Ingress port.
  * egress - Egress port.
  * service_function_parameters - Dict. of service function parameters

Flow Classifier
  * id - Flow classifier ID.
  * project_id - Tenant ID.
  * name - Readable name.
  * description - Readable description.
  * ethertype - Ethertype ('IPv4'/'IPv6').
  * protocol - IP protocol.
  * source_port_range_min - Minimum source protocol port.
  * source_port_range_max - Maximum source protocol port.
  * destination_port_range_min - Minimum destination protocol port.
  * destination_port_range_max - Maximum destination protocol port.
  * source_ip_prefix - Source IP address or prefix.
  * destination_ip_prefix - Destination IP address or prefix.
  * logical_source_port - Neutron source port.
  * logical_destination_port - Neutron destination port.
  * l7_parameters - Dictionary of L7 parameters.

REST API
~~~~~~~~

Port Chain Operations:

+------------+---------------------------+------------------------------------------+
|Operation   |URL                        |Description                               |
+============+===========================+==========================================+
|POST        |/sfc/port_chains           |Create a Port Chain                       |
+------------+---------------------------+------------------------------------------+
|PUT         |/sfc/port_chains/{chain_id}|Update a specific Port Chain              |
+------------+---------------------------+------------------------------------------+
|DELETE      |/sfc/port_chains/{chain_id}|Delete a specific Port Chain              |
+------------+---------------------------+------------------------------------------+
|GET         |/sfc/port_chains           |List all Port Chains for specified tenant |
+------------+---------------------------+------------------------------------------+
|GET         |/sfc/port_chains/{chain_id}|Show information for a specific Port Chain|
+------------+---------------------------+------------------------------------------+

Port Pair Group Operations:

+------------+--------------------------------+-----------------------------------------------+
|Operation   |URL                             |Description                                    |
+============+================================+===============================================+
|POST        |/sfc/port_pair_groups           |Create a Port Pair Group                       |
+------------+--------------------------------+-----------------------------------------------+
|PUT         |/sfc/port_pair_groups/{group_id}|Update a specific Port Pair Group              |
+------------+--------------------------------+-----------------------------------------------+
|DELETE      |/sfc/port_pair_groups/{group_id}|Delete a specific Port Pair Group              |
+------------+--------------------------------+-----------------------------------------------+
|GET         |/sfc/port_pair_groups           |List all Port Pair Groups for specified tenant |
+------------+--------------------------------+-----------------------------------------------+
|GET         |/sfc/port_pair_groups/{group_id}|Show information for a specific Port Pair      |
+------------+--------------------------------+-----------------------------------------------+

Port Pair Operations:

+------------+-------------------------+------------------------------------------+
|Operation   |URL                      |Description                               |
+============+=========================+==========================================+
|POST        |/sfc/port_pairs          |Create a Port Pair                        |
+------------+-------------------------+------------------------------------------+
|PUT         |/sfc/port_pairs/{pair_id}|Update a specific Port Pair               |
+------------+-------------------------+------------------------------------------+
|DELETE      |/sfc/port_pairs/{pair_id}|Delete a specific Port Pair               |
+------------+-------------------------+------------------------------------------+
|GET         |/sfc/port_pairs          |List all Port Pairs for specified tenant  |
+------------+-------------------------+------------------------------------------+
|GET         |/sfc/port_pairs/{pair_id}|Show information for a specific Port Pair |
+------------+-------------------------+------------------------------------------+

Flow Classifier Operations:

+------------+-------------------------------+------------------------------------------------+
|Operation   |URL                            |Description                                     |
+============+===============================+================================================+
|POST        |/sfc/flow_classifiers          |Create a Flow-classifier                        |
+------------+-------------------------------+------------------------------------------------+
|PUT         |/sfc/flow_classifiers/{flow_id}|Update a specific Flow-classifier               |
+------------+-------------------------------+------------------------------------------------+
|DELETE      |/sfc/flow_classifiers/{flow_id}|Delete a specific Flow-classifier               |
+------------+-------------------------------+------------------------------------------------+
|GET         |/sfc/flow_classifiers          |List all Flow-classifiers for specified tenant  |
+------------+-------------------------------+------------------------------------------------+
|GET         |/sfc/flow_classifiers/{flow_id}|Show information for a specific Flow-classifier |
+------------+-------------------------------+------------------------------------------------+

REST API Impact
~~~~~~~~~~~~~~~

The following new resources will be created as a result of the API handling.

Port Chain resource:

+----------------+----------+--------+---------+----+-------------------------+
|Attribute       |Type      |Access  |Default  |CRUD|Description              |
|Name            |          |        |Value    |    |                         |
+================+==========+========+=========+====+=========================+
|id              |uuid      |RO, all |generated|R   |Port Chain ID.           |
+----------------+----------+--------+---------+----+-------------------------+
|project_id      |uuid      |RO, all |from auth|CR  |Tenant ID.               |
|                |          |        |token    |    |                         |
+----------------+----------+--------+---------+----+-------------------------+
|name            |string    |RW, all |''       |CRU |Port Chain name.         |
+----------------+----------+--------+---------+----+-------------------------+
|description     |string    |RW, all |''       |CRU |Port Chain description.  |
+----------------+----------+--------+---------+----+-------------------------+
|port_pair_groups|list(uuid)|RW, all |N/A      |CRU |List of port-pair-groups.|
+----------------+----------+--------+---------+----+-------------------------+
|flow_classifiers|list(uuid)|RW, all |[]       |CRU |List of flow-classifiers.|
+----------------+----------+--------+---------+----+-------------------------+
|chain_parameters|dict      |RW, all |mpls     |CR  |Dict. of parameters:     |
|                |          |        |         |    |'correlation':String     |
+----------------+----------+--------+---------+----+-------------------------+
|chain_id        |integer   |RW, all |Any      |CR  |Data-plane Chain Path ID.|
+----------------+----------+--------+---------+----+-------------------------+

The data-plane chain path ID is normally generated by the data-plane
implementation. However, an application may optionally generate its own
data-plane chain path ID and apply it to the Port Chain using the chain_id
attribute.

Port Pair Group resource:

+----------------+----------+--------+---------+----+-------------------------+
|Attribute       |Type      |Access  |Default  |CRUD|Description              |
|Name            |          |        |Value    |    |                         |
+================+==========+========+=========+====+=========================+
|id              |uuid      |RO, all |generated|R   |Port pair group ID.      |
+----------------+----------+--------+---------+----+-------------------------+
|project_id      |uuid      |RO, all |from auth|CR  |Tenant ID.               |
|                |          |        |token    |    |                         |
+----------------+----------+--------+---------+----+-------------------------+
|name            |string    |RW, all |''       |CRU |Port pair group name.    |
+----------------+----------+--------+---------+----+-------------------------+
|description     |string    |RW, all |''       |CRU |Port pair group          |
|                |          |        |         |    |description.             |
+----------------+----------+--------+---------+----+-------------------------+
|port_pairs      |list      |RW, all |N/A      |CRU |List of port-pairs.      |
+----------------+----------+--------+---------+----+-------------------------+
|port_pair_group |dict      |RW, all |''       |CR  |Dict. of parameters:     |
|_parameters     |          |        |         |    |'lb_fields':String       |
|                |          |        |         |    |'service_type':String    |
+----------------+----------+--------+---------+----+-------------------------+

Port Pair resource:

+---------------------------+--------+---------+---------+----+----------------------+
|Attribute Name             |Type    |Access   |Default  |CRUD|Description           |
+===========================+========+=========+=========+====+======================+
|id                         |uuid    |RO, all  |generated|R   |Port pair ID.         |
+---------------------------+--------+---------+---------+----+----------------------+
|project_id                 |uuid    |RO, all  |from auth|CR  |Tenant ID.            |
|                           |        |         |token    |    |                      |
+---------------------------+--------+---------+---------+----+----------------------+
|name                       |string  |RW, all  |''       |CRU |Port pair name.       |
+---------------------------+--------+---------+---------+----+----------------------+
|description                |string  |RW, all  |''       |CRU |Port pair description.|
+---------------------------+--------+---------+---------+----+----------------------+
|ingress                    |uuid    |RW, all  |N/A      |CR  |Ingress port ID.      |
+---------------------------+--------+---------+---------+----+----------------------+
|egress                     |uuid    |RW, all  |N/A      |CR  |Egress port ID.       |
+---------------------------+--------+---------+---------+----+----------------------+
|service_function_parameters|dict    |RW, all  |None     |CR  |Dict. of parameters:  |
|                           |        |         |         |    |'correlation':String  |
|                           |        |         |         |    |'weight':Integer      |
+---------------------------+--------+---------+---------+----+----------------------+

Flow Classifier resource:

+--------------------------+--------+---------+---------+----+-----------------------+
|Attribute Name            |Type    |Access   |Default  |CRUD|Description            |
|                          |        |         |Value    |    |                       |
+==========================+========+=========+=========+====+=======================+
|id                        |uuid    |RO, all  |generated|R   |Flow-classifier ID.    |
+--------------------------+--------+---------+---------+----+-----------------------+
|project_id                |uuid    |RO, all  |from auth|CR  |Tenant ID.             |
|                          |        |         |token    |    |                       |
+--------------------------+--------+---------+---------+----+-----------------------+
|name                      |string  |RW, all  |''       |CRU |Flow-classifier name.  |
+--------------------------+--------+---------+---------+----+-----------------------+
|description               |string  |RW, all  |''       |CRU |Flow-classifier        |
|                          |        |         |         |    |description.           |
+--------------------------+--------+---------+---------+----+-----------------------+
|ethertype                 |string  |RW, all  |'IPv4'   |CR  |L2 ethertype. Can be   |
|                          |        |         |         |    |'IPv4' or 'IPv6' only. |
+--------------------------+--------+---------+---------+----+-----------------------+
|protocol                  |string  |RW, all  |Any      |CR  |IP protocol name.      |
+--------------------------+--------+---------+---------+----+-----------------------+
|source_port_range_min     |integer |RW, all  |Any      |CR  |Minimum source         |
|                          |        |         |         |    |protocol port.         |
+--------------------------+--------+---------+---------+----+-----------------------+
|source_port_range_max     |integer |RW, all  |Any      |CR  |Maximum source         |
|                          |        |         |         |    |protocol port.         |
+--------------------------+--------+---------+---------+----+-----------------------+
|destination_port_range_min|integer |RW, all  |Any      |CR  |Minimum destination    |
|                          |        |         |         |    |protocol port.         |
+--------------------------+--------+---------+---------+----+-----------------------+
|destination_port_range_max|integer |RW, all  |Any      |CR  |Maximum destination    |
|                          |        |         |         |    |protocol port.         |
+--------------------------+--------+---------+---------+----+-----------------------+
|source_ip_prefix          |CIDR    |RW, all  |Any      |CR  |Source IPv4 or IPv6    |
|                          |        |         |         |    |prefix.                |
+--------------------------+--------+---------+---------+----+-----------------------+
|destination_ip_prefix     |CIDR    |RW, all  |Any      |CR  |Destination IPv4 or    |
|                          |        |         |         |    |IPv6 prefix.           |
+--------------------------+--------+---------+---------+----+-----------------------+
|logical_source_port       |uuid    |RW, all  |None     |CR  |Neutron source port.   |
+--------------------------+--------+---------+---------+----+-----------------------+
|logical_destination_port  |uuid    |RW, all  |None     |CR  |Neutron destination    |
|                          |        |         |         |    |port.                  |
+--------------------------+--------+---------+---------+----+-----------------------+
|l7_parameters             |dict    |RW, all  |Any      |CR  |Dict. of L7 parameters.|
+--------------------------+--------+---------+---------+----+-----------------------+

Json Port-pair create request example::

 {"port_pair": {"name": "SF1",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Firewall SF instance",
        "ingress": "dace4513-24fc-4fae-af4b-321c5e2eb3d1",
        "egress": "aef3478a-4a56-2a6e-cd3a-9dee4e2ec345",
    }
 }

 {"port_pair":  {"name": "SF2",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Loadbalancer SF instance",
        "ingress": "797f899e-73d4-11e5-b392-2c27d72acb4c",
        "egress": "797f899e-73d4-11e5-b392-2c27d72acb4c",
    }
 }

Json Port-pair create response example::

 {"port_pair": {"name": "SF1",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Firewall SF instance",
        "ingress": "dace4513-24fc-4fae-af4b-321c5e2eb3d1",
        "egress": "aef3478a-4a56-2a6e-cd3a-9dee4e2ec345",
        "id": "78dcd363-fc23-aeb6-f44b-56dc5e2fb3ae",
    }
  }

 {"port_pair":  {"name": "SF2",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Loadbalancer SF instance",
        "ingress": "797f899e-73d4-11e5-b392-2c27d72acb4c",
        "egress": "797f899e-73d4-11e5-b392-2c27d72acb4c",
        "id": "d11e9190-73d4-11e5-b392-2c27d72acb4c"
    }
 }

Json Port Pair Group create request example::

 {"port_pair_group": {"name": "Firewall_PortPairGroup",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Grouping Firewall SF instances",
        "port_pairs": [
            "78dcd363-fc23-aeb6-f44b-56dc5e2fb3ae"
        ],
        "port_pair_group_parameters": [
            "lb_fields: ip_src"
        ]
    }
  }

 {"port_pair_group": {"name": "Loadbalancer_PortPairGroup",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Grouping Loadbalancer SF instances",
        "port_pairs": [
            "d11e9190-73d4-11e5-b392-2c27d72acb4c"
        ]
        "port_pair_group_parameters": [
            "lb_fields: ip_src"
        ]
    }
 }

Json Port Pair Group create response example::

 {"port_pair_group": {"name": "Firewall_PortPairGroup",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Grouping Firewall SF instances",
        "port_pairs": [
            "78dcd363-fc23-aeb6-f44b-56dc5e2fb3ae
        ],
        "port_pair_group_parameters": [
            "lb_fields: ip_src"
        ]
        "id": "4512d643-24fc-4fae-af4b-321c5e2eb3d1",
    }
 }

 {"port_pair_group":  {"name": "Loadbalancer_PortPairGroup",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Grouping Loadbalancer SF instances",
        "port_pairs": [
            "d11e9190-73d4-11e5-b392-2c27d72acb4c"
        ],
        "port_pair_group_parameters": [
            "lb_fields: ip_src"
        ]
        "id": "4a634d49-76dc-4fae-af4b-321c5e23d651",
    }
 }

Json Flow Classifier create request example::

 {"flow_classifier": {"name": "FC1",
        "project_id": "1814726e2d22407b8ca76db5e567dcf1",
        "description": "Flow rule for classifying TCP traffic",
        "protocol": "TCP",
        "source_port_range_min": 22, "source_port_range_max": 4000,
        "destination_port_range_min": 80, "destination_port_range_max": 80,
        "source_ip_prefix": null, "destination_ip_prefix": "22.12.34.45"
    }
 }

 {"flow_classifier": {"name": "FC2",
        "project_id": "1814726e2d22407b8ca76db5e567dcf1",
        "description": "Flow rule for classifying UDP traffic",
        "protocol": "UDP",
        "source_port_range_min": 22, "source_port_range_max": 22,
        "destination_port_range_min": 80, "destination_port_range_max": 80,
        "source_ip_prefix": null, "destination_ip_prefix": "22.12.34.45"
    }
 }

Json Flow Classifier create response example::

 {"flow_classifier": {"name": "FC1",
        "project_id": "1814726e2d22407b8ca76db5e567dcf1",
        "description": "Flow rule for classifying TCP traffic",
        "protocol": "TCP",
        "source_port_range_min": 22, "source_port_range_max": 4000,
        "destination_port_range_min": 80, "destination_port_range_max": 80,
        "source_ip_prefix": null , "destination_ip_prefix": "22.12.34.45",
        "id": "4a334cd4-fe9c-4fae-af4b-321c5e2eb051"
    }
 }

 {"flow_classifier": {"name": "FC2",
        "project_id": "1814726e2d22407b8ca76db5e567dcf1",
        "description": "Flow rule for classifying UDP traffic",
        "protocol": "UDP",
        "source_port_range_min": 22, "source_port_range_max": 22,
        "destination_port_range_min": 80, "destination_port_range_max": 80,
        "source_ip_prefix": null , "destination_ip_prefix": "22.12.34.45",
        "id": "105a4b0a-73d6-11e5-b392-2c27d72acb4c"
    }
 }

Json Port Chain create request example::

 {"port_chain": {"name": "PC1",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Steering TCP and UDP traffic first to Firewall and then to Loadbalancer",
        "flow_classifiers": [
            "4a334cd4-fe9c-4fae-af4b-321c5e2eb051",
            "105a4b0a-73d6-11e5-b392-2c27d72acb4c"
        ],
        "port_pair_groups": [
            "4512d643-24fc-4fae-af4b-321c5e2eb3d1",
            "4a634d49-76dc-4fae-af4b-321c5e23d651"
        ],
        "chain_id": "10034"
    }
 }

Json Port Chain create response example::

 {"port_chain": {"name": "PC1",
        "project_id": "d382007aa9904763a801f68ecf065cf5",
        "description": "Steering TCP and UDP traffic first to Firewall and then to Loadbalancer",
        "flow_classifiers": [
            "4a334cd4-fe9c-4fae-af4b-321c5e2eb051",
            "105a4b0a-73d6-11e5-b392-2c27d72acb4c"
        ],
        "port_pair_groups": [
            "4512d643-24fc-4fae-af4b-321c5e2eb3d1",
            "4a634d49-76dc-4fae-af4b-321c5e23d651"
        ],
        "chain_id": "10034",
        "id": "1278dcd4-459f-62ed-754b-87fc5e4a6751"
    }
 }


Implementation
==============

Assignee(s)
~~~~~~~~~~~
Authors of the Specification and Primary contributors:
 * Cathy Zhang (cathy.h.zhang@huawei.com)
 * Louis Fourie (louis.fourie@huawei.com)

Other contributors:
 * Vikram Choudhary (vikram.choudhary@huawei.com)
 * Swaminathan Vasudevan (swaminathan.vasudevan@hp.com)
 * Yuji Azama (yuj-azama@rc.jp.nec.com)
 * Mohan Kumar (nmohankumar1011@gmail.com)
 * Ramanjaneya (ramanjieee@gmail.com)
 * Stephen Wong (stephen.kf.wong@gmail.com)
 * Nicolas Bouthors (Nicolas.BOUTHORS@qosmos.com)
 * Akihiro Motoki <amotoki@gmail.com>
 * Paul Carver <pcarver@att.com>

