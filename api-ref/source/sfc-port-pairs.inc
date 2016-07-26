.. -*- rst -*-
.. needs:method_verification
.. needs:parameter_verification
.. needs:example_verification
.. needs:body_verification

=========================
 Port Pairs (port-pairs)
=========================

Lists, shows information for, creates, updates and deletes port pairs.

List Port Pairs
===============

.. rest_method:: GET /v1.0/sfc/port_pairs

Lists port pairs.

Normal response codes: 200

Error response codes: unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

  - tenant_id: tenant_id

Response
--------

.. rest_parameters:: parameters.yaml

  - id: port_pair_id
  - tenant_id: tenant_id
  - name: port_pair_name
  - description: description
  - port_pair_groups: port_pair_groups
  - flow_classifiers: flow_classifiers

Response Example
----------------

**Example List port pairs: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-port-pairs/port-pair-list-resp.json
   :language: javascript

Create Port Pair
================

.. rest_method:: POST /v1.0/sfc/port_pairs

Creates a port pair.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

  - tenant_id: tenant_id
  - name: port_pair_name
  - description: description
  - ingress: ingress_port_id
  - egress: egress_port_id
  - service_function_parameters: service_function_parameters

Request Example
---------------

**Example Create port pair: JSON request**

.. literalinclude:: ../../doc/api_samples/sfc-port-pairs/port-pair-create-req.json
   :language: javascript

Response
--------

.. rest_parameters:: parameters.yaml

  - id: port_pair_id
  - tenant_id: tenant_id
  - name: port_pair_name
  - description: description
  - ingress: ingress_port_id
  - egress: egress_port_id
  - service_function_parameters: service_function_parameters

Response Example
----------------

**Example Create port pair: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-port-pairs/port-pair-create-resp.json
   :language: javascript

Show Port Pair Details
======================

.. rest_method:: GET /v1.0/sfc/port_pairs/{port_pair_id}

Shows details for a port pair.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - id: port_pair_id
  - tenant_id: tenant_id

Response
--------

.. rest_parameters:: parameters.yaml

  - id: port_pair_id
  - tenant_id: tenant_id
  - name: port_pair_name
  - description: description
  - ingress: ingress_port_id
  - egress: egress_port_id
  - service_function_parameters: service_function_parameters

Response Example
----------------

**Example Show port pair: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-port-pairs/port-pair-get-resp.json
   :language: javascript

Update Port Pair
================

.. rest_method:: PUT /v1.0/sfc/port_pairs/{port_pair_id}

Updates a port pair.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - id: port_pair_id
  - tenant_id: tenant_id
  - name: port_pair_name
  - description: description

Request Example
---------------

**Example Update port pair: JSON request**

.. literalinclude:: ../../doc/api_samples/sfc-port-pairs/port-pair-update-req.json
   :language: javascript

Response
--------

.. rest_parameters:: parameters.yaml

  - id: port_pair_id
  - tenant_id: tenant_id
  - name: port_pair_name
  - description: description
  - ingress: ingress_port_id
  - egress: egress_port_id
  - service_function_parameters: service_function_parameters

Response Example
----------------

**Example Update port pair: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-port-pairs/port-pair-update-resp.json
   :language: javascript

Delete Port Pair
================

.. rest_method:: DELETE /v1.0/sfc/port-pairs/{port_pair_id}

Deletes a port pair.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - id: port_pair_id
  - tenant_id: tenant_id

Response
--------

There is no body content for the response of a successful Delete request.

