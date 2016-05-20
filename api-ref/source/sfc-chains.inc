.. -*- rst -*-
.. needs:method_verification
.. needs:parameter_verification
.. needs:example_verification
.. needs:body_verification

===========================
 Port Chains (port-chains)
===========================

Lists, shows information for, creates, updates and deletes port chains.

List Port Chains
================

.. rest_method:: GET /v1.0/sfc/port_chains

Lists port chains.

Normal response codes: 200

Error response codes: unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

  - tenant_id: tenant_id

Response
--------

.. rest_parameters:: parameters.yaml

  - id: chain_id
  - tenant_id: tenant_id
  - name: port_chain_name
  - description: description
  - port_pair_groups: port_pair_groups
  - flow_classifiers: flow_classifiers
  - chain_parameters: chain_parameters

Response Example
----------------

**Example List port chains: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-chains/port-chain-list-resp.json
   :language: javascript

Create Port Chain
=================

.. rest_method:: POST /v1.0/sfc/port_chains

Creates a port chain.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

  - tenant_id: tenant_id
  - name: port_chain_name
  - description: description
  - port_pair_groups: port_pair_groups
  - flow_classifiers: flow_classifiers
  - chain_parameters: chain_parameters

Request Example
---------------

**Example Create port chain: JSON request**

.. literalinclude:: ../../doc/api_samples/sfc-chains/port-chain-create-req.json
   :language: javascript

Response
--------

.. rest_parameters:: parameters.yaml

  - id: chain_id
  - tenant_id: tenant_id
  - name: port_chain_name
  - description: description
  - port_pair_groups: port_pair_groups
  - flow_classifiers: flow_classifiers
  - chain_parameters: chain_parameters

Response Example
----------------

**Example Create port chain: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-chains/port-chain-create-resp.json
   :language: javascript

Show Port Chain Details
=======================

.. rest_method:: GET /v1.0/sfc/port_chains/{port_chain_id}

Shows details for a port chain.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - tenant_id: tenant_id
  - id: chain_id

Response
--------

.. rest_parameters:: parameters.yaml

  - tenant_id: tenant_id
  - id: chain_id
  - name: port_chain_name
  - description: description
  - port_pair_groups: port_pair_groups
  - flow_classifiers: flow_classifiers
  - chain_parameters: chain_parameters

Response Example
----------------

**Example Show port chain: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-chains/port-chain-get-resp.json
   :language: javascript

Update Port Chain
=================

.. rest_method:: PUT /v1.0/sfc/port_chains/{port_chain_id}

Updates a port chain.  The current list of port pair groups is replaced
by the port pair group list in the Update request. The current list of
flow classifiers is replaced by the flow classifier list in the Update
request.


Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - id: chain_id
  - tenant_id: tenant_id
  - name: port_chain_name
  - description: description
  - port_pair_groups: port_pair_groups
  - flow_classifiers: flow_classifiers

Request Example
---------------

**Example Update port chain: JSON request**

.. literalinclude:: ../../doc/api_samples/sfc-chains/port-chain-update-req.json
   :language: javascript

Response
--------

.. rest_parameters:: parameters.yaml

  - id: chain_id
  - tenant_id: tenant_id
  - name: port_chain_name
  - description: description
  - port_pair_groups: port_pair_groups
  - flow_classifiers: flow_classifiers

Response Example
----------------

**Example Update port chain: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-chains/port-chain-update-resp.json
   :language: javascript

Delete Port Chain
=================

.. rest_method:: DELETE /v1.0/sfc/port-chains/{port_chain_id}

Deletes a port chain.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - id: chain_id
  - tenant_id: tenant_id

Response
--------

There is no body content for the response of a successful Delete request.

