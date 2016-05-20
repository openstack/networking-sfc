.. -*- rst -*-
.. needs:method_verification
.. needs:parameter_verification
.. needs:example_verification
.. needs:body_verification

=====================================
 Flow Classifiers (flow-classifiers)
=====================================

Lists, shows information for, creates, updates and deletes flow classifiers.

List Flow Classifiers
=====================

.. rest_method:: GET /v1.0/sfc/flow_classifiers

Lists flow classifiers.

Normal response codes: 200

Error response codes: unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

  - tenant_id: tenant_id

Response
--------

.. rest_parameters:: parameters.yaml

  - id: flow_classifier_id
  - tenant_id: tenant_id
  - name: classifier_name
  - description: description

Response Example
----------------

**Example List flow classifiers: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-classifiers/flow-classifier-list-resp.json
   :language: javascript

Create Flow Classifier
======================

.. rest_method:: POST /v1.0/sfc/flow_classifiers

Creates a flow classifier.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403)

Request
-------

.. rest_parameters:: parameters.yaml

  - tenant_id: tenant_id
  - name: classifier_name
  - description: description
  - ethertype: ethertype
  - protocol: protocol
  - source_port_range_min: source_port_range_min
  - source_port_range_max: source_port_range_max
  - destination_port_range_min: destination_port_range_min
  - destination_port_range_max: destination_port_range_max
  - source_ip_prefix: source_ip_prefix
  - destination_ip_prefix: destination_ip_prefix
  - source_logical_port: source_logical_port
  - destination_logical_port: destination_logical_port
  - l7_parameters: l7_parameters

Request Example
---------------

**Example Create flow classifier: JSON request**

.. literalinclude:: ../../doc/api_samples/sfc-classifiers/flow-classifier-create-req.json
   :language: javascript

Response
--------

.. rest_parameters:: parameters.yaml

  - id: flow_classifier_id
  - tenant_id: tenant_id
  - name: classifier_name
  - description: description
  - ethertype: ethertype
  - protocol: protocol
  - source_port_range_min: source_port_range_min
  - source_port_range_max: source_port_range_max
  - destination_port_range_min: destination_port_range_min
  - destination_port_range_max: destination_port_range_max
  - source_ip_prefix: source_ip_prefix
  - destination_ip_prefix: destination_ip_prefix
  - source_logical_port: source_logical_port
  - destination_logical_port: destination_logical_port
  - l7_parameters: l7_parameters

Response Example
----------------

**Example Create flow classifier: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-classifiers/flow-classifier-create-resp.json
   :language: javascript

Show Flow Classifier Details
============================

.. rest_method:: GET /v1.0/sfc/flow_classifiers/{flow_classifier_id}

Shows details for a flow classifier.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - id: flow_classifier_id
  - tenant_id: tenant_id

Response
--------

.. rest_parameters:: parameters.yaml

  - id: flow_classifier_id
  - tenant_id: tenant_id
  - name: classifier_name
  - description: description
  - ethertype: ethertype
  - protocol: protocol
  - source_port_range_min: source_port_range_min
  - source_port_range_max: source_port_range_max
  - destination_port_range_min: destination_port_range_min
  - destination_port_range_max: destination_port_range_max
  - source_ip_prefix: source_ip_prefix
  - destination_ip_prefix: destination_ip_prefix
  - source_logical_port: source_logical_port
  - destination_logical_port: destination_logical_port
  - l7_parameters: l7_parameters

Response Example
----------------

**Example Show flow classifier: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-classifiers/flow-classifier-get-resp.json
   :language: javascript

Update Flow Classifier
======================

.. rest_method:: PUT /v1.0/sfc/flow_classifiers/{flow_classifier_id}

Updates a flow classifier.

Normal response codes: 200

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - id: flow_classifier_id
  - tenant_id: tenant_id
  - name: classifier_name
  - description: description

Request Example
---------------

**Example Update flow classifier: JSON request**

.. literalinclude:: ../../doc/api_samples/sfc-classifiers/flow-classifier-update-req.json
   :language: javascript

Response
--------

.. rest_parameters:: parameters.yaml

  - id: flow_classifier_id
  - tenant_id: tenant_id
  - name: classifier_name
  - description: description
  - ethertype: ethertype
  - protocol: protocol
  - source_port_range_min: source_port_range_min
  - source_port_range_max: source_port_range_max
  - destination_port_range_min: destination_port_range_min
  - destination_port_range_max: destination_port_range_max
  - source_ip_prefix: source_ip_prefix
  - destination_ip_prefix: destination_ip_prefix
  - source_logical_port: source_logical_port
  - destination_logical_port: destination_logical_port
  - l7_parameters: l7_parameters

Response Example
----------------

**Example Update flow classifier: JSON response**

.. literalinclude:: ../../doc/api_samples/sfc-classifiers/flow-classifier-update-resp.json
   :language: javascript

Delete Flow Classifier
======================

.. rest_method:: DELETE /v1.0/sfc/flow-classifiers/{flow_classifier_id}

Deletes a flow classifier.

Normal response codes: 202

Error response codes: badRequest(400), unauthorized(401), forbidden(403), itemNotFound(404)

Request
-------

.. rest_parameters:: parameters.yaml

  - id: flow_classifier_id
  - tenant_id: tenant_id

Response
--------

There is no body content for the response of a successful Delete request.

