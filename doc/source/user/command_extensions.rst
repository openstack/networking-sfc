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


=================
Command extension
=================

Networking-sfc uses python-neutronclient's existing command extension framework
for adding required command lines for realizing service function chaining
functionality. Refer to `Python-neutronclient command extension <https://docs.openstack.org/python-neutronclient/latest/contributor/client_command_extensions.html>`_ for further details.


List of New Neutron CLI Commands:
---------------------------------
Below listed command lines are introduced for realizing service function chaining.

.. code-block:: none

    flow-classifier-create   Create a flow-classifier.
    flow-classifier-delete   Delete a given flow-classifier.
    flow-classifier-list     List flow-classifiers that belong to a given tenant.
    flow-classifier-show     Show information of a given flow-classifier.
    flow-classifier-update   Update flow-classifier information.

    port-pair-create         Create a port-pair.
    port-pair-delete         Delete a given port-pair.
    port-pair-list           List port-pairs that belongs to a given tenant.
    port-pair-show           Show information of a given port-pair.
    port-pair-update         Update port-pair's information.

    port-pair-group-create   Create a port-pair-group.
    port-pair-group-delete   Delete a given port-pair-group.
    port-pair-group-list     List port-pair-groups that belongs to a given tenant.
    port-pair-group-show     Show information of a given port-pair-group.
    port-pair-group-update   Update port-pair-group's information.

    port-chain-create        Create a port-chain.
    port-chain-delete        Delete a given port-chain.
    port-chain-list          List port-chains that belong to a given tenant.
    port-chain-show          Show information of a given port-chain.
    port-chain-update        Update port-chain's information.

