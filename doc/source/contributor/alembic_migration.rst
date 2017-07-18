..
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


Alembic-migration
=================

Using alembic-migration, required data modeling for networking-sfc is defined and
applied to the database. Refer to `Neutron alembic migration process <https://docs.openstack.org/neutron/latest/contributor/alembic_migrations.html>`_ for further details.

The important operations are listed below.

Checking migration
------------------

.. code-block:: console

    neutron-db-manage --subproject networking-sfc check_migration
      Running branches for networking-sfc ...
    start_networking_sfc (branchpoint)
                         -> 48072cb59133 (contract) (head)
                         -> 24fc7241aa5 (expand)

      OK

Checking branch information
---------------------------

.. code-block:: console

    neutron-db-manage --subproject networking-sfc branches
      Running branches for networking-sfc ...
    start_networking_sfc (branchpoint)
                         -> 48072cb59133 (contract) (head)
                         -> 24fc7241aa5 (expand)

      OK

Checking migration history
--------------------------

.. code-block:: console

    neutron-db-manage --subproject networking-sfc history
      Running history for networking-sfc ...
    9768e6a66c9 -> 5a475fc853e6 (expand) (head), Defining OVS data-model
    24fc7241aa5 -> 9768e6a66c9 (expand), Defining flow-classifier data-model
    start_networking_sfc -> 24fc7241aa5 (expand), Defining Port Chain data-model.
    start_networking_sfc -> 48072cb59133 (contract) (head), Initial Liberty no-op script.
    <base> -> start_networking_sfc (branchpoint), start networking-sfc chain

Applying changes
----------------

.. code-block:: console

    neutron-db-manage --subproject networking-sfc upgrade head
    INFO  [alembic.runtime.migration] Context impl MySQLImpl.
    INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
      Running upgrade for networking-sfc ...
    INFO  [alembic.runtime.migration] Context impl MySQLImpl.
    INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
    INFO  [alembic.runtime.migration] Running upgrade  -> start_networking_sfc, start networking-sfc chain
    INFO  [alembic.runtime.migration] Running upgrade start_networking_sfc -> 48072cb59133, Initial Liberty no-op script.
    INFO  [alembic.runtime.migration] Running upgrade start_networking_sfc -> 24fc7241aa5, Defining Port Chain data-model.
    INFO  [alembic.runtime.migration] Running upgrade 24fc7241aa5 -> 9768e6a66c9, Defining flow-classifier data-model
    INFO  [alembic.runtime.migration] Running upgrade 9768e6a66c9 -> 5a475fc853e6, Defining OVS data-model
      OK

Checking current version
------------------------

.. code-block:: console

    neutron-db-manage --subproject networking-sfc current
      Running current for networking-sfc ...
    INFO  [alembic.runtime.migration] Context impl MySQLImpl.
    INFO  [alembic.runtime.migration] Will assume non-transactional DDL.
    48072cb59133 (head)
    5a475fc853e6 (head)
      OK

