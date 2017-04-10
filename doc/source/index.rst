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


Welcome to the Service Function Chaining Documentation!
=======================================================
.. include:: ../../README.rst


===============
Developer Guide
===============

In the Developer Guide, you will find information on Networking-SFC lower level
programming APIs. There are sections that cover the core pieces of networking-sfc,
including its api, command-lines, database, system-design, alembic-migration etc.
There are also subsections that describe specific plugins inside networking-sfc.
Finally, the developer guide includes information about testing infrastructure.

Programming HowTos and Tutorials
--------------------------------
.. toctree::
    :maxdepth: 2

    installation
    usage
    contribution

Networking-SFC Internals
------------------------
.. toctree::
   :maxdepth: 2

   api
   system_design_and_workflow
   ovs_driver_and_agent_workflow
   command_extensions
   alembic_migration
   sfc_ovn_driver
   ovs_symmetric_port_chain
   sfc_port_chain_tap

Indices and tables
------------------

* :ref:`genindex`
* :ref:`search`

