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


Configuration
=============

Controller nodes
----------------

After installing the package, enable the service plugins in neutron-server by
adding them in ``neutron.conf`` (typically found in ``/etc/neutron/``)::

    [DEFAULT]
    service_plugins = flow_classifier,sfc

In the same configuration file, specify the driver to use in the plugins. Here
we use the OVS driver::

    [sfc]
    drivers = ovs

    [flowclassifier]
    drivers = ovs

After that, restart the neutron-server. In devstack, run::

    systemctl restart devstack@q-svc

In a similar way with systemd setups, you can run::

    systemctl restart neutron-server

Compute nodes
-------------

After installing the package, enable the networking-sfc extension in the Open
vSwitch agent. The configuration file name can change, the default one is
``/etc/neutron/plugins/ml2/ml2_conf.ini``. Add the sfc extension::

    [agent]
    extensions = sfc

And restart the neutron-openvswitch-agent process. In devstack, run::

    systemctl restart devstack@q-agt

And with systemd setups you can run::

    systemctl restart neutron-openvswitch-agent

Database setup
--------------

The database is the standard Neutron database with a few more tables, which
can be configured with ``neutron-db-manage`` command-line tool:

.. code-block:: console

    neutron-db-manage --subproject networking-sfc upgrade head
