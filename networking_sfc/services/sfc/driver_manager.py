# Copyright 2015 Futurewei. All rights reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from oslo_config import cfg
from oslo_log import log
import stevedore

from networking_sfc._i18n import _LE, _LI
from networking_sfc.services.sfc.common import exceptions as sfc_exc


LOG = log.getLogger(__name__)
cfg.CONF.import_opt('drivers',
                    'networking_sfc.services.sfc.common.config',
                    group='sfc')


class SfcDriverManager(stevedore.named.NamedExtensionManager):
    """Implementation of SFC drivers."""

    def __init__(self):
        # Registered sfc drivers, keyed by name.
        self.drivers = {}
        # Ordered list of sfc drivers, defining
        # the order in which the drivers are called.
        self.ordered_drivers = []
        LOG.info(_LI("Configured SFC drivers: %s"),
                 cfg.CONF.sfc.drivers)
        super(SfcDriverManager, self).__init__('networking_sfc.sfc.drivers',
                                               cfg.CONF.sfc.drivers,
                                               invoke_on_load=True,
                                               name_order=True)
        LOG.info(_LI("Loaded SFC drivers: %s"), self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all SFC drivers.

        This method should only be called once in the SfcDriverManager
        constructor.
        """
        for ext in self:
            self.drivers[ext.name] = ext
            self.ordered_drivers.append(ext)
        LOG.info(_LI("Registered SFC drivers: %s"),
                 [driver.name for driver in self.ordered_drivers])

    def initialize(self):
        # ServiceChain bulk operations requires each driver to support them
        self.native_bulk_support = True
        for driver in self.ordered_drivers:
            LOG.info(_LI("Initializing SFC driver '%s'"), driver.name)
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def _call_drivers(self, method_name, context):
        """Helper method for calling a method across all SFC drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        """
        for driver in self.ordered_drivers:
            try:
                getattr(driver.obj, method_name)(context)
            except Exception as e:
                # This is an internal failure.
                LOG.exception(e)
                LOG.error(
                    _LE("SFC driver '%(name)s' failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )
                raise sfc_exc.SfcDriverError(
                    method=method_name
                )

    def create_port_chain(self, context):
        self._call_drivers("create_port_chain", context)

    def update_port_chain(self, context):
        self._call_drivers("update_port_chain", context)

    def delete_port_chain(self, context):
        self._call_drivers("delete_port_chain", context)

    def create_port_pair(self, context):
        self._call_drivers("create_port_pair", context)

    def update_port_pair(self, context):
        self._call_drivers("update_port_pair", context)

    def delete_port_pair(self, context):
        self._call_drivers("delete_port_pair", context)

    def create_port_pair_group(self, context):
        self._call_drivers("create_port_pair_group", context)

    def update_port_pair_group(self, context):
        self._call_drivers("update_port_pair_group", context)

    def delete_port_pair_group(self, context):
        self._call_drivers("delete_port_pair_group", context)
