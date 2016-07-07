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
from networking_sfc.services.flowclassifier.common import exceptions as fc_exc


LOG = log.getLogger(__name__)
cfg.CONF.import_opt('drivers',
                    'networking_sfc.services.flowclassifier.common.config',
                    group='flowclassifier')


class FlowClassifierDriverManager(stevedore.named.NamedExtensionManager):
    """Implementation of Flow Classifier drivers."""

    def __init__(self):
        # Registered flow classifier drivers, keyed by name.
        self.drivers = {}
        # Ordered list of flow classifier drivers, defining
        # the order in which the drivers are called.
        self.ordered_drivers = []
        LOG.info(_LI("Configured Flow Classifier drivers: %s"),
                 cfg.CONF.flowclassifier.drivers)
        super(FlowClassifierDriverManager, self).__init__(
            'networking_sfc.flowclassifier.drivers',
            cfg.CONF.flowclassifier.drivers,
            invoke_on_load=True,
            name_order=True)
        LOG.info(_LI("Loaded Flow Classifier drivers: %s"),
                 self.names())
        self._register_drivers()

    def _register_drivers(self):
        """Register all Flow Classifier drivers.

        This method should only be called once in the
        FlowClassifierDriverManager constructor.
        """
        for ext in self:
            self.drivers[ext.name] = ext
            self.ordered_drivers.append(ext)
        LOG.info(_LI("Registered Flow Classifier drivers: %s"),
                 [driver.name for driver in self.ordered_drivers])

    def initialize(self):
        # ServiceChain bulk operations requires each driver to support them
        self.native_bulk_support = True
        for driver in self.ordered_drivers:
            LOG.info(_LI("Initializing Flow Classifier driver '%s'"),
                     driver.name)
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def _call_drivers(self, method_name, context, raise_orig_exc=False):
        """Helper method for calling a method across all drivers.

        :param method_name: name of the method to call
        :param context: context parameter to pass to each method call
        :param raise_orig_exc: whether or not to raise the original
        driver exception, or use a general one
        """
        for driver in self.ordered_drivers:
            try:
                getattr(driver.obj, method_name)(context)
            except Exception as e:
                # This is an internal failure.
                LOG.exception(e)
                LOG.error(
                    _LE("Flow Classifier driver '%(name)s' "
                        "failed in %(method)s"),
                    {'name': driver.name, 'method': method_name}
                )
                if raise_orig_exc:
                    raise
                else:
                    raise fc_exc.FlowClassifierDriverError(
                        method=method_name
                    )

    def create_flow_classifier(self, context):
        self._call_drivers("create_flow_classifier", context)

    def update_flow_classifier(self, context):
        self._call_drivers("update_flow_classifier", context)

    def delete_flow_classifier(self, context):
        self._call_drivers("delete_flow_classifier", context)

    def create_flow_classifier_precommit(self, context):
        """Driver precommit before the db transaction committed."""
        self._call_drivers("create_flow_classifier_precommit", context,
                           raise_orig_exc=True)
