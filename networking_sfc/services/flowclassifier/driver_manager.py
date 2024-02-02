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
from stevedore.named import NamedExtensionManager

from networking_sfc.services.flowclassifier.common import exceptions as fc_exc


LOG = log.getLogger(__name__)
cfg.CONF.import_opt('drivers',
                    'networking_sfc.services.flowclassifier.common.config',
                    group='flowclassifier')


class FlowClassifierDriverManager(NamedExtensionManager):
    """Implementation of Flow Classifier drivers."""

    def __init__(self, namespace='networking_sfc.flowclassifier.drivers',
                 names=cfg.CONF.flowclassifier.drivers):
        # Registered flow classifier drivers, keyed by name.
        self.drivers = {}
        # Ordered list of flow classifier drivers, defining
        # the order in which the drivers are called.
        self.ordered_drivers = []
        LOG.info("Configured Flow Classifier drivers: %s", names)
        super().__init__(namespace, names, invoke_on_load=True,
                         name_order=True)
        LOG.info("Loaded Flow Classifier drivers: %s",
                 self.names())
        self._register_drivers()

    @classmethod
    def make_test_instance(cls, extensions, namespace='TESTING'):
        """Construct a test FlowClassifierDriverManager

        Test instances are passed a list of extensions to use rather than
        loading them from entry points.

        :param extensions: Pre-configured Extension instances
        :type extensions: list of :class:`~stevedore.extension.Extension`
        :param namespace: The namespace for the manager; used only for
            identification since the extensions are passed in.
        :type namespace: str
        :return: The manager instance, initialized for testing

        """

        o = super(FlowClassifierDriverManager, cls).make_test_instance(
            extensions, namespace=namespace)
        o.drivers = {}
        o.ordered_drivers = []
        o._register_drivers()
        return o

    def _register_drivers(self):
        """Register all Flow Classifier drivers.

        This method should only be called once in the
        FlowClassifierDriverManager constructor.
        """
        for ext in self:
            self.drivers[ext.name] = ext
            self.ordered_drivers.append(ext)
        LOG.info("Registered Flow Classifier drivers: %s",
                 [driver.name for driver in self.ordered_drivers])

    def initialize(self):
        # ServiceChain bulk operations requires each driver to support them
        self.native_bulk_support = True
        for driver in self.ordered_drivers:
            LOG.info("Initializing Flow Classifier driver '%s'",
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
                    "Flow Classifier driver '%(name)s' "
                    "failed in %(method)s",
                    {'name': driver.name, 'method': method_name}
                )
                if raise_orig_exc:
                    raise
                raise fc_exc.FlowClassifierDriverError(
                    method=method_name
                )

    def create_flow_classifier_precommit(self, context):
        """Driver precommit before the db transaction committed."""
        self._call_drivers("create_flow_classifier_precommit", context,
                           raise_orig_exc=True)

    def create_flow_classifier_postcommit(self, context):
        self._call_drivers("create_flow_classifier_postcommit", context)

    def update_flow_classifier_precommit(self, context):
        self._call_drivers("update_flow_classifier_precommit", context)

    def update_flow_classifier_postcommit(self, context):
        self._call_drivers("update_flow_classifier_postcommit", context)

    def delete_flow_classifier(self, context):
        self._call_drivers("delete_flow_classifier", context)

    def delete_flow_classifier_precommit(self, context):
        self._call_drivers("delete_flow_classifier_precommit", context)

    def delete_flow_classifier_postcommit(self, context):
        self._call_drivers("delete_flow_classifier_postcommit", context)
