# Copyright 2017 Futurewei. All rights reserved.
# Copyright 2017 Intel Corporation.
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

from networking_sfc.services.sfc.common import exceptions as sfc_exc


LOG = log.getLogger(__name__)
cfg.CONF.import_opt('drivers',
                    'networking_sfc.services.sfc.common.config',
                    group='sfc')


class SfcDriverManager(NamedExtensionManager):
    """Implementation of SFC drivers."""

    def __init__(self, namespace='networking_sfc.sfc.drivers',
                 names=cfg.CONF.sfc.drivers):
        # Registered sfc drivers, keyed by name.
        self.drivers = {}
        # Ordered list of sfc drivers, defining
        # the order in which the drivers are called.
        self.ordered_drivers = []
        LOG.info("Configured SFC drivers: %s", names)
        super().__init__(namespace, names, invoke_on_load=True,
                         name_order=True)
        LOG.info("Loaded SFC drivers: %s", self.names())
        self._register_drivers()

    @classmethod
    def make_test_instance(cls, extensions, namespace='TESTING'):
        """Construct a test SfcDriverManager

        Test instances are passed a list of extensions to use rather than
        loading them from entry points.

        :param extensions: Pre-configured Extension instances
        :type extensions: list of :class:`~stevedore.extension.Extension`
        :param namespace: The namespace for the manager; used only for
            identification since the extensions are passed in.
        :type namespace: str
        :return: The manager instance, initialized for testing

        """

        o = super(SfcDriverManager, cls).make_test_instance(
            extensions, namespace=namespace)
        o.drivers = {}
        o.ordered_drivers = []
        o._register_drivers()
        return o

    def _register_drivers(self):
        """Register all SFC drivers.

        This method should only be called once in the SfcDriverManager
        constructor.
        """
        for ext in self:
            self.drivers[ext.name] = ext
            self.ordered_drivers.append(ext)
        LOG.info("Registered SFC drivers: %s",
                 [driver.name for driver in self.ordered_drivers])

    def initialize(self):
        # ServiceChain bulk operations requires each driver to support them
        self.native_bulk_support = True
        for driver in self.ordered_drivers:
            LOG.info("Initializing SFC driver '%s'", driver.name)
            driver.obj.initialize()
            self.native_bulk_support &= getattr(driver.obj,
                                                'native_bulk_support', True)

    def _call_drivers(self, method_name, context, raise_orig_exc=False):
        """Helper method for calling a method across all SFC drivers.

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
                    "SFC driver '%(name)s' failed in %(method)s",
                    {'name': driver.name, 'method': method_name}
                )
                if raise_orig_exc:
                    raise
                raise sfc_exc.SfcDriverError(
                    method=method_name
                )

    def create_port_chain_precommit(self, context):
        self._call_drivers("create_port_chain_precommit", context,
                           raise_orig_exc=True)

    def create_port_chain_postcommit(self, context):
        self._call_drivers("create_port_chain_postcommit", context)

    def update_port_chain_precommit(self, context):
        self._call_drivers("update_port_chain_precommit", context)

    def update_port_chain_postcommit(self, context):
        self._call_drivers("update_port_chain_postcommit", context)

    def delete_port_chain(self, context):
        self._call_drivers("delete_port_chain", context)

    def delete_port_chain_precommit(self, context):
        self._call_drivers("delete_port_chain_precommit", context)

    def delete_port_chain_postcommit(self, context):
        self._call_drivers("delete_port_chain_postcommit", context)

    def create_port_pair_precommit(self, context):
        self._call_drivers("create_port_pair_precommit", context)

    def create_port_pair_postcommit(self, context):
        self._call_drivers("create_port_pair_postcommit", context)

    def update_port_pair_precommit(self, context):
        self._call_drivers("update_port_pair_precommit", context)

    def update_port_pair_postcommit(self, context):
        self._call_drivers("update_port_pair_postcommit", context)

    def delete_port_pair(self, context):
        self._call_drivers("delete_port_pair", context)

    def delete_port_pair_precommit(self, context):
        self._call_drivers("delete_port_pair_precommit", context)

    def delete_port_pair_postcommit(self, context):
        self._call_drivers("delete_port_pair_postcommit", context)

    def create_port_pair_group_precommit(self, context):
        self._call_drivers("create_port_pair_group_precommit", context)

    def create_port_pair_group_postcommit(self, context):
        self._call_drivers("create_port_pair_group_postcommit", context)

    def update_port_pair_group_precommit(self, context):
        self._call_drivers("update_port_pair_group_precommit", context)

    def update_port_pair_group_postcommit(self, context):
        self._call_drivers("update_port_pair_group_postcommit", context)

    def delete_port_pair_group(self, context):
        self._call_drivers("delete_port_pair_group", context)

    def delete_port_pair_group_precommit(self, context):
        self._call_drivers("delete_port_pair_group_precommit", context)

    def delete_port_pair_group_postcommit(self, context):
        self._call_drivers("delete_port_pair_group_postcommit", context)

    def create_service_graph_precommit(self, context):
        self._call_drivers("create_service_graph_precommit", context)

    def create_service_graph_postcommit(self, context):
        self._call_drivers("create_service_graph_postcommit", context)

    def update_service_graph_precommit(self, context):
        self._call_drivers("update_service_graph_precommit", context)

    def update_service_graph_postcommit(self, context):
        self._call_drivers("update_service_graph_postcommit", context)

    def delete_service_graph_precommit(self, context):
        self._call_drivers("delete_service_graph_precommit", context)

    def delete_service_graph_postcommit(self, context):
        self._call_drivers("delete_service_graph_postcommit", context)
