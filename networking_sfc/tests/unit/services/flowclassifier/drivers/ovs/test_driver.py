# Copyright 2016 Huawei.  All rights reserved.
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

from neutron_lib.api.definitions import portbindings
from neutron_lib import context

from oslo_utils import importutils

from neutron.api import extensions as api_ext
from neutron.common import config

from networking_sfc.db import flowclassifier_db as fdb
from networking_sfc.extensions import flowclassifier
from networking_sfc.services.flowclassifier.common import context as fc_ctx
from networking_sfc.services.flowclassifier.common import exceptions as fc_exc
from networking_sfc.services.flowclassifier.drivers.ovs import driver
from networking_sfc.tests import base
from networking_sfc.tests.unit.db import test_flowclassifier_db


class OVSFlowClassifierDriverTestCase(
    test_flowclassifier_db.FlowClassifierDbPluginTestCaseBase,
    base.NeutronDbPluginV2TestCase
):

    resource_prefix_map = dict([
        (k, flowclassifier.FLOW_CLASSIFIER_PREFIX)
        for k in flowclassifier.RESOURCE_ATTRIBUTE_MAP.keys()
    ])

    def setUp(self):
        flowclassifier_plugin = (
            test_flowclassifier_db.DB_FLOWCLASSIFIER_PLUGIN_CLASS)

        service_plugins = {
            flowclassifier.FLOW_CLASSIFIER_EXT: flowclassifier_plugin
        }
        fdb.FlowClassifierDbPlugin.supported_extension_aliases = [
            flowclassifier.FLOW_CLASSIFIER_EXT]
        fdb.FlowClassifierDbPlugin.path_prefix = (
            flowclassifier.FLOW_CLASSIFIER_PREFIX
        )
        super(OVSFlowClassifierDriverTestCase, self).setUp(
            ext_mgr=None,
            plugin=None,
            service_plugins=service_plugins
        )
        self.flowclassifier_plugin = importutils.import_object(
            flowclassifier_plugin)
        ext_mgr = api_ext.PluginAwareExtensionManager(
            test_flowclassifier_db.extensions_path,
            {
                flowclassifier.FLOW_CLASSIFIER_EXT: self.flowclassifier_plugin
            }
        )
        app = config.load_paste_app('extensions_test_app')
        self.ext_api = api_ext.ExtensionMiddleware(app, ext_mgr=ext_mgr)
        self.ctx = context.get_admin_context()
        self.driver = driver.OVSFlowClassifierDriver()
        self.driver.initialize()

    def tearDown(self):
        super(OVSFlowClassifierDriverTestCase, self).tearDown()

    def test_create_flow_classifier_precommit(self):
        with self.port(
            name='port1',
            device_owner='compute',
            device_id='test',
            arg_list=(
                portbindings.HOST_ID,
            ),
            **{portbindings.HOST_ID: 'test'}
        ) as src_port:
            with self.flow_classifier(flow_classifier={
                'name': 'test1',
                'logical_source_port': src_port['port']['id']
            }) as fc:
                fc_context = fc_ctx.FlowClassifierContext(
                    self.flowclassifier_plugin, self.ctx,
                    fc['flow_classifier']
                )
                self.driver.create_flow_classifier_precommit(fc_context)

    def test_create_flow_classifier_precommit_no_logical_source_port(self):
        with self.flow_classifier(flow_classifier={
            'name': 'test1',
            'logical_source_port': None
        }) as fc:
            fc_context = fc_ctx.FlowClassifierContext(
                self.flowclassifier_plugin, self.ctx,
                fc['flow_classifier']
            )
            self.assertRaises(
                fc_exc.FlowClassifierBadRequest,
                self.driver.create_flow_classifier_precommit,
                fc_context)
