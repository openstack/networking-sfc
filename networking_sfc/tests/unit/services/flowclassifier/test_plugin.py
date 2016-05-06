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

import copy
import mock

from networking_sfc.services.flowclassifier.common import context as fc_ctx
from networking_sfc.services.flowclassifier.common import exceptions as fc_exc
from networking_sfc.tests.unit.db import test_flowclassifier_db

FLOWCLASSIFIER_PLUGIN_KLASS = (
    "networking_sfc.services.flowclassifier."
    "plugin.FlowClassifierPlugin"
)


class FlowClassifierPluginTestCase(
    test_flowclassifier_db.FlowClassifierDbPluginTestCase
):
    def setUp(
        self, core_plugin=None, flowclassifier_plugin=None, ext_mgr=None
    ):
        if not flowclassifier_plugin:
            flowclassifier_plugin = FLOWCLASSIFIER_PLUGIN_KLASS
        self.driver_manager_p = mock.patch(
            'networking_sfc.services.flowclassifier.driver_manager.'
            'FlowClassifierDriverManager'
        )
        self.fake_driver_manager_class = self.driver_manager_p.start()
        self.fake_driver_manager = mock.Mock()
        self.fake_driver_manager_class.return_value = self.fake_driver_manager
        self.plugin_context = None
        super(FlowClassifierPluginTestCase, self).setUp(
            core_plugin=core_plugin,
            flowclassifier_plugin=flowclassifier_plugin,
            ext_mgr=ext_mgr
        )

    def _record_context(self, plugin_context):
        self.plugin_context = plugin_context

    def test_create_flow_classifier_driver_manager_called(self):
        self.fake_driver_manager.create_flow_classifier = mock.Mock(
            side_effect=self._record_context)
        self.fake_driver_manager.create_flow_classifier_precommit = mock.Mock(
            side_effect=self._record_context)
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(flow_classifier={
                'logical_source_port': port['port']['id']
            }) as fc:
                driver_manager = self.fake_driver_manager
                create_flow_classifier_precommit = (
                    driver_manager.create_flow_classifier_precommit)
                create_flow_classifier_precommit.assert_called_once_with(
                    mock.ANY
                )
                driver_manager.create_flow_classifier.assert_called_once_with(
                    mock.ANY
                )
                self.assertIsInstance(
                    self.plugin_context, fc_ctx.FlowClassifierContext
                )
                self.assertIn('flow_classifier', fc)
                self.assertEqual(
                    self.plugin_context.current, fc['flow_classifier'])

    def test_create_flow_classifier_driver_manager_exception(self):
        self.fake_driver_manager.create_flow_classifier = mock.Mock(
            side_effect=fc_exc.FlowClassifierDriverError(
                method='create_flow_classifier'
            )
        )
        with self.port(
            name='test1'
        ) as port:
            self._create_flow_classifier(
                self.fmt, {'logical_source_port': port['port']['id']},
                expected_res_status=500)
            driver_manager = self.fake_driver_manager
            create_flow_classifier_precommit = (
                driver_manager.create_flow_classifier_precommit)
            create_flow_classifier_precommit.assert_called_once_with(
                mock.ANY
            )
            driver_manager.create_flow_classifier.assert_called_once_with(
                mock.ANY
            )
            driver_manager.delete_flow_classifier.assert_called_once_with(
                mock.ANY
            )
            self._test_list_resources('flow_classifier', [])

    def test_create_flow_classifier_precommit_driver_manager_exception(self):
        self.fake_driver_manager.create_flow_classifier_precommit = mock.Mock(
            side_effect=fc_exc.FlowClassifierDriverError(
                method='create_flow_classifier_precommit'
            )
        )
        with self.port(
            name='test1'
        ) as port:
            self._create_flow_classifier(
                self.fmt, {'logical_source_port': port['port']['id']},
                expected_res_status=500)
            driver_manager = self.fake_driver_manager
            create_flow_classifier_precommit = (
                driver_manager.create_flow_classifier_precommit)
            create_flow_classifier_precommit.assert_called_once_with(
                mock.ANY
            )
            driver_manager.create_flow_classifier.assert_not_called()
            driver_manager.delete_flow_classifier.assert_not_called()
            self._test_list_resources('flow_classifier', [])

    def test_update_flow_classifier_driver_manager_called(self):
        self.fake_driver_manager.update_flow_classifier = mock.Mock(
            side_effect=self._record_context)
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(flow_classifier={
                'name': 'test1',
                'logical_source_port': port['port']['id']
            }) as fc:
                req = self.new_update_request(
                    'flow_classifiers', {'flow_classifier': {'name': 'test2'}},
                    fc['flow_classifier']['id']
                )
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                driver_manager = self.fake_driver_manager
                driver_manager.update_flow_classifier.assert_called_once_with(
                    mock.ANY
                )
                self.assertIsInstance(
                    self.plugin_context, fc_ctx.FlowClassifierContext
                )
                self.assertIn('flow_classifier', fc)
                self.assertIn('flow_classifier', res)
                self.assertEqual(
                    self.plugin_context.current, res['flow_classifier'])
                self.assertEqual(
                    self.plugin_context.original, fc['flow_classifier'])

    def test_update_flow_classifier_driver_manager_exception(self):
        self.fake_driver_manager.update_flow_classifier = mock.Mock(
            side_effect=fc_exc.FlowClassifierDriverError(
                method='update_flow_classifier'
            )
        )
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(flow_classifier={
                'name': 'test1',
                'logical_source_port': port['port']['id']
            }) as fc:
                self.assertIn('flow_classifier', fc)
                original_flow_classifier = fc['flow_classifier']
                req = self.new_update_request(
                    'flow_classifiers', {'flow_classifier': {'name': 'test2'}},
                    fc['flow_classifier']['id']
                )
                updated_flow_classifier = copy.copy(original_flow_classifier)
                updated_flow_classifier['name'] = 'test2'
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 500)
                driver_manager = self.fake_driver_manager
                driver_manager.update_flow_classifier.assert_called_once_with(
                    mock.ANY
                )
                res = self._list('flow_classifiers')
                self.assertIn('flow_classifiers', res)
                self.assertItemsEqual(
                    res['flow_classifiers'], [updated_flow_classifier])

    def test_delete_flow_classifer_driver_manager_called(self):
        self.fake_driver_manager.delete_flow_classifier = mock.Mock(
            side_effect=self._record_context)
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(
                flow_classifier={'logical_source_port': port['port']['id']},
                do_delete=False
            ) as fc:
                req = self.new_delete_request(
                    'flow_classifiers', fc['flow_classifier']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 204)
                driver_manager = self.fake_driver_manager
                driver_manager.delete_flow_classifier.assert_called_once_with(
                    mock.ANY
                )
                self.assertIsInstance(
                    self.plugin_context, fc_ctx.FlowClassifierContext
                )
                self.assertIn('flow_classifier', fc)
                self.assertEqual(
                    self.plugin_context.current, fc['flow_classifier'])

    def test_delete_flow_classifier_driver_manager_exception(self):
        self.fake_driver_manager.delete_flow_classifier = mock.Mock(
            side_effect=fc_exc.FlowClassifierDriverError(
                method='delete_flow_classifier'
            )
        )
        with self.port(
            name='test1'
        ) as port:
            with self.flow_classifier(flow_classifier={
                'name': 'test1',
                'logical_source_port': port['port']['id']
            }, do_delete=False) as fc:
                req = self.new_delete_request(
                    'flow_classifiers', fc['flow_classifier']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(res.status_int, 500)
                driver_manager = self.fake_driver_manager
                driver_manager.delete_flow_classifier.assert_called_once_with(
                    mock.ANY
                )
                self._test_list_resources('flow_classifier', [fc])
