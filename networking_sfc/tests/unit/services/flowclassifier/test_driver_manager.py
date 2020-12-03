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

from unittest.mock import Mock

from stevedore.extension import Extension

from neutron.tests import base

from networking_sfc.services.flowclassifier.common import exceptions as fc_exc
from networking_sfc.services.flowclassifier.driver_manager \
    import FlowClassifierDriverManager


class DriverManagerTestCase(base.BaseTestCase):
    def setUp(self):
        super(DriverManagerTestCase, self).setUp()

    def test_initialize_called(self):
        driver1 = Extension('mock_driver1', Mock(), None,
                            Mock(native_bulk_support=True))
        driver2 = Extension('mock_driver2', Mock(), None,
                            Mock(native_bulk_support=True))
        manager = FlowClassifierDriverManager.make_test_instance([driver1,
                                                                  driver2])
        manager.initialize()
        driver1.obj.initialize.assert_called_once_with()
        driver2.obj.initialize.assert_called_once_with()

    def _test_method_called(self, method_name):
        driver1 = Extension('mock_driver1', Mock(), None,
                            Mock(native_bulk_support=True))
        driver2 = Extension('mock_driver2', Mock(), None,
                            Mock(native_bulk_support=True))
        manager = FlowClassifierDriverManager.make_test_instance([driver1,
                                                                  driver2])
        mocked_context = Mock()
        getattr(manager, method_name)(mocked_context)
        getattr(driver1.obj, method_name).assert_called_once_with(
            mocked_context)
        getattr(driver2.obj, method_name).assert_called_once_with(
            mocked_context)

    def _test_method_exception(self, method_name,
                               expected_exc=fc_exc.FlowClassifierDriverError):
        driver = Extension('mock_driver', Mock(), None,
                           Mock(native_bulk_support=True))
        mock_method = Mock(side_effect=fc_exc.FlowClassifierException)
        setattr(driver.obj, method_name, mock_method)
        manager = FlowClassifierDriverManager.make_test_instance([driver])
        mocked_context = Mock()
        self.assertRaises(expected_exc,
                          getattr(manager, method_name),
                          mocked_context)

    def test_create_flow_classifier_precommit_called(self):
        self._test_method_called("create_flow_classifier_precommit")

    def test_create_flow_classifier_precommit_exception(self):
        self._test_method_exception("create_flow_classifier_precommit",
                                    fc_exc.FlowClassifierException)

    def test_create_flow_classifier_postcommit_called(self):
        self._test_method_called("create_flow_classifier_postcommit")

    def test_create_flow_classifier_postcommit_exception(self):
        self._test_method_exception("create_flow_classifier_postcommit")

    def test_update_flow_classifier_precommit_called(self):
        self._test_method_called("update_flow_classifier_precommit")

    def test_update_flow_classifier_precommit_exception(self):
        self._test_method_exception("update_flow_classifier_precommit")

    def test_update_flow_classifier_postcommit_called(self):
        self._test_method_called("update_flow_classifier_postcommit")

    def test_update_flow_classifier_postcommit_exception(self):
        self._test_method_exception("update_flow_classifier_postcommit")

    def test_delete_flow_classifier_called(self):
        self._test_method_called("delete_flow_classifier")

    def test_delete_flow_classifier_exception(self):
        self._test_method_exception("delete_flow_classifier")

    def test_delete_flow_classifier_precommit_called(self):
        self._test_method_called("delete_flow_classifier_precommit")

    def test_delete_flow_classifier_precommit_exception(self):
        self._test_method_exception("delete_flow_classifier_precommit")

    def test_delete_flow_classifier_postcommit_called(self):
        self._test_method_called("delete_flow_classifier_postcommit")

    def test_delete_flow_classifier_postcommit_exception(self):
        self._test_method_exception("delete_flow_classifier_postcommit")
