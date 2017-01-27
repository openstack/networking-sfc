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

import contextlib
import mock
import pkg_resources
import stevedore

from oslo_config import cfg

from neutron.tests import base

from networking_sfc.services.flowclassifier.common import config as fc_config
from networking_sfc.services.flowclassifier.common import exceptions as fc_exc
from networking_sfc.services.flowclassifier import driver_manager as fc_driver


class DriverManagerTestCase(base.BaseTestCase):
    def setUp(self):
        super(DriverManagerTestCase, self).setUp()

    @contextlib.contextmanager
    def driver_manager_context(self, drivers):
        cfg.CONF.register_opts(fc_config.FLOWCLASSIFIER_DRIVER_OPTS,
                               'flowclassifier')
        backup_driver_names = cfg.CONF.flowclassifier.drivers
        driver_names = [
            driver_name for driver_name in drivers
        ]
        cfg.CONF.set_override('drivers', driver_names, 'flowclassifier')
        iter_entry_points = pkg_resources.iter_entry_points
        find_entry_points = stevedore.ExtensionManager._find_entry_points
        pkg_resources.iter_entry_points = mock.Mock()
        stevedore.ExtensionManager._find_entry_points = mock.Mock()
        driver_entry_points = []
        for driver_name in driver_names:
            driver_class = mock.Mock()
            ep = mock.Mock()
            ep.name = driver_name
            ep.resolve.return_value = driver_class
            driver_class.return_value = drivers[driver_name]
            drivers[driver_name].native_bulk_support = True
            driver_entry_points.append(ep)
        pkg_resources.iter_entry_points.return_value = driver_entry_points
        stevedore.ExtensionManager._find_entry_points.return_value = (
            driver_entry_points
        )
        yield fc_driver.FlowClassifierDriverManager()
        cfg.CONF.set_override('drivers', backup_driver_names, 'flowclassifier')
        pkg_resources.iter_entry_points = iter_entry_points
        stevedore.ExtensionManager._find_entry_points = find_entry_points

    def test_initialize_called(self):
        mock_driver1 = mock.Mock()
        mock_driver2 = mock.Mock()
        with self.driver_manager_context({
            'dummy1': mock_driver1,
            'dummy2': mock_driver2
        }) as manager:
            manager.initialize()
            mock_driver1.initialize.assert_called_once_with()
            mock_driver2.initialize.assert_called_once_with()

    def _test_method_called(self, method_name):
        driver1 = mock.Mock()
        driver2 = mock.Mock()
        with self.driver_manager_context({
            'dummy1': driver1,
            'dummy2': driver2
        }) as manager:
            mocked_context = mock.Mock()
            getattr(manager, method_name)(mocked_context)
            getattr(driver1, method_name).assert_called_once_with(
                mocked_context)
            getattr(driver2, method_name).assert_called_once_with(
                mocked_context)

    def _test_method_exception(self, method_name,
                               expected_exc=fc_exc.FlowClassifierDriverError):
        mock_driver = mock.Mock()
        mock_method = mock.Mock(
            side_effect=fc_exc.FlowClassifierException
        )
        setattr(mock_driver, method_name, mock_method)
        with self.driver_manager_context({
            'dummy': mock_driver,
        }) as manager:
            mocked_context = mock.Mock()
            self.assertRaises(
                expected_exc, getattr(manager, method_name), mocked_context)

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
