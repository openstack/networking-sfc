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
import six
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
            driver_name for driver_name in six.iterkeys(drivers)
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

    def test_create_flow_classifier_called(self):
        mock_driver1 = mock.Mock()
        mock_driver2 = mock.Mock()
        with self.driver_manager_context({
            'dummy1': mock_driver1,
            'dummy2': mock_driver2
        }) as manager:
            mocked_context = mock.Mock()
            manager.create_flow_classifier(mocked_context)
            mock_driver1.create_flow_classifier.assert_called_once_with(
                mocked_context)
            mock_driver2.create_flow_classifier.assert_called_once_with(
                mocked_context)

    def test_create_flow_classifier_precommit_called(self):
        driver1 = mock.Mock()
        driver2 = mock.Mock()
        with self.driver_manager_context({
            'dummy1': driver1,
            'dummy2': driver2
        }) as manager:
            mocked_context = mock.Mock()
            manager.create_flow_classifier_precommit(mocked_context)
            driver1.create_flow_classifier_precommit.assert_called_once_with(
                mocked_context)
            driver2.create_flow_classifier_precommit.assert_called_once_with(
                mocked_context)

    def test_create_flow_classifier_exception(self):
        mock_driver = mock.Mock()
        mock_driver.create_flow_classifier = mock.Mock(
            side_effect=fc_exc.FlowClassifierException
        )
        with self.driver_manager_context({
            'dummy': mock_driver,
        }) as manager:
            mocked_context = mock.Mock()
            self.assertRaises(
                fc_exc.FlowClassifierDriverError,
                manager.create_flow_classifier, mocked_context
            )

    def test_create_flow_classifier_precommit_exception(self):
        mock_driver = mock.Mock()
        mock_driver.create_flow_classifier_precommit = mock.Mock(
            side_effect=fc_exc.FlowClassifierException
        )
        with self.driver_manager_context({
            'dummy': mock_driver,
        }) as manager:
            mocked_context = mock.Mock()
            self.assertRaises(
                fc_exc.FlowClassifierException,
                manager.create_flow_classifier_precommit, mocked_context
            )

    def test_update_flow_classifier_called(self):
        mock_driver1 = mock.Mock()
        mock_driver2 = mock.Mock()
        with self.driver_manager_context({
            'dummy1': mock_driver1,
            'dummy2': mock_driver2
        }) as manager:
            mocked_context = mock.Mock()
            manager.update_flow_classifier(mocked_context)
            mock_driver1.update_flow_classifier.assert_called_once_with(
                mocked_context)
            mock_driver2.update_flow_classifier.assert_called_once_with(
                mocked_context)

    def test_update_flow_classifier_exception(self):
        mock_driver = mock.Mock()
        mock_driver.update_flow_classifier = mock.Mock(
            side_effect=fc_exc.FlowClassifierException
        )
        with self.driver_manager_context({
            'dummy': mock_driver,
        }) as manager:
            mocked_context = mock.Mock()
            self.assertRaises(
                fc_exc.FlowClassifierDriverError,
                manager.update_flow_classifier, mocked_context
            )

    def test_delete_flow_classifier_called(self):
        mock_driver1 = mock.Mock()
        mock_driver2 = mock.Mock()
        with self.driver_manager_context({
            'dummy1': mock_driver1,
            'dummy2': mock_driver2
        }) as manager:
            mocked_context = mock.Mock()
            manager.delete_flow_classifier(mocked_context)
            mock_driver1.delete_flow_classifier.assert_called_once_with(
                mocked_context)
            mock_driver2.delete_flow_classifier.assert_called_once_with(
                mocked_context)

    def test_delete_flow_classifier_exception(self):
        mock_driver = mock.Mock()
        mock_driver.delete_flow_classifier = mock.Mock(
            side_effect=fc_exc.FlowClassifierException
        )
        with self.driver_manager_context({
            'dummy': mock_driver,
        }) as manager:
            mocked_context = mock.Mock()
            self.assertRaises(
                fc_exc.FlowClassifierDriverError,
                manager.delete_flow_classifier, mocked_context
            )
