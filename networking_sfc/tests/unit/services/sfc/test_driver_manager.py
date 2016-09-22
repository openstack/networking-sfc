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

from networking_sfc.services.sfc.common import config as sfc_config
from networking_sfc.services.sfc.common import exceptions as sfc_exc
from networking_sfc.services.sfc import driver_manager as sfc_driver


class DriverManagerTestCase(base.BaseTestCase):
    def setUp(self):
        super(DriverManagerTestCase, self).setUp()

    @contextlib.contextmanager
    def driver_manager_context(self, drivers):
        cfg.CONF.register_opts(sfc_config.SFC_DRIVER_OPTS, 'sfc')
        backup_driver_names = cfg.CONF.sfc.drivers
        driver_names = [
            driver_name for driver_name in six.iterkeys(drivers)
        ]
        cfg.CONF.set_override('drivers', driver_names, 'sfc')
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
        yield sfc_driver.SfcDriverManager()
        cfg.CONF.set_override('drivers', backup_driver_names, 'sfc')
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

    def _test_method_exception(self, method_name):
        mock_driver = mock.Mock()
        mock_method = mock.Mock(
            side_effect=sfc_exc.SfcException
        )
        setattr(mock_driver, method_name, mock_method)
        with self.driver_manager_context({
            'dummy': mock_driver,
        }) as manager:
            mocked_context = mock.Mock()
            self.assertRaises(
                sfc_exc.SfcDriverError,
                getattr(manager, method_name), mocked_context)

    def test_create_port_chain_precommit_called(self):
        self._test_method_called("create_port_chain_precommit")

    def test_create_port_chain_precommit_exception(self):
        self._test_method_exception("create_port_chain_precommit")

    def test_create_port_chain_postcommit_called(self):
        self._test_method_called("create_port_chain_postcommit")

    def test_create_port_chain_postcommit_exception(self):
        self._test_method_exception("create_port_chain_postcommit")

    def test_update_port_chain_precommit_called(self):
        self._test_method_called("update_port_chain_precommit")

    def test_update_port_chain_precommit_exception(self):
        self._test_method_exception("update_port_chain_precommit")

    def test_update_port_chain_postcommit_called(self):
        self._test_method_called("update_port_chain_postcommit")

    def test_update_port_chain_postcommit_exception(self):
        self._test_method_exception("update_port_chain_postcommit")

    def test_delete_port_chain_called(self):
        self._test_method_called("delete_port_chain")

    def test_delete_port_chain_exception(self):
        self._test_method_exception("delete_port_chain")

    def test_delete_port_chain_precommit_called(self):
        self._test_method_called("delete_port_chain_precommit")

    def test_delete_port_chain_precommit_exception(self):
        self._test_method_exception("delete_port_chain_precommit")

    def test_delete_port_chain_postcommit_called(self):
        self._test_method_called("delete_port_chain_postcommit")

    def test_delete_port_chain_postcommit_exception(self):
        self._test_method_exception("delete_port_chain_postcommit")

    def test_create_port_pair_group_precommit_called(self):
        self._test_method_called("create_port_pair_group_precommit")

    def test_create_port_pair_group_precommit_exception(self):
        self._test_method_exception("create_port_pair_group_precommit")

    def test_create_port_pair_group_postcommit_called(self):
        self._test_method_called("create_port_pair_group_postcommit")

    def test_create_port_pair_group_postcommit_exception(self):
        self._test_method_exception("create_port_pair_group_postcommit")

    def test_update_port_pair_group_precommit_called(self):
        self._test_method_called("update_port_pair_group_precommit")

    def test_update_port_pair_group_precommit_exception(self):
        self._test_method_exception("update_port_pair_group_precommit")

    def test_update_port_pair_group_postcommit_called(self):
        self._test_method_called("update_port_pair_group_postcommit")

    def test_update_port_pair_group_postcommit_exception(self):
        self._test_method_exception("update_port_pair_group_postcommit")

    def test_delete_port_pair_group_called(self):
        self._test_method_called("delete_port_pair_group")

    def test_delete_port_pair_group_exception(self):
        self._test_method_exception("delete_port_pair_group")

    def test_delete_port_pair_group_precommit_called(self):
        self._test_method_called("delete_port_pair_group_precommit")

    def test_delete_port_pair_group_precommit_exception(self):
        self._test_method_exception("delete_port_pair_group_precommit")

    def test_delete_port_pair_group_postcommit_called(self):
        self._test_method_called("delete_port_pair_group_postcommit")

    def test_delete_port_pair_group_postcommit_exception(self):
        self._test_method_exception("delete_port_pair_group_postcommit")

    def test_create_port_pair_precommit_called(self):
        self._test_method_called("create_port_pair_precommit")

    def test_create_port_pair_precommit_exception(self):
        self._test_method_exception("create_port_pair_precommit")

    def test_create_port_pair_postcommit_called(self):
        self._test_method_called("create_port_pair_postcommit")

    def test_create_port_pair_postcommit_exception(self):
        self._test_method_exception("create_port_pair_postcommit")

    def test_update_port_pair_precommit_called(self):
        self._test_method_called("update_port_pair_precommit")

    def test_update_port_pair_precommit_exception(self):
        self._test_method_exception("update_port_pair_precommit")

    def test_update_port_pair_postcommit_called(self):
        self._test_method_called("update_port_pair_postcommit")

    def test_update_port_pair_postcommit_exception(self):
        self._test_method_exception("update_port_pair_postcommit")

    def test_delete_port_pair_called(self):
        self._test_method_called("delete_port_pair")

    def test_delete_port_pair_exception(self):
        self._test_method_exception("delete_port_pair")

    def test_delete_port_pair_precommit_called(self):
        self._test_method_called("delete_port_pair_precommit")

    def test_delete_port_pair_precommit_exception(self):
        self._test_method_exception("delete_port_pair_precommit")

    def test_delete_port_pair_postcommit_called(self):
        self._test_method_called("delete_port_pair_postcommit")

    def test_delete_port_pair_postcommit_exception(self):
        self._test_method_exception("delete_port_pair_postcommit")
