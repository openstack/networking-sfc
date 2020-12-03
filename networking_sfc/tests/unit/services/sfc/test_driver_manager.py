# Copyright 2017 Futurewei. All rights reserved.
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

from networking_sfc.services.sfc.common import exceptions as sfc_exc
from networking_sfc.services.sfc.driver_manager \
    import SfcDriverManager


class DriverManagerTestCase(base.BaseTestCase):
    def setUp(self):
        super(DriverManagerTestCase, self).setUp()

    def test_initialize_called(self):
        driver1 = Extension('mock_driver1', Mock(), None,
                            Mock(native_bulk_support=True))
        driver2 = Extension('mock_driver2', Mock(), None,
                            Mock(native_bulk_support=True))
        manager = SfcDriverManager.make_test_instance([driver1, driver2])
        manager.initialize()
        driver1.obj.initialize.assert_called_once_with()
        driver2.obj.initialize.assert_called_once_with()

    def _test_method_called(self, method_name):
        driver1 = Extension('mock_driver1', Mock(), None,
                            Mock(native_bulk_support=True))
        driver2 = Extension('mock_driver2', Mock(), None,
                            Mock(native_bulk_support=True))
        manager = SfcDriverManager.make_test_instance([driver1, driver2])
        mocked_context = Mock()
        getattr(manager, method_name)(mocked_context)
        getattr(driver1.obj, method_name).assert_called_once_with(
            mocked_context)
        getattr(driver2.obj, method_name).assert_called_once_with(
            mocked_context)

    def _test_method_exception(self, method_name,
                               expected_exc=sfc_exc.SfcDriverError):
        driver = Extension('mock_driver', Mock(), None,
                           Mock(native_bulk_support=True))
        mock_method = Mock(side_effect=sfc_exc.SfcException)
        setattr(driver.obj, method_name, mock_method)
        manager = SfcDriverManager.make_test_instance([driver])
        mocked_context = Mock()
        self.assertRaises(expected_exc,
                          getattr(manager, method_name),
                          mocked_context)

    def test_create_port_chain_precommit_called(self):
        self._test_method_called("create_port_chain_precommit")

    def test_create_port_chain_precommit_exception(self):
        self._test_method_exception("create_port_chain_precommit",
                                    sfc_exc.SfcException)

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

    def test_create_service_graph_precommit_called(self):
        self._test_method_called("create_service_graph_precommit")

    def test_create_service_graph_precommit_exception(self):
        self._test_method_exception("create_service_graph_precommit")

    def test_create_service_graph_postcommit_called(self):
        self._test_method_called("create_service_graph_postcommit")

    def test_create_service_graph_postcommit_exception(self):
        self._test_method_exception("create_service_graph_postcommit")

    def test_update_service_graph_precommit_called(self):
        self._test_method_called("update_service_graph_precommit")

    def test_update_service_graph_precommit_exception(self):
        self._test_method_exception("update_service_graph_precommit")

    def test_update_service_graph_postcommit_called(self):
        self._test_method_called("update_service_graph_postcommit")

    def test_update_service_graph_postcommit_exception(self):
        self._test_method_exception("update_service_graph_postcommit")

    def test_delete_service_graph_precommit_called(self):
        self._test_method_called("delete_service_graph_precommit")

    def test_delete_service_graph_precommit_exception(self):
        self._test_method_exception("delete_service_graph_precommit")

    def test_delete_service_graph_postcommit_called(self):
        self._test_method_called("delete_service_graph_postcommit")

    def test_delete_service_graph_postcommit_exception(self):
        self._test_method_exception("delete_service_graph_postcommit")
