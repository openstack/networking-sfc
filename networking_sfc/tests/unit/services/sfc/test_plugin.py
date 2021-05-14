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

import copy
from unittest import mock

from networking_sfc.services.sfc.common import context as sfc_ctx
from networking_sfc.services.sfc.common import exceptions as sfc_exc
from networking_sfc.tests.unit.db import test_sfc_db

SFC_PLUGIN_KLASS = (
    "networking_sfc.services.sfc.plugin.SfcPlugin"
)


class SfcPluginTestCase(test_sfc_db.SfcDbPluginTestCase):
    def setUp(self, core_plugin=None, sfc_plugin=None, ext_mgr=None):
        if not sfc_plugin:
            sfc_plugin = SFC_PLUGIN_KLASS
        self.driver_manager_p = mock.patch(
            'networking_sfc.services.sfc.driver_manager.SfcDriverManager'
        )
        self.fake_driver_manager_class = self.driver_manager_p.start()
        self.fake_driver_manager = mock.Mock()
        self.fake_driver_manager_class.return_value = self.fake_driver_manager
        self.plugin_context = None
        self.plugin_context_precommit = None
        self.plugin_context_postcommit = None
        super(SfcPluginTestCase, self).setUp(
            core_plugin=core_plugin, sfc_plugin=sfc_plugin,
            ext_mgr=ext_mgr
        )

    def _record_context(self, plugin_context):
        self.plugin_context = plugin_context

    def _record_context_precommit(self, plugin_context):
        self.plugin_context_precommit = plugin_context

    def _record_context_postcommit(self, plugin_context):
        self.plugin_context_postcommit = plugin_context

    def test_create_port_chain_driver_manager_called(self):
        self.fake_driver_manager.create_port_chain_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.create_port_chain_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(port_pair_group={}) as pg:
            with self.port_chain(port_chain={
                'port_pair_groups': [pg['port_pair_group']['id']]
            }) as pc:
                driver_manager = self.fake_driver_manager
                (driver_manager.create_port_chain_precommit
                    .assert_called_once_with(mock.ANY))
                (driver_manager.create_port_chain_postcommit
                    .assert_called_once_with(mock.ANY))
                self.assertIsInstance(
                    self.plugin_context_precommit, sfc_ctx.PortChainContext
                )
                self.assertIsInstance(
                    self.plugin_context_postcommit, sfc_ctx.PortChainContext
                )
                self.assertIn('port_chain', pc)
                self.assertEqual(
                    self.plugin_context_precommit.current, pc['port_chain'])
                self.assertEqual(
                    self.plugin_context_postcommit.current, pc['port_chain'])

    def test_create_port_chain_precommit_driver_manager_exception(self):
        self.fake_driver_manager.create_port_chain_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='create_port_chain_precommit'
            )
        )
        with self.port_pair_group(port_pair_group={}) as pg:
            self._create_port_chain(
                self.fmt,
                {'port_pair_groups': [pg['port_pair_group']['id']]},
                expected_res_status=500)
            self._test_list_resources('port_chain', [])
        (self.fake_driver_manager.create_port_chain_postcommit
         .assert_not_called())
        self.fake_driver_manager.delete_port_chain.assert_not_called()

    def test_create_port_chain_postcommit_driver_manager_exception(self):
        self.fake_driver_manager.create_port_chain_postcommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='create_port_chain_postcommit'
            )
        )
        with self.port_pair_group(port_pair_group={}) as pg:
            self._create_port_chain(
                self.fmt,
                {'port_pair_groups': [pg['port_pair_group']['id']]},
                expected_res_status=500)
            self._test_list_resources('port_chain', [])
        (self.fake_driver_manager.create_port_chain_precommit
         .assert_called_once_with(mock.ANY))
        self.fake_driver_manager.delete_port_chain.assert_called_once_with(
            mock.ANY
        )

    def test_update_port_chain_driver_manager_called(self):
        self.fake_driver_manager.update_port_chain_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.update_port_chain_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(port_pair_group={}) as pg:
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg['port_pair_group']['id']]
            }) as pc:
                req = self.new_update_request(
                    'port_chains', {'port_chain': {'name': 'test2'}},
                    pc['port_chain']['id']
                )
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                driver_manager = self.fake_driver_manager
                (driver_manager.update_port_chain_precommit
                 .assert_called_once_with(mock.ANY))
                (driver_manager.update_port_chain_postcommit
                 .assert_called_once_with(mock.ANY))
                self.assertIsInstance(
                    self.plugin_context_precommit, sfc_ctx.PortChainContext
                )
                self.assertIsInstance(
                    self.plugin_context_postcommit, sfc_ctx.PortChainContext
                )
                self.assertIn('port_chain', pc)
                self.assertIn('port_chain', res)
                self.assertEqual(
                    self.plugin_context_precommit.current, res['port_chain'])
                self.assertEqual(
                    self.plugin_context_postcommit.current, res['port_chain'])
                self.assertEqual(
                    self.plugin_context_precommit.original, pc['port_chain'])
                self.assertEqual(
                    self.plugin_context_postcommit.original, pc['port_chain'])

    def _test_update_port_chain_driver_manager_exception(self, updated):
        with self.port_pair_group(port_pair_group={}) as pg:
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg['port_pair_group']['id']]
            }) as pc:
                self.assertIn('port_chain', pc)
                original_port_chain = pc['port_chain']
                req = self.new_update_request(
                    'port_chains', {'port_chain': {'name': 'test2'}},
                    pc['port_chain']['id']
                )
                updated_port_chain = copy.copy(original_port_chain)
                if updated:
                    updated_port_chain['name'] = 'test2'
                res = req.get_response(self.ext_api)
                self.assertEqual(500, res.status_int)
                res = self._list('port_chains')
                self.assertIn('port_chains', res)
                self.assertCountEqual(
                    res['port_chains'], [updated_port_chain])

    def test_update_port_chain_precommit_driver_manager_exception(self):
        self.fake_driver_manager.update_port_chain_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='update_port_chain_precommit'
            )
        )
        self._test_update_port_chain_driver_manager_exception(False)

    def test_update_port_chain_postcommit_driver_manager_exception(self):
        self.fake_driver_manager.update_port_chain_postcommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='update_port_chain_postcommit'
            )
        )
        self._test_update_port_chain_driver_manager_exception(True)

    def test_delete_port_chain_manager_called(self):
        self.fake_driver_manager.delete_port_chain = mock.Mock(
            side_effect=self._record_context)
        self.fake_driver_manager.delete_port_chain_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.delete_port_chain_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(port_pair_group={}) as pg:
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg['port_pair_group']['id']]
            }, do_delete=False) as pc:
                req = self.new_delete_request(
                    'port_chains', pc['port_chain']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(204, res.status_int)
                driver_manager = self.fake_driver_manager
                (driver_manager.delete_port_chain
                 .assert_called_once_with(mock.ANY))
                (driver_manager.delete_port_chain_precommit
                 .assert_called_once_with(mock.ANY))
                (driver_manager.delete_port_chain_postcommit
                 .assert_called_once_with(mock.ANY))
                self.assertIsInstance(
                    self.plugin_context, sfc_ctx.PortChainContext
                )
                self.assertIsInstance(
                    self.plugin_context_precommit, sfc_ctx.PortChainContext
                )
                self.assertIsInstance(
                    self.plugin_context_postcommit, sfc_ctx.PortChainContext
                )
            self.assertIn('port_chain', pc)
            self.assertEqual(self.plugin_context.current, pc['port_chain'])
            self.assertEqual(self.plugin_context_precommit.current,
                             pc['port_chain'])
            self.assertEqual(self.plugin_context_postcommit.current,
                             pc['port_chain'])

    def _test_delete_port_chain_driver_manager_exception(self):
        with self.port_pair_group(port_pair_group={
        }, do_delete=False) as pg:
            with self.port_chain(port_chain={
                'name': 'test1',
                'port_pair_groups': [pg['port_pair_group']['id']]
            }, do_delete=False) as pc:
                req = self.new_delete_request(
                    'port_chains', pc['port_chain']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(500, res.status_int)
                self._test_list_resources('port_chain', [pc])

    def test_delete_port_chain_driver_manager_exception(self):
        self.fake_driver_manager.delete_port_chain = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='delete_port_chain'
            )
        )
        self._test_delete_port_chain_driver_manager_exception()

    def test_delete_port_chain_driver_precommit_manager_exception(self):
        self.fake_driver_manager.delete_port_chain_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='delete_port_chain_precommit'
            )
        )
        self._test_delete_port_chain_driver_manager_exception()

    def test_create_port_pair_group_driver_manager_called(self):
        self.fake_driver_manager.create_port_pair_group_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.create_port_pair_group_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(port_pair_group={}) as pc:
            fake_driver_manager = self.fake_driver_manager
            (fake_driver_manager.create_port_pair_group_precommit
             .assert_called_once_with(mock.ANY))
            (fake_driver_manager.create_port_pair_group_postcommit
             .assert_called_once_with(mock.ANY))
            self.assertIsInstance(
                self.plugin_context_precommit, sfc_ctx.PortPairGroupContext
            )
            self.assertIsInstance(
                self.plugin_context_postcommit, sfc_ctx.PortPairGroupContext
            )
            self.assertIn('port_pair_group', pc)
            self.assertEqual(
                self.plugin_context_precommit.current, pc['port_pair_group'])
            self.assertEqual(
                self.plugin_context_postcommit.current, pc['port_pair_group'])

    def test_create_port_pair_group_precommit_driver_manager_exception(self):
        self.fake_driver_manager.create_port_pair_group_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='create_port_pair_group_precommit'
            )
        )
        self._create_port_pair_group(self.fmt, {}, expected_res_status=500)
        self._test_list_resources('port_pair_group', [])
        driver_manager = self.fake_driver_manager
        (driver_manager.create_port_pair_group_precommit
         .assert_called_once_with(mock.ANY))
        driver_manager.create_port_pair_group_postcommit.assert_not_called()
        driver_manager.delete_port_pair_group.assert_not_called()
        driver_manager.delete_port_pair_group_precommit.assert_not_called()
        driver_manager.delete_port_pair_group_postcommit.assert_not_called()

    def test_create_port_pair_group_postcommit_driver_manager_exception(self):
        self.fake_driver_manager.create_port_pair_group_postcommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='create_port_pair_group_postcommit'
            )
        )
        self._create_port_pair_group(self.fmt, {}, expected_res_status=500)
        self._test_list_resources('port_pair_group', [])
        driver_manager = self.fake_driver_manager
        (driver_manager.create_port_pair_group_precommit
         .assert_called_once_with(mock.ANY))
        (driver_manager.delete_port_pair_group
         .assert_called_once_with(mock.ANY))
        (driver_manager.delete_port_pair_group_precommit
         .assert_called_once_with(mock.ANY))
        (driver_manager.delete_port_pair_group_postcommit
         .assert_called_once_with(mock.ANY))

    def test_update_port_pair_group_driver_manager_called(self):
        self.fake_driver_manager.update_port_pair_group_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.update_port_pair_group_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }) as pc:
            req = self.new_update_request(
                'port_pair_groups', {'port_pair_group': {'name': 'test2'}},
                pc['port_pair_group']['id']
            )
            res = self.deserialize(
                self.fmt,
                req.get_response(self.ext_api)
            )
            driver_manager = self.fake_driver_manager
            (driver_manager.update_port_pair_group_precommit
             .assert_called_once_with(mock.ANY))
            (driver_manager.update_port_pair_group_postcommit
             .assert_called_once_with(mock.ANY))
            self.assertIsInstance(
                self.plugin_context_precommit, sfc_ctx.PortPairGroupContext
            )
            self.assertIsInstance(
                self.plugin_context_postcommit, sfc_ctx.PortPairGroupContext
            )
            self.assertIn('port_pair_group', pc)
            self.assertIn('port_pair_group', res)
            self.assertEqual(
                self.plugin_context_precommit.current, res['port_pair_group'])
            self.assertEqual(
                self.plugin_context_postcommit.current, res['port_pair_group'])
            self.assertEqual(
                self.plugin_context_precommit.original, pc['port_pair_group'])
            self.assertEqual(
                self.plugin_context_postcommit.original, pc['port_pair_group'])

    def _test_update_port_pair_group_driver_manager_exception(self, updated):
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }) as pc:
            self.assertIn('port_pair_group', pc)
            original_port_pair_group = pc['port_pair_group']
            req = self.new_update_request(
                'port_pair_groups', {'port_pair_group': {'name': 'test2'}},
                pc['port_pair_group']['id']
            )
            updated_port_pair_group = copy.copy(original_port_pair_group)
            if updated:
                updated_port_pair_group['name'] = 'test2'
            res = req.get_response(self.ext_api)
            self.assertEqual(500, res.status_int)
            res = self._list('port_pair_groups')
            self.assertIn('port_pair_groups', res)
            self.assertCountEqual(
                res['port_pair_groups'], [updated_port_pair_group])

    def test_update_port_pair_group_precommit_driver_manager_exception(self):
        self.fake_driver_manager.update_port_pair_group_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='update_port_pair_group_precommit'
            )
        )
        self._test_update_port_pair_group_driver_manager_exception(False)

    def test_update_port_pair_group_postcommit_driver_manager_exception(self):
        self.fake_driver_manager.update_port_pair_group_postcommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='update_port_pair_group_postcommit'
            )
        )
        self._test_update_port_pair_group_driver_manager_exception(True)

    def test_delete_port_pair_group_manager_called(self):
        self.fake_driver_manager.delete_port_pair_group = mock.Mock(
            side_effect=self._record_context)
        self.fake_driver_manager.delete_port_pair_group_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.delete_port_pair_group_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }, do_delete=False) as pc:
            req = self.new_delete_request(
                'port_pair_groups', pc['port_pair_group']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(204, res.status_int)
            driver_manager = self.fake_driver_manager
            driver_manager.delete_port_pair_group.assert_called_once_with(
                mock.ANY
            )
            (driver_manager.delete_port_pair_group_precommit
             .assert_called_once_with(mock.ANY))
            (driver_manager.delete_port_pair_group_postcommit
             .assert_called_once_with(mock.ANY))
            self.assertIsInstance(
                self.plugin_context, sfc_ctx.PortPairGroupContext
            )
            self.assertIsInstance(
                self.plugin_context_precommit, sfc_ctx.PortPairGroupContext
            )
            self.assertIsInstance(
                self.plugin_context_postcommit, sfc_ctx.PortPairGroupContext
            )
            self.assertIn('port_pair_group', pc)
            self.assertEqual(
                self.plugin_context.current, pc['port_pair_group'])
            self.assertEqual(
                self.plugin_context_precommit.current, pc['port_pair_group'])
            self.assertEqual(
                self.plugin_context_postcommit.current, pc['port_pair_group'])

    def _test_delete_port_pair_group_driver_manager_exception(self):
        with self.port_pair_group(port_pair_group={
            'name': 'test1'
        }, do_delete=False) as pc:
            req = self.new_delete_request(
                'port_pair_groups', pc['port_pair_group']['id']
            )
            res = req.get_response(self.ext_api)
            self.assertEqual(500, res.status_int)
            self._test_list_resources('port_pair_group', [pc])

    def test_delete_port_pair_group_driver_manager_exception(self):
        self.fake_driver_manager.delete_port_pair_group = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='delete_port_pair_group'
            )
        )
        self._test_delete_port_pair_group_driver_manager_exception()

    def test_delete_port_pair_group_precommit_driver_manager_exception(self):
        self.fake_driver_manager.delete_port_pair_group_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='delete_port_pair_group_precommit'
            )
        )
        self._test_delete_port_pair_group_driver_manager_exception()

    def test_create_port_pair_driver_manager_called(self):
        self.fake_driver_manager.create_port_pair_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.create_port_pair_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc:
                driver_manager = self.fake_driver_manager
                (driver_manager.create_port_pair_precommit
                 .assert_called_once_with(mock.ANY))
                (driver_manager.create_port_pair_postcommit
                 .assert_called_once_with(mock.ANY))
                self.assertIsInstance(
                    self.plugin_context_precommit, sfc_ctx.PortPairContext
                )
                self.assertIsInstance(
                    self.plugin_context_postcommit, sfc_ctx.PortPairContext
                )
                self.assertIn('port_pair', pc)
                self.assertEqual(self.plugin_context_precommit.current,
                                 pc['port_pair'])
                self.assertEqual(self.plugin_context_postcommit.current,
                                 pc['port_pair'])

    def test_create_port_pair_precommit_driver_manager_exception(self):
        self.fake_driver_manager.create_port_pair_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='create_port_pair_precommit'
            )
        )
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_port['port']['id'],
                    'egress': dst_port['port']['id']
                },
                expected_res_status=500)
            self._test_list_resources('port_pair', [])
            driver_manager = self.fake_driver_manager
            driver_manager.create_port_pair_postcommit.assert_not_called()
            driver_manager.delete_port_pair.assert_not_called()

    def test_create_port_pair_postcommit_driver_manager_exception(self):
        self.fake_driver_manager.create_port_pair_postcommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='create_port_pair_postcommit'
            )
        )
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            self._create_port_pair(
                self.fmt,
                {
                    'ingress': src_port['port']['id'],
                    'egress': dst_port['port']['id']
                },
                expected_res_status=500)
            self._test_list_resources('port_pair', [])
            driver_manager = self.fake_driver_manager
            driver_manager.create_port_pair_precommit.assert_called_once_with(
                mock.ANY
            )
            driver_manager.delete_port_pair.assert_called_once_with(
                mock.ANY
            )
            driver_manager.delete_port_pair_precommit.assert_called_once_with(
                mock.ANY
            )
            driver_manager.delete_port_pair_postcommit.assert_called_once_with(
                mock.ANY
            )

    def test_update_port_pair_driver_manager_called(self):
        self.fake_driver_manager.update_port_pair_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.update_port_pair_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc:
                req = self.new_update_request(
                    'port_pairs', {'port_pair': {'name': 'test2'}},
                    pc['port_pair']['id']
                )
                res = self.deserialize(
                    self.fmt,
                    req.get_response(self.ext_api)
                )
                driver_manager = self.fake_driver_manager
                (driver_manager.update_port_pair_precommit
                 .assert_called_once_with(mock.ANY))
                (driver_manager.update_port_pair_postcommit
                 .assert_called_once_with(mock.ANY))
                self.assertIsInstance(
                    self.plugin_context_precommit, sfc_ctx.PortPairContext
                )
                self.assertIsInstance(
                    self.plugin_context_postcommit, sfc_ctx.PortPairContext
                )
                self.assertIn('port_pair', pc)
                self.assertIn('port_pair', res)
                self.assertEqual(
                    self.plugin_context_precommit.current, res['port_pair'])
                self.assertEqual(
                    self.plugin_context_postcommit.current, res['port_pair'])
                self.assertEqual(
                    self.plugin_context_precommit.original, pc['port_pair'])
                self.assertEqual(
                    self.plugin_context_postcommit.original, pc['port_pair'])

    def _test_update_port_pair_driver_manager_exception(self, updated):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }) as pc:
                self.assertIn('port_pair', pc)
                original_port_pair = pc['port_pair']
                req = self.new_update_request(
                    'port_pairs', {'port_pair': {'name': 'test2'}},
                    pc['port_pair']['id']
                )
                updated_port_pair = copy.copy(original_port_pair)
                if updated:
                    updated_port_pair['name'] = 'test2'
                res = req.get_response(self.ext_api)
                self.assertEqual(500, res.status_int)
                res = self._list('port_pairs')
                self.assertIn('port_pairs', res)
                self.assertCountEqual(res['port_pairs'], [updated_port_pair])

    def test_update_port_pair_precommit_driver_manager_exception(self):
        self.fake_driver_manager.update_port_pair_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='update_port_pair_precommit'
            )
        )
        self._test_update_port_pair_driver_manager_exception(False)

    def test_update_port_pair_postcommit_driver_manager_exception(self):
        self.fake_driver_manager.update_port_pair_postcommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='update_port_pair_postcommit'
            )
        )
        self._test_update_port_pair_driver_manager_exception(True)

    def test_delete_port_pair_manager_called(self):
        self.fake_driver_manager.delete_port_pair = mock.Mock(
            side_effect=self._record_context)
        self.fake_driver_manager.delete_port_pair_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.delete_port_pair_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }, do_delete=False) as pc:
                req = self.new_delete_request(
                    'port_pairs', pc['port_pair']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(204, res.status_int)
                fake_driver_manager = self.fake_driver_manager
                fake_driver_manager.delete_port_pair.assert_called_once_with(
                    mock.ANY
                )
                (fake_driver_manager.delete_port_pair_precommit
                 .assert_called_once_with(mock.ANY))
                (fake_driver_manager.delete_port_pair_postcommit
                 .assert_called_once_with(mock.ANY))
                self.assertIsInstance(
                    self.plugin_context, sfc_ctx.PortPairContext
                )
                self.assertIsInstance(
                    self.plugin_context_precommit, sfc_ctx.PortPairContext
                )
                self.assertIsInstance(
                    self.plugin_context_postcommit, sfc_ctx.PortPairContext
                )
                self.assertIn('port_pair', pc)
                self.assertEqual(self.plugin_context.current, pc['port_pair'])

    def _test_delete_port_pair_driver_manager_exception(self):
        with self.port(
            name='port1',
            device_id='default'
        ) as src_port, self.port(
            name='port2',
            device_id='default'
        ) as dst_port:
            with self.port_pair(port_pair={
                'name': 'test1',
                'ingress': src_port['port']['id'],
                'egress': dst_port['port']['id']
            }, do_delete=False) as pc:
                req = self.new_delete_request(
                    'port_pairs', pc['port_pair']['id']
                )
                res = req.get_response(self.ext_api)
                self.assertEqual(500, res.status_int)
                self._test_list_resources('port_pair', [pc])

    def test_delete_port_pair_driver_manager_exception(self):
        self.fake_driver_manager.delete_port_pair = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='delete_port_pair'
            )
        )
        self._test_delete_port_pair_driver_manager_exception()

    def test_delete_port_pair_precommit_driver_manager_exception(self):
        self.fake_driver_manager.delete_port_pair_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='delete_port_pair_precommit'
            )
        )
        self._test_delete_port_pair_driver_manager_exception()

    def test_create_service_graph_driver_manager_called(self):
        self.fake_driver_manager.create_service_graph_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.create_service_graph_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                with self.service_graph(
                    service_graph={
                        'name': 'test1',
                        'port_chains': {
                            pc1['port_chain']['id']: [pc2['port_chain']['id']]
                        }
                    }
                ) as graph:
                    driver_manager = self.fake_driver_manager
                    (driver_manager.create_service_graph_precommit
                        .assert_called_once_with(mock.ANY))
                    (driver_manager.create_service_graph_postcommit
                        .assert_called_once_with(mock.ANY))
                    self.assertIsInstance(
                        self.plugin_context_precommit,
                        sfc_ctx.ServiceGraphContext
                    )
                    self.assertIsInstance(
                        self.plugin_context_postcommit,
                        sfc_ctx.ServiceGraphContext
                    )
                    self.assertIn('service_graph', graph)
                    self.assertEqual(
                        self.plugin_context_precommit.current,
                        graph['service_graph'])
                    self.assertEqual(
                        self.plugin_context_postcommit.current,
                        graph['service_graph'])

    def test_create_service_graph_precommit_driver_manager_exception(self):
        self.fake_driver_manager.create_service_graph_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='create_service_graph_precommit'
            )
        )
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]
                    }
                }, expected_res_status=500)
                self._test_list_resources('service_graph', [])
            (self.fake_driver_manager.create_service_graph_postcommit
                .assert_not_called())
            self.fake_driver_manager.delete_service_graph.assert_not_called()

    def test_create_service_graph_postcommit_driver_manager_exception(self):
        self.fake_driver_manager.create_service_graph_postcommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='create_service_graph_postcommit'
            )
        )
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                self._create_service_graph(self.fmt, {
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]
                    }
                }, expected_res_status=500)
                self._test_list_resources('service_graph', [])
            (self.fake_driver_manager.create_service_graph_precommit
             .assert_called_once_with(mock.ANY))
            self.fake_driver_manager.delete_service_graph_postcommit.\
                assert_called_once_with(mock.ANY)

    def test_update_service_graph_driver_manager_called(self):
        self.fake_driver_manager.update_service_graph_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.update_service_graph_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                with self.service_graph(service_graph={
                    'name': 'test1',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]
                    }
                }) as graph:
                    req = self.new_update_request(
                        'service_graphs',
                        {'service_graph': {'name': 'test2'}},
                        graph['service_graph']['id']
                    )
                    res = self.deserialize(
                        self.fmt,
                        req.get_response(self.ext_api)
                    )
                    driver_manager = self.fake_driver_manager
                    (driver_manager.update_service_graph_precommit
                     .assert_called_once_with(mock.ANY))
                    (driver_manager.update_service_graph_postcommit
                     .assert_called_once_with(mock.ANY))
                    self.assertIsInstance(
                        self.plugin_context_precommit,
                        sfc_ctx.ServiceGraphContext
                    )
                    self.assertIsInstance(
                        self.plugin_context_postcommit,
                        sfc_ctx.ServiceGraphContext
                    )
                    self.assertIn('service_graph', graph)
                    self.assertIn('service_graph', res)
                    self.assertEqual(
                        self.plugin_context_precommit.current,
                        res['service_graph'])
                    self.assertEqual(
                        self.plugin_context_postcommit.current,
                        res['service_graph'])
                    self.assertEqual(
                        self.plugin_context_precommit.original,
                        graph['service_graph'])
                    self.assertEqual(
                        self.plugin_context_postcommit.original,
                        graph['service_graph'])

    def _test_update_service_graph_driver_manager_exception(self, updated):
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                with self.service_graph(service_graph={
                    'name': 'test1',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]
                    }
                }) as graph:
                    self.assertIn('service_graph', graph)
                    original_service_graph = graph['service_graph']
                    req = self.new_update_request(
                        'service_graphs', {'service_graph': {'name': 'test2'}},
                        graph['service_graph']['id']
                    )
                    updated_service_graph = copy.copy(original_service_graph)
                    if updated:
                        updated_service_graph['name'] = 'test2'
                    res = req.get_response(self.ext_api)
                    self.assertEqual(500, res.status_int)
                    res = self._list('service_graphs')
                    self.assertIn('service_graphs', res)
                    self.assertCountEqual(
                        res['service_graphs'], [updated_service_graph])

    def test_update_service_graph_precommit_driver_manager_exception(self):
        self.fake_driver_manager.update_service_graph_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='update_service_graph_precommit'
            )
        )
        self._test_update_service_graph_driver_manager_exception(False)

    def test_update_service_graph_postcommit_driver_manager_exception(self):
        self.fake_driver_manager.update_service_graph_postcommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='update_service_graph_postcommit'
            )
        )
        self._test_update_service_graph_driver_manager_exception(True)

    def test_delete_service_graph_manager_called(self):
        self.fake_driver_manager.delete_service_graph_precommit = mock.Mock(
            side_effect=self._record_context_precommit)
        self.fake_driver_manager.delete_service_graph_postcommit = mock.Mock(
            side_effect=self._record_context_postcommit)
        with self.port_pair_group(
            port_pair_group={}
        ) as pg1, self.port_pair_group(
            port_pair_group={}
        ) as pg2:
            with self.port_chain(
                port_chain={'port_pair_groups': [pg1['port_pair_group']['id']]}
            ) as pc1, self.port_chain(
                port_chain={'port_pair_groups': [pg2['port_pair_group']['id']]}
            ) as pc2:
                with self.service_graph(service_graph={
                    'name': 'test1',
                    'port_chains': {
                        pc1['port_chain']['id']: [pc2['port_chain']['id']]
                    }
                }, do_delete=False) as graph:
                    req = self.new_delete_request(
                        'service_graphs', graph['service_graph']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(204, res.status_int)
                    driver_manager = self.fake_driver_manager
                    (driver_manager.delete_service_graph_precommit
                     .assert_called_once_with(mock.ANY))
                    (driver_manager.delete_service_graph_postcommit
                     .assert_called_once_with(mock.ANY))
                    self.assertIsInstance(
                        self.plugin_context_precommit,
                        sfc_ctx.ServiceGraphContext
                    )
                    self.assertIsInstance(
                        self.plugin_context_postcommit,
                        sfc_ctx.ServiceGraphContext
                    )
                self.assertIn('service_graph', graph)
                self.assertEqual(self.plugin_context_precommit.current,
                                 graph['service_graph'])
                self.assertEqual(self.plugin_context_postcommit.current,
                                 graph['service_graph'])

    def _test_delete_service_graph_driver_manager_exception(self):
        with self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg1, self.port_pair_group(
            port_pair_group={}, do_delete=False
        ) as pg2:
            with self.port_chain(
                port_chain={
                    'port_pair_groups': [
                        pg1['port_pair_group']['id']
                    ]
                },
                do_delete=False
            ) as pc1, self.port_chain(
                port_chain={
                    'port_pair_groups': [
                        pg2['port_pair_group']['id']
                    ]
                },
                do_delete=False
            ) as pc2:
                with self.service_graph(
                    service_graph={
                        'name': 'test1',
                        'port_chains': {
                            pc1['port_chain']['id']: [
                                pc2['port_chain']['id']
                            ]
                        }
                    },
                    do_delete=False
                ) as graph:
                    req = self.new_delete_request(
                        'service_graphs', graph['service_graph']['id']
                    )
                    res = req.get_response(self.ext_api)
                    self.assertEqual(500, res.status_int)
                    self._test_list_resources('service_graph', [graph])

    def test_delete_service_graph_driver_precommit_manager_exception(self):
        self.fake_driver_manager.delete_service_graph_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='delete_service_graph_precommit'
            )
        )
        self._test_delete_service_graph_driver_manager_exception()

    def test_delete_service_graph_driver_postcommit_manager_exception(self):
        self.fake_driver_manager.delete_service_graph_precommit = mock.Mock(
            side_effect=sfc_exc.SfcDriverError(
                method='delete_service_graph_postcommit'
            )
        )
        self._test_delete_service_graph_driver_manager_exception()
