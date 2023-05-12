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
from unittest import mock

from neutron.agent import securitygroups_rpc as sg_rpc
from neutron.api import extensions as api_ext
from neutron.api.rpc.agentnotifiers import dhcp_rpc_agent_api as dhcp_rpc_log
from neutron.api.v2 import resource as api_res_log
from neutron import manager
from neutron.notifiers import nova as nova_log
from neutron.plugins.ml2 import db as ml2_db
from neutron.plugins.ml2.drivers import type_flat
from neutron.plugins.ml2.drivers import type_local
from neutron.plugins.ml2.drivers import type_tunnel
from neutron.plugins.ml2.drivers import type_vlan
from neutron.plugins.ml2.drivers import type_vxlan   # noqa
from neutron.plugins.ml2 import managers as ml2_manager
from neutron.plugins.ml2 import plugin as ml2_plugin
from neutron import quota as quota_log
from neutron.scheduler import dhcp_agent_scheduler as dhcp_agent_log
from neutron_lib import constants as nl_const
from oslo_config import cfg
from oslo_utils import uuidutils

from neutron.tests import base as n_base
from neutron.tests.unit.db import test_db_base_plugin_v2 as test_db_plugin


class BaseTestCase(n_base.BaseTestCase):
    pass


class NeutronDbPluginV2TestCase(test_db_plugin.NeutronDbPluginV2TestCase):
    def setUp(self, plugin=None, service_plugins=None, ext_mgr=None):
        self._mock_unnecessary_logging()

        if not plugin:
            plugin = 'neutron.plugins.ml2.plugin.Ml2Plugin'
        cfg.CONF.set_override('tenant_network_types', ['vxlan'], group='ml2')
        cfg.CONF.set_override(
            'vni_ranges', ['1:1000'], group='ml2_type_vxlan')
        cfg.CONF.set_override(
            'mechanism_drivers', ['openvswitch'], group='ml2')
        super(NeutronDbPluginV2TestCase, self).setUp(
            ext_mgr=ext_mgr,
            plugin=plugin,
            service_plugins=service_plugins
        )
        self._tenant_id = uuidutils.generate_uuid()
        self._network = self._make_network(
            self.fmt, 'net1',
            True)
        self._subnet = self._make_subnet(
            self.fmt, self._network, gateway='10.0.0.1',
            cidr='10.0.0.0/24', ip_version=4
        )
        self._gateway = self._create_port(
            self.fmt, self._network['network']['id'],
            device_owner=nl_const.DEVICE_OWNER_ROUTER_INTF
        )

    def _mock_unnecessary_logging(self):
        mock_log_sg_rpc_p = mock.patch.object(sg_rpc, 'LOG')
        self.mock_log_sg_rpc = mock_log_sg_rpc_p.start()

        mock_log_api_ext_p = mock.patch.object(api_ext, 'LOG')
        self.mock_log_api_ext = mock_log_api_ext_p.start()

        mock_log_dhcp_rpc_log_p = mock.patch.object(dhcp_rpc_log, 'LOG')
        self.mock_log_dhcp_rpc_log = mock_log_dhcp_rpc_log_p.start()

        mock_log_dhcp_rpc_log_p = mock.patch.object(dhcp_rpc_log, 'LOG')
        self.mock_log_dhcp_rpc_log = mock_log_dhcp_rpc_log_p.start()

        mock_log_api_res_log_p = mock.patch.object(api_res_log, 'LOG')
        self.mock_log_api_res_log = mock_log_api_res_log_p.start()

        mock_log_cfg_p = mock.patch.object(cfg, 'LOG')
        self.mock_log_cfg = mock_log_cfg_p.start()

        mock_log_manager_p = mock.patch.object(manager, 'LOG')
        self.mock_log_manager = mock_log_manager_p.start()

        mock_log_nova_p = mock.patch.object(nova_log, 'LOG')
        self.mock_log_nova = mock_log_nova_p.start()

        mock_log_ml2_db_p = mock.patch.object(ml2_db, 'LOG')
        self.mock_log_ml2_db = mock_log_ml2_db_p.start()

        mock_log_ml2_manager_p = mock.patch.object(ml2_manager, 'LOG')
        self.mock_log_ml2_manager = mock_log_ml2_manager_p.start()

        mock_log_plugin_p = mock.patch.object(ml2_plugin, 'LOG')
        self.mock_log_plugin = mock_log_plugin_p.start()

        mock_log_type_flat_p = mock.patch.object(type_flat, 'LOG')
        self.mock_log_type_flat = mock_log_type_flat_p.start()

        mock_log_type_local_p = mock.patch.object(type_local, 'LOG')
        self.mock_log_type_local = mock_log_type_local_p.start()

        mock_log_type_tunnel_p = mock.patch.object(type_tunnel, 'LOG')
        self.mock_log_type_tunnel = mock_log_type_tunnel_p.start()

        mock_log_type_vlan_p = mock.patch.object(type_vlan, 'LOG')
        self.mock_log_type_vlan = mock_log_type_vlan_p.start()

        mock_log_quota_log_p = mock.patch.object(quota_log, 'LOG')
        self.mock_log_quota_log = mock_log_quota_log_p.start()

        mock_log_dhcp_agent_log_p = mock.patch.object(dhcp_agent_log, 'LOG')
        self.mock_log_dhcp_agent_log = mock_log_dhcp_agent_log_p.start()

    def tearDown(self):
        super(NeutronDbPluginV2TestCase, self).tearDown()

    @contextlib.contextmanager
    def port(self, fmt=None, **kwargs):
        net_id = self._network['network']['id']
        port = self._make_port(fmt or self.fmt, net_id, as_admin=True,
                               **kwargs)
        yield port
