# Copyright 2016 Futurewei. All rights reserved.
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

from neutron.tests.functional import test_server

from networking_sfc.services.flowclassifier.common import (  # noqa
    config as fc_config)  # noqa
from networking_sfc.services.sfc.common import (  # noqa
    config as sfc_config)  # noqa


class TestService(test_server.TestPluginWorker):
    def test_start(self):
        cfg.CONF.set_override(
            'service_plugins', [
                'networking_sfc.services.flowclassifier.plugin.'
                'FlowClassifierPlugin',
                'networking_sfc.services.sfc.plugin.SfcPlugin'
            ]
        )
        cfg.CONF.set_override(
            'drivers', ['ovs'], group='flowclassifier'
        )
        cfg.CONF.set_override(
            'drivers', ['ovs'], group='sfc'
        )
        super(TestService, self).test_start()
