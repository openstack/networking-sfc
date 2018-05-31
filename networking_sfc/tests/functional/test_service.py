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

import os
import os.path
import signal


from oslo_config import cfg

from neutron.common import utils
from neutron.tests.functional import test_server

from networking_sfc.services.flowclassifier.common import (  # noqa
    config as fc_config)  # noqa
from networking_sfc.services.sfc.common import (  # noqa
    config as sfc_config)  # noqa


class TestService(test_server.TestPluginWorker):
    def _fake_start(self):
        with open(self.temp_file, 'ab') as f:
            f.write(test_server.FAKE_START_MSG)

    def _test_restart_service_on_sighup(self, service, workers=1):
        self._start_server(callback=service, workers=workers)
        os.kill(self.service_pid, signal.SIGHUP)
        expected_msg = test_server.FAKE_START_MSG * workers * 2
        expected_size = len(expected_msg)

        utils.wait_until_true(
            lambda: (os.path.isfile(self.temp_file) and
                     os.stat(self.temp_file).st_size ==
                     expected_size),
            timeout=5, sleep=0.1,
            exception=RuntimeError(
                "Timed out waiting for file %(filename)s to be created and "
                "its size become equal to %(size)s." %
                {'filename': self.temp_file,
                 'size': expected_size}))
        with open(self.temp_file, 'rb') as f:
            res = f.readline()
            self.assertEqual(expected_msg, res)

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
