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

from oslo_log import log as logging

from tempest import config
from tempest.lib import exceptions as lib_exc

from networking_sfc.tests.tempest_plugin.tests import flowclassifier_client
from networking_sfc.tests.tempest_plugin.tests.scenario import manager
from networking_sfc.tests.tempest_plugin.tests import sfc_client

CONF = config.CONF
LOG = logging.getLogger(__name__)


class SfcScenarioTest(
    flowclassifier_client.FlowClassifierClientMixin,
    sfc_client.SfcClientMixin,
    manager.NetworkScenarioTest
):
    def _check_connectivity(
        self, source_ip, destination_ip, routes=None,
        username=None, private_key=None
    ):
        msg = "ip address %r is reachable" % source_ip
        ok = self.ping_ip_address(source_ip, should_succeed=True)
        self.assertTrue(ok, msg=msg)
        client = self.get_remote_client(
            source_ip, username=username, private_key=private_key)
        cmd = 'traceroute -n -I %s' % destination_ip
        LOG.debug('exec command on %s: %s', source_ip, cmd)
        try:
            result = client.exec_command(cmd)
            LOG.debug(
                'traceroute from %s to %s:\n%s',
                source_ip, destination_ip, result)
            lines = result.split('\n')
            lines = [line for line in lines if line]
            lines = lines[1:-1]
            if len(lines) != len(routes):
                LOG.error('length mismatch:\n%s\nvs\n%s', lines, routes)
                self.assertEqual(len(lines), len(routes))
            for line, route_list in zip(lines, routes):
                found = any([route in line for route in route_list])
                if not found:
                    LOG.error('did not found any route %s in %s',
                              route_list, line)
                    self.assertTrue(found)
        except lib_exc.SSHExecCommandFailed as e:
            LOG.exception(e)
            raise
        except lib_exc.SSHTimeout as e:
            LOG.exception(e)
            raise
