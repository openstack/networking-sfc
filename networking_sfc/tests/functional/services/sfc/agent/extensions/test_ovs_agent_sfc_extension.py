# Copyright (c) 2016 Red Hat, Inc.
# All Rights Reserved.
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

from neutron.tests.functional.agent.l2 import base


class TestOVSAgentSfcExtension(base.OVSAgentTestFramework):
    def setUp(self):
        super(TestOVSAgentSfcExtension, self).setUp()
        self.config.set_override('extensions', ['sfc'], 'agent')
        self.agent = self.create_agent()

    def test_run(self):
        self.agent._report_state()
        agent_state = self.agent.state_rpc.report_state.call_args[0][1]
        self.assertEqual(['sfc'], agent_state['configurations']['extensions'])
