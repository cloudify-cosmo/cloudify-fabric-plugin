########
# Copyright (c) 2016 GigaSpaces Technologies Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

import os
import mock
from winrm.tests.conftest import protocol_fake

from winrm_plugin.tasks import (
    # run_script,
    run_commands
)

import testtools
from cloudify.workflows import local
from cloudify.state import current_ctx
from cloudify.mocks import MockCloudifyContext
from cloudify.exceptions import NonRecoverableError

UNAUTHORIZED_INPUTS = {}
BAD_POWERSHELL_COMMANDS = ['blahblahblah-blue', 'blebleh-bleh']
ADDRESS = 'localhost'
USERNAME = 'Admin'
PASSWORD = 'Secret'
WINRM_PORT = 5985
WINRM_PROTOCOL = 'http'
PROCESS = ['powershell', 'cmd']
IGNORED_LOCAL_WORKFLOW_MODULES = (
    'worker_installer.tasks',
    'plugin_installer.tasks',
    'cloudify_agent.operations',
    'cloudify_agent.installer.operations',
)


class TestWorkflow(testtools.TestCase):

    @mock.patch('winrm_plugin.tasks.get_conn', protocol_fake)
    def test_unauthorized_run_script(self):

        # TODO: rewrite the blueprints to work with cfy-local & not with AWS
        cfy_local = local.init_env(
            os.path.join('blueprint', 'winrm-script-blueprint.yaml'),
            name=self._testMethodName,
            inputs=UNAUTHORIZED_INPUTS,
            ignored_modules=IGNORED_LOCAL_WORKFLOW_MODULES)

        self.assertRaises(NonRecoverableError,
                          cfy_local.execute())

#### BETTER EXAMPLE THAN THE OTHER ONE
class TestCloudifyWinrmPlugin(testtools.TestCase):

    @property
    def get_mock_cloudify_context(self, test_name):
        return MockCloudifyContext(
            node_id=test_name,
            properties={},
            deployment_id='d1'
        )

    @mock.patch('winrm_plugin.tasks.get_conn', protocol_fake)
    @mock.patch('winrm.protocol.Protocol.run_command', winrm.exceptions.WinRMTransportError)
    def test_run_commands_bad_powershell_command(self):
        ctx = self.get_mock_context('test_run_commands_bad_powershell_command')
        current_ctx.set(ctx=ctx)
        operation_inputs = dict(
            commands=BAD_POWERSHELL_COMMANDS,
            address=ADDRESS,
            username=USERNAME,
            password=PASSWORD,
            process=PROCESS[0],
            winrm_port=WINRM_PORT,
            winrm_protocol=WINRM_PROTOCOL,
            ctx=ctx
        )
        self.assertRaises(run_commands(**operation_inputs), NonRecoverableError)
