########
# Copyright (c) 2014 GigaSpaces Technologies Ltd. All rights reserved
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
import unittest
import contextlib
import errno

from cloudify.exceptions import NonRecoverableError
from cloudify.workflows import local
from cloudify.workflows import ctx as workflow_ctx
from cloudify.decorators import workflow
from cloudify.endpoint import LocalEndpoint

from fabric_plugin import tasks


class FabricPluginTest(unittest.TestCase):

    def test_missing_tasks_file(self):
        try:
            self._execute('test.run_task', tasks_file='missing.py')
            self.fail()
        except IOError, e:
            self.assertEqual(e.errno, errno.ENOENT)

    def test_bad_tasks_file(self):
        try:
            self._execute('test.run_task', tasks_file='corrupted_file.py')
            self.fail()
        except NonRecoverableError, e:
            self.assertIn("Could not load 'corrupted_file.py'", e.message)
            self.assertIn("ImportError: No module named module", e.message)

    def test_missing_task(self):
        try:
            self._execute('test.run_task', task_name='missing')
            self.fail()
        except NonRecoverableError, e:
            self.assertIn("Could not find task", e.message)
            self.assertIn('missing', e.message)
            self.assertIn('fabric_tasks.py', e.message)

    def test_non_callable_task(self):
        try:
            self._execute('test.run_task', task_name='non_callable')
            self.fail()
        except NonRecoverableError, e:
            self.assertIn('not callable', e.message)
            self.assertIn('non_callable', e.message)
            self.assertIn('fabric_tasks.py', e.message)

    def test_run_task(self):
        self._execute('test.run_task', task_name='task')
        instance = self.env.storage.get_node_instances()[0]
        self.assertDictContainsSubset(self.default_fabric_env,
                                      self.mock.settings_merged)
        self.assertIs(False, self.mock.settings_merged['warn_only'])
        self.assertEqual(instance.runtime_properties['task_called'], 'called')

    def test_run_commands(self):
        commands = ['command1', 'command2']
        self._execute('test.run_commands', commands=commands)
        self.assertDictContainsSubset(self.default_fabric_env,
                                      self.mock.settings_merged)
        self.assertIs(True, self.mock.settings_merged['warn_only'])
        self.assertListEqual(self.mock.commands, commands)

    def test_missing_user(self):
        try:
            self._execute('test.run_task',
                          task_name='task',
                          fabric_env={'password': 'test'})
            self.fail()
        except NonRecoverableError, e:
            self.assertEqual('ssh user definition missing', e.message)

    def test_missing_key_or_password(self):
        try:
            self._execute('test.run_task',
                          task_name='task',
                          fabric_env={'user': 'test'})
            self.fail()
        except NonRecoverableError, e:
            self.assertIn('key_filename or password', e.message)

    def test_fabric_env_default_override(self):
        # first sanity for no override
        self._execute('test.run_task',
                      task_name='task')
        self.assertEqual(self.mock.settings_merged['timeout'],
                         tasks.FABRIC_ENV_DEFAULTS['timeout'])
        # now override
        invocation_fabric_env = self.default_fabric_env.copy()
        invocation_fabric_env['timeout'] = 1000000
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=invocation_fabric_env)
        self.assertEqual(self.mock.settings_merged['timeout'], 1000000)

    def test_implicit_host_string(self):
        self._execute('test.run_task',
                      task_name='test_implicit_host_string')
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(instance.runtime_properties['expected_host_string'],
                         self.mock.settings_merged['host_string'])

    def test_explicit_host_string(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['host_string'] = 'explicit_host_string'
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        self.assertEqual('explicit_host_string',
                         self.mock.settings_merged['host_string'])

    def test_explicit_password(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['password'] = 'explicit_password'
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        self.assertEqual('explicit_password',
                         self.mock.settings_merged['password'])

    def test_implicit_key_filename(self):
        fabric_env = self.default_fabric_env.copy()
        del fabric_env['key_filename']
        bootstrap_context = {
            'cloudify_agent': {
                'agent_key_path': 'implicit_key_filename'
            }
        }
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env,
                      bootstrap_context=bootstrap_context)
        self.assertEqual('implicit_key_filename',
                         self.mock.settings_merged['key_filename'])

    def test_explicit_key_filename(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['key_filename'] = 'explicit_key_filename'
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        self.assertEqual('explicit_key_filename',
                         self.mock.settings_merged['key_filename'])

    def test_implicit_user(self):
        fabric_env = self.default_fabric_env.copy()
        del fabric_env['user']
        bootstrap_context = {
            'cloudify_agent': {
                'user': 'implicit_user'
            }
        }
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env,
                      bootstrap_context=bootstrap_context)
        self.assertEqual('implicit_user',
                         self.mock.settings_merged['user'])

    def test_explicit_user(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['user'] = 'explicit_user'
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        self.assertEqual('explicit_user',
                         self.mock.settings_merged['user'])

    def test_override_warn_only(self):
        fabric_env = self.default_fabric_env.copy()
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        self.assertIs(False, self.mock.settings_merged['warn_only'])
        fabric_env = self.default_fabric_env.copy()
        fabric_env['warn_only'] = True
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        self.assertIs(True, self.mock.settings_merged['warn_only'])

    def test_failed_command(self):
        commands = ['fail']
        try:
            self._execute('test.run_commands', commands=commands)
            self.fail()
        except tasks.FabricCommandError, e:
            self.assertEqual('mock_stdout', e.output)
            self.assertEqual('mock_stderr', e.error)
            self.assertEqual('mock_command', e.command)
            self.assertEqual(1, e.code)

    class MockCommandResult(object):

        def __init__(self, failed):
            self.failed = failed
            self.stdout = 'mock_stdout'
            self.stderr = 'mock_stderr'
            self.command = 'mock_command'
            self.return_code = 1

    class MockFabricApi(object):

        def __init__(self):
            self.commands = []
            self.settings_merged = {}

        @contextlib.contextmanager
        def settings(self, **kwargs):
            self.settings_merged.update(kwargs)
            yield

        def run(self, command):
            self.commands.append(command)
            return FabricPluginTest.MockCommandResult(command == 'fail')

    def setUp(self):
        self.default_fabric_env = {
            'user': 'test',
            'key_filename': 'test'
        }
        self.original_fabric_api = tasks.fabric_api
        self.original_bootstrap_context = LocalEndpoint.get_bootstrap_context
        self.mock = self.MockFabricApi()
        tasks.fabric_api = self.mock
        self.bootstrap_context = {}
        outer = self

        def mock_get_bootstrap_context(self):
            return outer.bootstrap_context
        LocalEndpoint.get_bootstrap_context = mock_get_bootstrap_context
        self.addCleanup(self.cleanup)

    def cleanup(self):
        tasks.fabric_api = self.original_fabric_api
        LocalEndpoint.get_bootstrap_context = self.original_bootstrap_context

    def _execute(self,
                 operation,
                 fabric_env=None,
                 task_name=None,
                 tasks_file=None,
                 commands=None,
                 bootstrap_context=None):

        bootstrap_context = bootstrap_context or {}
        self.bootstrap_context.update(bootstrap_context)

        inputs = {
            'fabric_env': fabric_env or self.default_fabric_env,
            'task_name': task_name or 'stub',
            'commands': commands or [],
            'tasks_file': tasks_file or 'fabric_tasks.py'
        }
        blueprint_path = os.path.join(os.path.dirname(__file__),
                                      'blueprint', 'blueprint.yaml')
        self.env = local.Environment(blueprint_path,
                                     name=self._testMethodName,
                                     inputs=inputs)
        self.env.execute('execute_operation',
                         parameters={'operation': operation},
                         task_retries=0)


@workflow
def execute_operation(operation, **kwargs):
    node = next(workflow_ctx.nodes)
    instance = next(node.instances)
    instance.execute_operation(operation)
