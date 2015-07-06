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

import json
import os
import unittest
import contextlib
import getpass
from mock import patch
from collections import namedtuple

from fabric import api
from fabric.contrib import files
from fabric import context_managers

from cloudify.exceptions import NonRecoverableError
from cloudify.workflows import local
from cloudify.workflows import ctx as workflow_ctx
from cloudify.decorators import workflow
from cloudify.endpoint import LocalEndpoint

from fabric_plugin import tasks
from cloudify import ctx


def _mock_requests_get(url):
    from fabric_plugin.tests import blueprint
    path = url.split('http://localhost/')[1]
    basedir = os.path.dirname(blueprint.__file__)
    response = namedtuple('Response', 'text status_code')
    with open(os.path.join(basedir, path)) as f:
        response.text = f.read()
    return response


class BaseFabricPluginTest(unittest.TestCase):

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
            return BaseFabricPluginTest.MockCommandResult(command == 'fail')

    def setUp(self):
        self.default_fabric_env = {
            'host_string': 'test',
            'user': 'test',
            'key_filename': 'test',
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
                 task_properties=None,
                 task_mapping=None,
                 commands=None,
                 bootstrap_context=None,
                 script_path=None,
                 process=None,
                 ip=None,
                 custom_input='value'):

        bootstrap_context = bootstrap_context or {}
        self.bootstrap_context.update(bootstrap_context)

        inputs = {
            'fabric_env': fabric_env or self.default_fabric_env,
            'task_name': task_name or 'stub',
            'commands': commands or [],
            'tasks_file': tasks_file or 'fabric_tasks.py',
            'task_properties': task_properties or {},
            'task_mapping': task_mapping or '',
            'ip': ip or '',
            'script_path': script_path or '',
            'process': process or {},
            'custom_input': custom_input
        }
        blueprint_path = os.path.join(os.path.dirname(__file__),
                                      'blueprint', 'blueprint.yaml')
        self.env = local.init_env(blueprint_path,
                                  name=self._testMethodName,
                                  inputs=inputs)
        result = self.env.execute('execute_operation',
                                  parameters={'operation': operation},
                                  task_retries=0)
        return result, self.env


class FabricPluginTest(BaseFabricPluginTest):

    def test_missing_tasks_file(self):
        try:
            self._execute('test.run_task', tasks_file='missing.py')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not get 'missing.py'", e.message)

    def test_bad_tasks_file(self):
        try:
            self._execute('test.run_task', tasks_file='corrupted_file.py')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not load 'corrupted_file.py'", e.message)
            self.assertIn("ImportError: No module named module", e.message)

    def test_missing_task(self):
        try:
            self._execute('test.run_task', task_name='missing')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not find task", e.message)
            self.assertIn('missing', e.message)
            self.assertIn('fabric_tasks.py', e.message)

    def test_non_callable_task(self):
        try:
            self._execute('test.run_task', task_name='non_callable')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn('not callable', e.message)
            self.assertIn('non_callable', e.message)
            self.assertIn('fabric_tasks.py', e.message)

    def test_missing_tasks_module(self):
        try:
            self._execute('test.run_module_task',
                          task_mapping='module_that_does_not_exist.some_task')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not load 'module_that", e.message)

    def test_missing_module_task_attribute(self):
        try:
            self._execute('test.run_module_task',
                          task_mapping='fabric_plugin.tests.tests.whoami')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not find 'whoami' in fabric_", e.message)

    def test_non_callable_module_task(self):
        try:
            self._execute(
                'test.run_module_task',
                task_mapping='fabric_plugin.tests.tests.non_callable')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("'non_callable' in 'fabric_", e.message)
            self.assertIn('not callable', e.message)

    def test_run_task(self):
        self._execute('test.run_task', task_name='task')
        instance = self.env.storage.get_node_instances()[0]
        self.assertDictContainsSubset(self.default_fabric_env,
                                      self.mock.settings_merged)
        self.assertIs(False, self.mock.settings_merged['warn_only'])
        self.assertEqual(instance.runtime_properties['task_called'], 'called')

    def test_run_module_task(self):
        self._execute('test.run_module_task',
                      task_mapping='fabric_plugin.tests.tests.module_task')
        instance = self.env.storage.get_node_instances()[0]
        self.assertDictContainsSubset(self.default_fabric_env,
                                      self.mock.settings_merged)
        self.assertIs(False, self.mock.settings_merged['warn_only'])
        self.assertEqual(instance.runtime_properties['task_called'], 'called')

    def test_task_properties(self):
        self._execute('test.run_task', task_name='test_task_properties',
                      task_properties={'arg': 'value'})
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(instance.runtime_properties['arg'], 'value')

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
                          fabric_env={'password': 'test',
                                      'host_string': 'test'})
            self.fail()
        except NonRecoverableError as e:
            self.assertEqual('ssh user definition missing', e.message)

    def test_missing_key_or_password(self):
        try:
            self._execute('test.run_task',
                          task_name='task',
                          fabric_env={'user': 'test',
                                      'host_string': 'test'})
            self.fail()
        except NonRecoverableError as e:
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
        fabric_env = self.default_fabric_env.copy()
        del fabric_env['host_string']
        self._execute('test.run_task',
                      task_name='test_implicit_host_string',
                      ip='1.1.1.1',
                      fabric_env=fabric_env)
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

    def test_env_var_key_filename(self):
        with patch.dict(os.environ, {
                tasks.CLOUDIFY_MANAGER_PRIVATE_KEY_PATH: 'env_key_filename'}):
            self._execute('test.run_task',
                          task_name='task')
        self.assertEqual('env_key_filename',
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
        except tasks.FabricCommandError as e:
            self.assertEqual('mock_stdout', e.output)
            self.assertEqual('mock_stderr', e.error)
            self.assertEqual('mock_command', e.command)
            self.assertEqual(1, e.code)


class FabricPluginRealSSHTests(BaseFabricPluginTest):

    def setUp(self):
        self.CUSTOM_BASE_DIR = '/tmp/new-cloudify-ctx'
        if getpass.getuser() != 'travis':
            raise unittest.SkipTest()

        super(FabricPluginRealSSHTests, self).setUp()
        self.default_fabric_env = {
            'host_string': 'localhost',
            'user': 'travis',
            'password': 'travis'
        }
        tasks.fabric_api = self.original_fabric_api
        with context_managers.settings(**self.default_fabric_env):
            if files.exists(tasks.DEFAULT_BASE_DIR):
                api.run('rm -rf {0}'.format(tasks.DEFAULT_BASE_DIR))
            if files.exists(self.CUSTOM_BASE_DIR):
                api.run('rm -rf {0}'.format(self.CUSTOM_BASE_DIR))

    def test_run_script(self):
        expected_runtime_property_value = 'some_value'
        _, env = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName,
                    'test_value': expected_runtime_property_value
                },
            })
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(expected_runtime_property_value,
                         instance.runtime_properties['test_value'])

    @patch('fabric_plugin.tasks.requests.get', _mock_requests_get)
    def test_run_script_from_url(self):
        expected_runtime_property_value = 'some_value'
        _, env = self._execute(
            'test.run_script',
            script_path='http://localhost/scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName,
                    'test_value': expected_runtime_property_value
                }})
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(expected_runtime_property_value,
                         instance.runtime_properties['test_value'])

    def test_run_script_default_base_dir(self):
        _, env = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName,
                },
            })
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual('{0}/work'.format(tasks.DEFAULT_BASE_DIR),
                         instance.runtime_properties['work_dir'])

    def test_run_script_process_config(self):
        expected_env_value = 'test_value_env'
        expected_arg1_value = 'test_value_arg1'
        expected_arg2_value = 'test_value_arg2'
        expected_cwd = '/tmp'
        expected_base_dir = self.CUSTOM_BASE_DIR

        _, env = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName,
                    'test_value_env': expected_env_value
                },
                'args': [expected_arg1_value, expected_arg2_value],
                'cwd': expected_cwd,
                'base_dir': expected_base_dir
            })
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(expected_env_value,
                         instance.runtime_properties['env_value'])
        self.assertTrue(len(instance.runtime_properties['bash_version']) > 0)
        self.assertEqual(expected_arg1_value,
                         instance.runtime_properties['arg1_value'])
        self.assertEqual(expected_arg2_value,
                         instance.runtime_properties['arg2_value'])
        self.assertEqual(expected_cwd,
                         instance.runtime_properties['cwd'])
        self.assertEqual('{0}/ctx'.format(expected_base_dir),
                         instance.runtime_properties['ctx_path'])

    def test_run_script_command_prefix(self):
        _, env = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName,
                },
                'command_prefix': 'dash'
            })
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(len(instance.runtime_properties['bash_version']), 0)
        self.assertEqual('sanity', instance.runtime_properties['sanity'])

    def test_run_script_reuse_existing_ctx(self):
        expected_test_value_1 = 'test_value_1'
        expected_test_value_2 = 'test_value_2'
        _, env = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': '{0}_1'.format(self._testMethodName),
                    'test_value': expected_test_value_1
                },
            })
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(expected_test_value_1,
                         instance.runtime_properties['test_value'])
        _, env = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': '{0}_2'.format(self._testMethodName),
                    'test_value': expected_test_value_2
                },
            })
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(expected_test_value_2,
                         instance.runtime_properties['test_value'])

    def test_run_script_return_value(self):
        expected_return_value = 'expected_return_value'
        return_value, _ = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName,
                    'return_value': expected_return_value
                },
                'command_prefix': 'dash'
            })
        self.assertEqual(return_value, expected_return_value)

    def test_run_script_ctx_server_port(self):
        from cloudify.proxy import server
        expected_port = server.get_unused_port()
        return_value, _ = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName
                },
                'ctx_server_port': expected_port
            })
        self.assertIn(':{0}'.format(expected_port), return_value)

    def test_run_script_download_resource(self):
        return_value, _ = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName
                }
            })
        self.assertEqual(return_value, 'content')

    def test_run_script_inputs_as_env_variables(self):
        def test(value):
            return_value, _ = self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                custom_input=value,
                process={
                    'env': {
                        'test_operation': self._testMethodName
                    }
                })
            self.assertEqual(return_value if isinstance(value, basestring)
                             else json.loads(return_value), value)
        test('string-value')
        test([1, 2, 3])
        test({'key': 'value'})

    def test_run_script_inputs_as_env_variables_process_env_override(self):
        def test_override(value):
            return_value, _ = self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                custom_input='custom-input-value',
                process={
                    'env': {
                        'test_operation': self._testMethodName,
                        'custom_env_var': value
                    }
                })
            self.assertEqual(return_value if isinstance(value, basestring)
                             else json.loads(return_value), value)
        test_override('string-value')
        test_override([1, 2, 3])
        test_override({'key': 'value'})


@workflow
def execute_operation(operation, **kwargs):
    node = next(workflow_ctx.nodes)
    instance = next(node.instances)
    return instance.execute_operation(operation).get()


def module_task():
    ctx.instance.runtime_properties['task_called'] = 'called'

non_callable = 1
