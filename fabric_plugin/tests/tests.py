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
import sys
import json
import getpass
import unittest
import tempfile
import posixpath
import contextlib
from StringIO import StringIO
from collections import namedtuple

from mock import patch
from fabric import api
from fabric.contrib import files
from fabric import context_managers

from cloudify import ctx
from cloudify.workflows import local
from cloudify.decorators import workflow
from cloudify.endpoint import LocalEndpoint
from cloudify.workflows import ctx as workflow_ctx
from cloudify.exceptions import (NonRecoverableError,
                                 RecoverableError)

from fabric_plugin import tasks
from fabric_plugin.tasks import (ILLEGAL_CTX_OPERATION_ERROR,
                                 DEFAULT_BASE_SUBDIR)


def _mock_requests_get(url):
    from fabric_plugin.tests import blueprint
    path = url.split('http://localhost/')[1]
    basedir = os.path.dirname(blueprint.__file__)
    response = namedtuple('Response', 'text status_code')
    with open(os.path.join(basedir, path)) as f:
        response.text = f.read()
    return response


class TestException(Exception):
    pass


class BaseFabricPluginTest(unittest.TestCase):

    class MockCommandResult(str):

        def __init__(self, failed):
            str.__init__(self)
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
        def settings(self, *args, **kwargs):
            self.settings_merged.update(kwargs)
            if args:
                groups = args[0]
                self.settings_merged.update({'hide_output': groups})
            yield

        def run(self, command):
            self.commands.append(command)
            self.settings_merged['use_sudo'] = False
            return BaseFabricPluginTest.MockCommandResult(
                command == 'fail')

        def sudo(self, command):
            self.commands.append(command)
            self.settings_merged['use_sudo'] = True
            return BaseFabricPluginTest.MockCommandResult(
                command == 'fail')

        def hide(self, *groups):
            return groups

        def exists(self, path):
            """Allows to return the settings in the `run_script`
            execution method.

            The first thing we do in the `run_script` function
            is check if a path exists. Since we can't really
            execute it as it requires a host, this will return
            the settings for us to check.
            """
            raise TestException(self.settings_merged)

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
                 custom_input='value',
                 use_sudo=False,
                 hide_output=None):

        bootstrap_context = bootstrap_context or {}
        self.bootstrap_context.update(bootstrap_context)

        inputs = {
            'fabric_env': fabric_env or self.default_fabric_env,
            'task_name': task_name or 'stub',
            'commands': commands or [],
            'use_sudo': use_sudo,
            'tasks_file': tasks_file or 'fabric_tasks.py',
            'task_properties': task_properties or {},
            'task_mapping': task_mapping or '',
            'ip': ip or '',
            'script_path': script_path or '',
            'process': process or {},
            'custom_input': custom_input,
            'hide_output': hide_output or ()
        }
        blueprint_path = os.path.join(os.path.dirname(__file__),
                                      'blueprint', 'blueprint.yaml')
        self.env = local.init_env(blueprint_path,
                                  name=self._testMethodName,
                                  inputs=inputs)
        result = self.env.execute('execute_operation',
                                  parameters={'operation': operation},
                                  task_retry_interval=0,
                                  task_retries=0)
        return result, self.env


class FabricPluginTest(BaseFabricPluginTest):

    def test_missing_tasks_file(self):
        try:
            self._execute('test.run_task', tasks_file='missing.py')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not get 'missing.py'", str(e))

    def test_bad_tasks_file(self):
        try:
            self._execute('test.run_task', tasks_file='corrupted_file.py')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not load 'corrupted_file.py'", str(e))
            self.assertIn("ImportError: No module named module", str(e))

    def test_missing_task(self):
        try:
            self._execute('test.run_task', task_name='missing')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not find task", str(e))
            self.assertIn('missing', str(e))
            self.assertIn('fabric_tasks.py', str(e))

    def test_non_callable_task(self):
        try:
            self._execute('test.run_task', task_name='non_callable')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn('not callable', str(e))
            self.assertIn('non_callable', str(e))
            self.assertIn('fabric_tasks.py', str(e))

    def test_missing_tasks_module(self):
        try:
            self._execute('test.run_module_task',
                          task_mapping='module_that_does_not_exist.some_task')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not load 'module_that", str(e))

    def test_missing_module_task_attribute(self):
        try:
            self._execute('test.run_module_task',
                          task_mapping='fabric_plugin.tests.tests.whoami')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("Could not find 'whoami' in fabric_", str(e))

    def test_non_callable_module_task(self):
        try:
            self._execute(
                'test.run_module_task',
                task_mapping='fabric_plugin.tests.tests.non_callable')
            self.fail()
        except NonRecoverableError as e:
            self.assertIn("'non_callable' in 'fabric_", str(e))
            self.assertIn('not callable', str(e))

    def test_run_task(self):
        self._execute('test.run_task', task_name='task')
        instance = self.env.storage.get_node_instances()[0]
        self.assertDictContainsSubset(self.default_fabric_env,
                                      self.mock.settings_merged)
        self.assertFalse(self.mock.settings_merged['warn_only'])
        self.assertEqual(instance.runtime_properties['task_called'], 'called')

    def test_run_module_task(self):
        self._execute('test.run_module_task',
                      task_mapping='fabric_plugin.tests.tests.module_task')
        instance = self.env.storage.get_node_instances()[0]
        self.assertDictContainsSubset(self.default_fabric_env,
                                      self.mock.settings_merged)
        self.assertFalse(self.mock.settings_merged['warn_only'])
        self.assertEqual(instance.runtime_properties['task_called'], 'called')

    def test_task_properties(self):
        self._execute('test.run_task', task_name='test_task_properties',
                      task_properties={'arg': 'value'})
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(instance.runtime_properties['arg'], 'value')

    def _test_run_commands(self, use_sudo=False):
        commands = ['command1', 'command2']
        self._execute(
            'test.run_commands',
            commands=commands,
            use_sudo=use_sudo)
        self.assertDictContainsSubset(self.default_fabric_env,
                                      self.mock.settings_merged)
        self.assertTrue(self.mock.settings_merged['warn_only'])
        self.assertIs(use_sudo, self.mock.settings_merged['use_sudo'])
        self.assertListEqual(self.mock.commands, commands)

    def test_run_commands(self):
        self._test_run_commands()

    def test_run_sudo_commands(self):
        self._test_run_commands(use_sudo=True)

    def test_missing_user(self):
        try:
            self._execute('test.run_task',
                          task_name='task',
                          fabric_env={'password': 'test',
                                      'host_string': 'test'})
            self.fail()
        except NonRecoverableError as e:
            self.assertEqual('ssh user definition missing', str(e))

    def test_missing_key_or_password(self):
        try:
            self._execute('test.run_task',
                          task_name='task',
                          fabric_env={'user': 'test',
                                      'host_string': 'test'})
            self.fail()
        except NonRecoverableError as e:
            self.assertIn('key_filename/key or password', str(e))

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

    def test_explicit_key(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['key'] = 'explicit_key_content'
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        self.assertEqual('explicit_key_content',
                         self.mock.settings_merged['key'])

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
        self.assertFalse(self.mock.settings_merged['warn_only'])
        fabric_env = self.default_fabric_env.copy()
        fabric_env['warn_only'] = True
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        self.assertTrue(self.mock.settings_merged['warn_only'])

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

    def test_hide_viable_groups(self):
        groups = ('running', 'stdout')
        hide_func = tasks._hide_output(groups)
        self.assertEqual(hide_func, groups)

    def _test_hide_in_settings(self, execution_method, **kwargs):
        groups = ('running', 'stdout')
        self._execute(
            'test.{0}'.format(execution_method),
            hide_output=groups,
            **kwargs)
        self.assertDictContainsSubset(
            {'hide_output': groups},
            self.mock.settings_merged)

    def _test_hide_non_viable_groups(self, execution_method, **kwargs):
        try:
            self._execute(
                'test.{0}'.format(execution_method),
                hide_output=('running', 'bla'),
                **kwargs)
            self.fail()
        except NonRecoverableError as ex:
            self.assertIn('`hide_output` must be a subset of', str(ex))

    def test_hide_in_settings_and_non_viable_groups_in_commands(self):
        self._test_hide_in_settings(
            execution_method='run_commands')
        self._test_hide_non_viable_groups(
            execution_method='run_commands')

    def test_hide_in_settings_and_non_viable_groups_in_task(self):
        self._test_hide_in_settings(
            execution_method='run_task',
            task_name='task')
        self._test_hide_non_viable_groups(
            execution_method='run_task',
            task_name='task')

    def test_hide_in_settings_and_non_viable_groups_in_module(self):
        self._test_hide_in_settings(
            execution_method='run_module_task',
            task_mapping='fabric_plugin.tests.tests.module_task')
        self._test_hide_non_viable_groups(
            execution_method='run_module_task',
            task_mapping='fabric_plugin.tests.tests.module_task')

    def test_hide_in_settings_and_non_viable_groups_in_script(self):
        original_fabric_files = tasks.fabric_files
        tasks.fabric_files = self.mock
        try:
            self._test_hide_in_settings(
                execution_method='run_script',
                script_path='scripts/script.py')
            self.fail()
        except TestException as ex:
            self.assertIn("'hide_output': ('running', 'stdout')", str(ex))
        finally:
            tasks.fabric_files = original_fabric_files

        self._test_hide_non_viable_groups(
            execution_method='run_script',
            script_path='scripts/script.sh')


class FabricPluginRealSSHTests(BaseFabricPluginTest):

    def setUp(self):
        self.CUSTOM_BASE_DIR = '/tmp/new-tmp'
        user = getpass.getuser()
        if user != 'ubuntu':
            raise unittest.SkipTest()

        super(FabricPluginRealSSHTests, self).setUp()
        user = getpass.getuser()
        if user == 'ubuntu':
            self.default_fabric_env = {
                'host_string': 'localhost',
                'user': 'ubuntu',
                'key_filename': '/home/ubuntu/.ssh/build_key.rsa'
            }

        tasks.fabric_api = self.original_fabric_api
        with context_managers.settings(**self.default_fabric_env):
            if files.exists(DEFAULT_BASE_SUBDIR):
                api.run('rm -rf {0}'.format(DEFAULT_BASE_SUBDIR))
            if files.exists(self.CUSTOM_BASE_DIR):
                api.run('rm -rf {0}'.format(self.CUSTOM_BASE_DIR))

    def test_run_script_with_hide(self):

        def execute_script(hide_groups=None):
            hide_groups = hide_groups or []
            try:
                previous_stdout = sys.stdout
                current_stdout = StringIO()
                sys.stdout = current_stdout
                self._execute(
                    'test.run_script',
                    script_path='scripts/script.sh',
                    process={
                        'env': {
                            'test_operation': self._testMethodName,
                        },
                    },
                    hide_output=hide_groups)
                output = current_stdout.getvalue().strip()
            finally:
                sys.stdout = previous_stdout
            return output

        expected_log_message = \
            '[localhost] run: source /tmp/cloudify-ctx/scripts/'

        output = execute_script()
        self.assertIn(expected_log_message, output)

        output = execute_script(hide_groups=['everything'])
        self.assertNotIn(expected_log_message, output)

    def _test_run_script(self, script_path):
        expected_runtime_property_value = 'some_value'
        _, env = self._execute(
            'test.run_script',
            script_path=script_path,
            process={
                'env': {
                    'test_operation': self._testMethodName,
                    'test_value': expected_runtime_property_value,
                },
            })
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(expected_runtime_property_value,
                         instance.runtime_properties['test_value'])

    def test_run_python_script(self):
        self._test_run_script('scripts/script.py')

    def test_nested_property(self):
        self._test_run_script('scripts/script.py')

    def test_run_script(self):
        self._test_run_script('scripts/script.sh')

    @patch('fabric_plugin.tasks.requests.get', _mock_requests_get)
    def test_run_script_from_url(self):
        self._test_run_script('http://localhost/scripts/script.sh')

    def test_run_script_as_sudo(self):
        self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            use_sudo=True,
            process={
                'env': {
                    'test_operation': self._testMethodName,
                },
            })
        with context_managers.settings(**self.default_fabric_env):
            self.assertTrue(files.exists('/opt/test_dir'))
            api.sudo('rm -rf /opt/test_dir')

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
        self.assertEqual(posixpath.join(tempfile.gettempdir(),
                                        DEFAULT_BASE_SUBDIR,
                                        'work'),
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
        self.assertEqual(
            posixpath.join(expected_base_dir, DEFAULT_BASE_SUBDIR, 'ctx'),
            instance.runtime_properties['ctx_path']
        )

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
                'command_prefix': 'bash'
            },
        )
        self.assertEqual(return_value, expected_return_value)

    def test_imported_ctx_retry_operation(self):
        from datetime import datetime
        error_msg = 'oops_try_again!'
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        output_file_path = \
            '/tmp/{0}-{1}.log'.format(self._testMethodName, timestamp)
        try:
            self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                process={
                    'env': {
                        'test_operation': self._testMethodName,
                        'error_msg': error_msg,
                        'output_file': output_file_path
                    }
                })
            self.fail('expected to raise an exception')
        except RecoverableError as e:
            self.assertEquals(error_msg, str(e))
            # verify that ctx outputs error message to stderr
            _, output_local_copy_path = tempfile.mkstemp()
            with context_managers.settings(**self.default_fabric_env):
                api.get(remote_path=output_file_path,
                        local_path=output_local_copy_path)
                with open(output_local_copy_path, 'r') as output_file:
                    self.assertEquals(error_msg, output_file.read().strip())

    def test_imported_ctx_abort_operation(self):
        from datetime import datetime
        error_msg = 'a_terrible_error_abortion!'
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        output_file_path = \
            '/tmp/{0}-{1}.log'.format(self._testMethodName, timestamp)
        try:
            self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                process={
                    'env': {
                        'test_operation': self._testMethodName,
                        'error_msg': error_msg,
                        'output_file': output_file_path
                    }
                })
            self.fail('expected to raise an exception')
        except NonRecoverableError as e:
            self.assertEquals(error_msg, str(e))
            # verify that ctx outputs error message to stderr
            _, output_local_copy_path = tempfile.mkstemp()
            with context_managers.settings(**self.default_fabric_env):
                api.get(remote_path=output_file_path,
                        local_path=output_local_copy_path)
                with open(output_local_copy_path, 'r') as output_file:
                    self.assertEquals(error_msg, output_file.read().strip())

    def test_crash_abort_after_return(self):
        try:
            self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                process={
                    'env': {
                        'test_operation': self._testMethodName,
                        'return_value': 'some_value'
                    }
                })
        except NonRecoverableError as e:
            self.assertEquals(str(ILLEGAL_CTX_OPERATION_ERROR), str(e))

    def test_crash_return_after_abort(self):
        error_msg = 'oops_we_got_an_error'
        try:
            self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                process={
                    'env': {
                        'test_operation': self._testMethodName,
                        'error_msg': error_msg
                    }
                })
            self.fail('expected to raise an exception')
        except NonRecoverableError as e:
            self.assertEquals(str(ILLEGAL_CTX_OPERATION_ERROR), str(e))

    def test_run_script_abort(self):
        error_msg = 'oops_we_got_an_error'
        try:
            self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                process={
                    'env': {
                        'test_operation': self._testMethodName,
                        'error_msg': error_msg
                    },
                })
            self.fail('expected to raise an exception')
        except NonRecoverableError as e:
            self.assertEquals(error_msg, str(e))

    def test_abort_returns_nonzero_exit_code(self):
        from datetime import datetime
        error_msg = 'oops_we_got_an_error'
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        output_file_path = \
            '/tmp/{0}-{1}.log'.format(self._testMethodName, timestamp)
        try:
            self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                process={
                    'env': {
                        'test_operation': self._testMethodName,
                        'error_msg': error_msg,
                        'output_file': output_file_path
                    }
                })
            self.fail('expected to raise an exception')
        except NonRecoverableError as e:
            self.assertEquals(error_msg, str(e))
            # verify that ctx outputs error message to stderr
            _, output_local_copy_path = tempfile.mkstemp()
            with context_managers.settings(**self.default_fabric_env):
                api.get(remote_path=output_file_path,
                        local_path=output_local_copy_path)
                with open(output_local_copy_path, 'r') as output_file:
                    self.assertEquals(error_msg, output_file.read().strip())

    def test_abort_and_script_exits_elsewhere_with_nonzero_exit_code(self):
        error_msg = 'oops_we_got_an_error'
        try:
            self._execute(
                'test.run_script',
                script_path='scripts/script.sh',
                process={
                    'env': {
                        'test_operation': self._testMethodName,
                        'error_msg': error_msg
                    }
                })
            self.fail('expected to raise an exception')
        except NonRecoverableError as e:
            self.assertEquals(error_msg, str(e))

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

    def test_run_script_download_resource_and_render(self):
        return_value, _ = self._execute(
            'test.run_script',
            script_path='scripts/script.sh',
            process={
                'env': {
                    'test_operation': self._testMethodName
                }
            })
        self.assertEqual(return_value, 'test')

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
