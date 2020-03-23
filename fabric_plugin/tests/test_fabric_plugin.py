# Copyright (c) 2014-2020 Cloudify Platform Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import unittest

from invoke import Context
from mock import patch, MagicMock, Mock

from cloudify import ctx
from cloudify.workflows import local
from cloudify.decorators import workflow
from cloudify.endpoint import LocalEndpoint
from cloudify.workflows import ctx as workflow_ctx
from cloudify.exceptions import NonRecoverableError

from fabric_plugin import tasks


class BaseFabricPluginTest(unittest.TestCase):
    def setUp(self):
        self.default_fabric_env = {
            'host_string': 'test',
            'user': 'test',
            'key_filename': 'test',
        }
        self.bootstrap_context = {}
        LocalEndpoint.get_bootstrap_context = lambda _: self.bootstrap_context

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
                 use_sudo=False):

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
        }
        blueprint_path = os.path.join(os.path.dirname(__file__),
                                      'blueprint', 'blueprint.yaml')
        self.env = local.init_env(blueprint_path,
                                  name=self._testMethodName,
                                  inputs=inputs)

        self.conn = MockConnection()
        self.conn_factory = Mock(return_value=self.conn)
        with patch('fabric_plugin.tasks.Connection', self.conn_factory):
            result = self.env.execute('execute_operation',
                                      parameters={'operation': operation},
                                      task_retry_interval=0,
                                      task_retries=0)
        return result


class MockConnection(MagicMock, Context):
    def __init__(self, **kw):
        super(MockConnection, self).__init__()
        self.run = Mock()
        self.sudo = Mock()

    @property
    def cwd(self):
        return '/'


class FabricPluginTest(BaseFabricPluginTest):
    def _get_conn_kwargs(self):
        return self.conn_factory.mock_calls[-1].kwargs

    def test_missing_tasks_file(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "Could not get 'missing.py'"):
            self._execute('test.run_task', tasks_file='missing.py')

    def test_bad_tasks_file(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "ImportError: No module named module"):
            self._execute('test.run_task', tasks_file='corrupted_file.py')

    def test_missing_task(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "Could not find task 'missing'"):
            self._execute('test.run_task', task_name='missing')

    def test_non_callable_task(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "is not callable"):
            self._execute('test.run_task', task_name='non_callable')

    def test_missing_tasks_module(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "Could not load 'module_that"):
            self._execute('test.run_module_task',
                          task_mapping='module_that_does_not_exist.some_task')

    def test_missing_module_task_attribute(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "Could not find 'whoami' in fabric_"):
            self._execute(
                'test.run_module_task',
                task_mapping='fabric_plugin.tests.test_fabric_plugin.whoami')

    def test_non_callable_module_task(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "is not callable"):
            self._execute(
                'test.run_module_task',
                task_mapping='fabric_plugin.tests.'
                             'test_fabric_plugin.non_callable')

    def test_conn_kwargs(self):
        self._execute('test.run_task', task_name='task')
        kw = self._get_conn_kwargs()
        self.assertEqual(
            self.default_fabric_env['user'],
            kw['user']
        )
        self.assertEqual(
            self.default_fabric_env['key_filename'],
            kw['connect_kwargs']['key_filename']
        )
        self.assertEqual(
            self.default_fabric_env['host_string'],
            kw['host']
        )

    def test_run_task(self):
        self._execute('test.run_task', task_name='task')
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(instance.runtime_properties['task_called'], 'called')

    def test_run_module_task(self):
        self._execute(
            'test.run_module_task',
            task_mapping='fabric_plugin.tests.test_fabric_plugin.module_task')
        instance = self.env.storage.get_node_instances()[0]
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

        if use_sudo:
            mock_calls = self.conn.sudo.mock_calls
        else:
            mock_calls = self.conn.run.mock_calls

        mock_commands = [args[0] for c, args, kwargs in mock_calls]
        self.assertEqual(commands, mock_commands)

    def test_run_commands(self):
        self._test_run_commands()

    def test_run_sudo_commands(self):
        self._test_run_commands(use_sudo=True)

    def test_missing_user(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "ssh user definition missing"):
            self._execute('test.run_task',
                          task_name='task',
                          fabric_env={'password': 'test',
                                      'host_string': 'test'})

    def test_missing_key_or_password(self):
        with self.assertRaisesRegexp(NonRecoverableError,
                                     "key_filename/key or password"):
            self._execute('test.run_task',
                          task_name='task',
                          fabric_env={'user': 'test',
                                      'host_string': 'test'})

    def test_fabric_env_default_override(self):
        # first sanity for no override
        self._execute('test.run_task', task_name='task')
        kw = self._get_conn_kwargs()
        self.assertEqual(
            kw['connect_timeout'],
            tasks.FABRIC_ENV_DEFAULTS['connect_timeout'])

        # now override
        invocation_fabric_env = self.default_fabric_env.copy()
        invocation_fabric_env['connect_timeout'] = 1000000
        self._execute(
            'test.run_task',
            task_name='task',
            fabric_env=invocation_fabric_env)
        kw = self._get_conn_kwargs()
        self.assertEqual(kw['connect_timeout'], 1000000)

    def test_implicit_host_string(self):
        fabric_env = self.default_fabric_env.copy()
        del fabric_env['host_string']
        self._execute(
            'test.run_task',
            task_name='test_implicit_host_string',
            ip='1.1.1.1',
            fabric_env=fabric_env)
        kw = self._get_conn_kwargs()
        instance = self.env.storage.get_node_instances()[0]
        self.assertEqual(instance.runtime_properties['expected_host_string'],
                         kw['host'])

    def test_explicit_host_string(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['host_string'] = 'explicit_host_string'
        self._execute(
            'test.run_task',
            task_name='task',
            fabric_env=fabric_env)
        kw = self._get_conn_kwargs()
        self.assertEqual('explicit_host_string',
                         kw['host'])

    def test_explicit_password(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['password'] = 'explicit_password'
        self._execute(
            'test.run_task',
            task_name='task',
            fabric_env=fabric_env)
        kw = self._get_conn_kwargs()
        self.assertEqual('explicit_password',
                         kw['password'])

    def test_implicit_key_filename(self):
        fabric_env = self.default_fabric_env.copy()
        del fabric_env['key_filename']
        bootstrap_context = {
            'cloudify_agent': {
                'agent_key_path': 'implicit_key_filename'
            }
        }
        self._execute(
            'test.run_task',
            task_name='task',
            fabric_env=fabric_env,
            bootstrap_context=bootstrap_context)
        kw = self._get_conn_kwargs()
        self.assertEqual('implicit_key_filename',
                         kw['connect_kwargs']['key_filename'])

    def test_explicit_key_filename(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['key_filename'] = 'explicit_key_filename'
        self._execute(
            'test.run_task',
            task_name='task',
            fabric_env=fabric_env)
        kw = self._get_conn_kwargs()
        self.assertEqual('explicit_key_filename',
                         kw['connect_kwargs']['key_filename'])

    def test_explicit_key(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['key'] = 'explicit_key_content'
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        kw = self._get_conn_kwargs()
        self.assertEqual('explicit_key_content',
                         kw['connect_kwargs']['key'])

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
        kw = self._get_conn_kwargs()
        self.assertEqual('implicit_user', kw['user'])

    def test_explicit_user(self):
        fabric_env = self.default_fabric_env.copy()
        fabric_env['user'] = 'explicit_user'
        self._execute('test.run_task',
                      task_name='task',
                      fabric_env=fabric_env)
        kw = self._get_conn_kwargs()
        self.assertEqual('explicit_user', kw['user'])


@workflow
def execute_operation(operation, **kwargs):
    node = next(workflow_ctx.nodes)
    instance = next(node.instances)
    return instance.execute_operation(operation).get()


def module_task():
    ctx.instance.runtime_properties['task_called'] = 'called'


non_callable = 1
