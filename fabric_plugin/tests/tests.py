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

from cloudify.workflows import local
from cloudify.workflows import ctx as workflow_ctx
from cloudify.decorators import workflow


class FabricPluginTest(unittest.TestCase):

    def test_run_task(self):
        self._execute('test.run_task', task_name='task')

    def test_run_commands(self):
        self._execute('test.run_commands', commands=['ls /'])

    def _execute(self,
                 operation,
                 task_name=None,
                 tasks_file=None,
                 commands=None):
        key_filename = os.path.expanduser('~/.vagrant.d/insecure_private_key')
        inputs = {
            'fabric_env': {
                'host_string': '11.0.0.7',
                'user': 'vagrant',
                'key_filename': key_filename
            },
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
