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


class FabricPluginTest(unittest.TestCase):

    def setUp(self):
        key_filename = os.path.expanduser('~/.vagrant.d/insecure_private_key')
        inputs = {
            'fabric_env': {
                'host_string': '11.0.0.7',
                'user': 'vagrant',
                'key_filename': key_filename
            }
        }
        self.env = local.Environment(self._blueprint(),
                                     name=self._testMethodName,
                                     inputs=inputs)

    def _blueprint(self):
        return os.path.join(os.path.dirname(__file__),
                            'resources', 'blueprint.yaml')

    def _execute(self, workflow):
        self.env.execute(workflow,
                         task_retries=0)

    def test(self):
        self._execute('install')

