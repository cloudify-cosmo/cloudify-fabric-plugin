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
#
#
# class BaseWinrmPluginTest(BaseFabricPluginTest):
#
#
# class WinrmPluginTest(BaseWinrmPluginTest):

from winrm.tests import conftest
from winrm_plugin import tasks
# import pytest
import mock


def mock_protocol():
    return conftest.protocol_fake


@mock.patch('tasks.get_conn', new=mock_protocol())
def test_conn_and_shell():
    tasks.get_conn(None, None, None, None, None)


print test_conn_and_shell()
