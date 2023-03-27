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
import re
import pathlib
from setuptools import setup


def read(rel_path):
    here = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(here, rel_path), 'r') as fp:
        return fp.read()


def get_version():
    current_dir = pathlib.Path(__file__).parent.resolve()
    with open(os.path.join(current_dir, 'fabric_plugin/__version__.py'),
              'r') as outfile:
        var = outfile.read()
        return re.search(r'\d+.\d+.\d+', var).group()


setup(
    name='cloudify-fabric-plugin',
    version=get_version(),
    author='Cloudify',
    author_email='hello@cloudify.co',
    packages=['fabric_plugin'],
    license='LICENSE',
    description='Plugin for remotely running fabric tasks and commands',
    install_requires=[
        'cloudify-common>=4.5.5',
        'fabric2==2.5.0',
    ]
)
