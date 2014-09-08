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


import sys
import os
import importlib

from fabric import api

from cloudify.decorators import operation
from cloudify.exceptions import NonRecoverableError
from cloudify import ctx


FABRIC_ENV_DEFAULTS = {
    'warn_only': True,
    'connection_attempts': 5,
    'timeout': 10,
    'forward_agent': True,
    'abort_on_prompts': False,
    'keepalive': 0,
    'linewise': False,
    'pool_size': 0,
    'skip_bad_hosts': False,
    'status': False,
    'disable_known_hosts': False
}


@operation
def run_task(tasks_file, task_name, fabric_env, **kwargs):
    """runs the specified fabric task loaded from 'tasks_file'

    :param tasks_file: the tasks file
    :param task_name: the task name to run in 'tasks_file'
    :param fabric_env: fabric configuration
    """
    task = _get_task(ctx, tasks_file, task_name)
    ctx.logger.info('running task: {0} from {1}'.format(task_name, tasks_file))
    with api.settings(**_fabric_env(ctx, fabric_env)):
        task(ctx)


def _get_task(_ctx, tasks_file, task_name):
    tasks_file = _ctx.download_resource(tasks_file)
    _ctx.logger.debug('importing tasks file...')
    sys.path.append(os.path.dirname(tasks_file))
    try:
        module = importlib.import_module(os.path.basename(
            os.path.splitext(os.path.join(tasks_file))[0]))
    except ImportError, e:
        raise NonRecoverableError(
            'Could not import {0} ({1})'.format(tasks_file, e.message))
    finally:
        sys.path.remove(os.path.dirname(tasks_file))

    try:
        task = getattr(module, task_name)
    except AttributeError, e:
        raise NonRecoverableError(
            'Could not get task {0} from {1} ({2})'
            .format(task_name, tasks_file, e.message))
    return task


class CredentialsHandler():
    """handler to easily retrieve credentials info"""
    def __init__(self, _ctx, fabric_env):
        self.ctx = _ctx
        self.fabric_env = fabric_env
        self.logger = self.ctx.logger

    @property
    def user(self):
        """returns the ssh user to use when connecting to the remote host"""
        self.logger.debug('retrieving ssh user...')
        if 'user' not in self.fabric_env:
            if self.ctx.bootstrap_context.cloudify_agent.user:
                user = self.ctx.bootstrap_context.cloudify_agent.user
            else:
                self.logger.error('no user configured for ssh connections')
                raise NonRecoverableError('ssh user definition missing')
        else:
            user = self.fabric_env['user']
        self.logger.debug('ssh user is: {0}'.format(user))
        return user

    @property
    def key_filename(self):
        """returns the ssh key to use when connecting to the remote host"""
        self.logger.debug('retrieving ssh key...')
        if 'key_filename' not in self.fabric_env:
            if self.ctx.bootstrap_context.cloudify_agent.agent_key_path:
                key = self.ctx.bootstrap_context.cloudify_agent.agent_key_path
            else:
                self.logger.debug('ssh key path not configured')
                return None
        else:
            key = self.fabric_env['key_filename']
        self.logger.debug('ssh key path is: {0}'.format(key))
        return key

    @property
    def password(self):
        """returns the ssh pwd to use when connecting to the remote host"""
        self.logger.debug('retrieving ssh password...')
        if 'password' in self.fabric_env:
            pwd = self.fabric_env['password']
        else:
            self.logger.debug('ssh password not configured')
            return None
        self.logger.debug('ssh pwd is: {0}'.format(pwd))
        return pwd

    @property
    def host_string(self):
        self.logger.debug('retrieving host string...')
        if 'host_string' in self.fabric_env:
            host_string = self.fabric_env['host_string']
        else:
            host_string = self.ctx.host_ip
        self.logger.debug('ssh host_string is: {0}'.format(host_string))
        return host_string


def _fabric_env(_ctx, fabric_env):
    """prepares fabric environment variables configuration

    :param _ctx: CloudifyContext instance
    :param fabric_env: fabric configuration
    """
    _ctx.logger.info('preparing fabric environment...')
    credentials = CredentialsHandler(_ctx, fabric_env)
    final_env = {}
    final_env.update(FABRIC_ENV_DEFAULTS)
    final_env.update(fabric_env)
    final_env.update({
        'host_string': credentials.host_string,
        'user': credentials.user,
        'key_filename': credentials.key_filename,
        'password': credentials.password
    })
    # validations
    if not (final_env.get('password') or final_env.get('key_filename')):
        raise NonRecoverableError(
            'access credentials not supplied '
            '(you must supply at least one of key_filename or password)')
    _ctx.logger.info('environment prepared successfully')
    return final_env
