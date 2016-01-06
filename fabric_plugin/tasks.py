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
import importlib
import json
import requests
import tempfile
from StringIO import StringIO

from six import exec_
from fabric import api as fabric_api
from fabric import context_managers as fabric_context
from fabric.contrib import files as fabric_files

from cloudify import utils
from cloudify import ctx
from cloudify import exceptions
from cloudify.decorators import operation
from cloudify.proxy.client import CTX_SOCKET_URL
from cloudify.proxy import client as proxy_client
from cloudify.proxy import server as proxy_server
from cloudify.exceptions import NonRecoverableError

from fabric_plugin import tunnel
from fabric_plugin import exec_env


DEFAULT_BASE_DIR = '/tmp/cloudify-ctx'

FABRIC_ENV_DEFAULTS = {
    'connection_attempts': 5,
    'timeout': 10,
    'forward_agent': True,
    'abort_on_prompts': True,
    'keepalive': 0,
    'linewise': False,
    'pool_size': 0,
    'skip_bad_hosts': False,
    'status': False,
    'disable_known_hosts': False,
    'combine_stderr': True,
}

# Very low level workaround used to support manager recovery
# that is executed on a client different than the one used
# to bootstrap
CLOUDIFY_MANAGER_PRIVATE_KEY_PATH = 'CLOUDIFY_MANAGER_PRIVATE_KEY_PATH'


@operation
def run_task(tasks_file, task_name, fabric_env=None,
             task_properties=None, **kwargs):
    """runs the specified fabric task loaded from 'tasks_file'

    :param tasks_file: the tasks file
    :param task_name: the task name to run in 'tasks_file'
    :param fabric_env: fabric configuration
    :param task_properties: optional properties to pass on to the task
                            as invocation kwargs
    """
    task = _get_task(tasks_file, task_name)
    ctx.logger.info('running task: {0} from {1}'.format(task_name, tasks_file))
    return _run_task(task, task_properties, fabric_env)


@operation
def run_module_task(task_mapping, fabric_env=None,
                    task_properties=None, **kwargs):
    """runs the specified fabric module task specified by mapping'

    :param task_mapping: the task module mapping
    :param fabric_env: fabric configuration
    :param task_properties: optional properties to pass on to the task
                            as invocation kwargs
    """
    task = _get_task_from_mapping(task_mapping)
    ctx.logger.info('running task: {0}'.format(task_mapping))
    return _run_task(task, task_properties, fabric_env)


def _run_task(task, task_properties, fabric_env):
    with fabric_api.settings(**_fabric_env(fabric_env, warn_only=False)):
        task_properties = task_properties or {}
        return task(**task_properties)


@operation
def run_commands(commands, fabric_env=None, **kwargs):
    """runs the provider 'commands' in sequence

    :param commands: a list of commands to run
    :param fabric_env: fabric configuration
    """
    with fabric_api.settings(**_fabric_env(fabric_env, warn_only=True)):
        for command in commands:
            ctx.logger.info('running command: {0}'.format(command))
            result = fabric_api.run(command)
            if result.failed:
                raise FabricCommandError(result)


@operation
def run_script(script_path, fabric_env=None, process=None, **kwargs):

    if not process:
        process = {}
    process = _create_process_config(process, kwargs)
    base_dir = process.get('base_dir', DEFAULT_BASE_DIR)
    ctx_server_port = process.get('ctx_server_port')

    proxy_client_path = proxy_client.__file__
    if proxy_client_path.endswith('.pyc'):
        proxy_client_path = proxy_client_path[:-1]
    local_script_path = get_script(ctx.download_resource, script_path)
    base_script_path = os.path.basename(local_script_path)
    remote_ctx_dir = base_dir
    remote_ctx_path = '{0}/ctx'.format(remote_ctx_dir)
    remote_scripts_dir = '{0}/scripts'.format(remote_ctx_dir)
    remote_work_dir = '{0}/work'.format(remote_ctx_dir)
    remote_path_suffix = '{0}-{1}'.format(base_script_path,
                                          utils.id_generator(size=8))
    remote_env_script_path = '{0}/env-{1}'.format(remote_scripts_dir,
                                                  remote_path_suffix)
    remote_script_path = '{0}/{1}'.format(remote_scripts_dir,
                                          remote_path_suffix)

    env = process.get('env', {})
    cwd = process.get('cwd', remote_work_dir)
    args = process.get('args')
    command_prefix = process.get('command_prefix')

    command = remote_script_path
    if command_prefix:
        command = '{0} {1}'.format(command_prefix, command)
    if args:
        command = ' '.join([command] + args)

    with fabric_api.settings(**_fabric_env(fabric_env, warn_only=False)):
        if not fabric_files.exists(remote_ctx_path):
            # there may be race conditions with other operations that
            # may be running in parallel, so we pass -p to make sure
            # we get 0 exit code if the directory already exists
            fabric_api.run('mkdir -p {0}'.format(remote_scripts_dir))
            fabric_api.run('mkdir -p {0}'.format(remote_work_dir))
            fabric_api.put(proxy_client_path, remote_ctx_path)

        actual_ctx = ctx._get_current_object()

        def returns(_value):
            actual_ctx._return_value = _value
        actual_ctx._return_value = None
        actual_ctx.returns = returns

        original_download_resource = actual_ctx.download_resource

        def download_resource(resource_path, target_path=None):
            local_target_path = original_download_resource(resource_path)
            return fabric_put_in_remote_path(local_target_path, target_path)

        actual_ctx.download_resource = download_resource

        original_download_resource_and_render = \
            actual_ctx.download_resource_and_render

        def download_resource_and_render(resource_path,
                                         target_path=None,
                                         template_variables=None):
            local_target_path = original_download_resource_and_render(
                resource_path,
                template_variables=template_variables)

            return fabric_put_in_remote_path(local_target_path, target_path)

        actual_ctx.download_resource_and_render = download_resource_and_render

        def fabric_put_in_remote_path(local_target_path, target_path):
            if target_path:
                remote_target_path = target_path
            else:
                remote_target_path = '{0}/{1}'.format(
                    remote_work_dir,
                    os.path.basename(local_target_path))
            fabric_api.put(local_target_path, remote_target_path)
            return remote_target_path

        proxy = proxy_server.HTTPCtxProxy(actual_ctx, port=ctx_server_port)

        env_script = StringIO()
        env['PATH'] = '{0}:$PATH'.format(remote_ctx_dir)
        env[CTX_SOCKET_URL] = proxy.socket_url
        for key, value in env.iteritems():
            env_script.write('export {0}={1}\n'.format(key, value))
        env_script.write('chmod +x {0}\n'.format(remote_script_path))
        env_script.write('chmod +x {0}\n'.format(remote_ctx_path))
        try:
            fabric_api.put(local_script_path, remote_script_path)
            fabric_api.put(env_script, remote_env_script_path)
            with fabric_context.cd(cwd):
                with tunnel.remote(proxy.port):
                    fabric_api.run('source {0} && {1}'.format(
                        remote_env_script_path, command))
            return actual_ctx._return_value
        finally:
            proxy.close()


def get_script(download_resource_func, script_path):
    split = script_path.split('://')
    schema = split[0]
    if schema in ['http', 'https']:
        response = requests.get(script_path)
        if response.status_code == 404:
            raise NonRecoverableError('Failed downloading script: {0} ('
                                      'status code: {1})'
                                      .format(script_path,
                                              response.status_code))
        content = response.text
        suffix = script_path.split('/')[-1]
        script_path = tempfile.mktemp(suffix='-{0}'.format(suffix))
        with open(script_path, 'wb') as f:
            f.write(content)
        return script_path
    else:
        return download_resource_func(script_path)


def _create_process_config(process, operation_kwargs):
    env_vars = operation_kwargs.copy()
    if 'ctx' in env_vars:
        del env_vars['ctx']
    env_vars.update(process.get('env', {}))
    for k, v in env_vars.items():
        if isinstance(v, (dict, list, set)):
            env_vars[k] = "'{0}'".format(json.dumps(v))
    process['env'] = env_vars
    return process


def _get_task_from_mapping(mapping):
    split = mapping.split('.')
    module_name = '.'.join(split[:-1])
    task_name = split[-1]
    try:
        module = importlib.import_module(module_name)
    except Exception as e:
        raise exceptions.NonRecoverableError(
            "Could not load '{0}' ({1}: {2})".format(module_name,
                                                     type(e).__name__, e))
    try:
        task = getattr(module, task_name)
    except Exception as e:
        raise exceptions.NonRecoverableError(
            "Could not find '{0}' in {1} ({2}: {3})"
            .format(task_name, module_name,
                    type(e).__name__, e))
    if not callable(task):
        raise exceptions.NonRecoverableError(
            "'{0}' in '{1}' is not callable"
            .format(task_name, module_name))
    return task


def _get_task(tasks_file, task_name):
    ctx.logger.debug('getting tasks file...')
    try:
        tasks_code = ctx.get_resource(tasks_file)
    except Exception as e:
        raise exceptions.NonRecoverableError(
            "Could not get '{0}' ({1}: {2})".format(tasks_file,
                                                    type(e).__name__, e))
    exec_globs = exec_env.exec_globals(tasks_file)
    try:
        exec_(tasks_code, _globs_=exec_globs)
    except Exception as e:
        raise exceptions.NonRecoverableError(
            "Could not load '{0}' ({1}: {2})".format(tasks_file,
                                                     type(e).__name__, e))
    task = exec_globs.get(task_name)
    if not task:
        raise exceptions.NonRecoverableError(
            "Could not find task '{0}' in '{1}'"
            .format(task_name, tasks_file))
    if not callable(task):
        raise exceptions.NonRecoverableError(
            "'{0}' in '{1}' is not callable"
            .format(task_name, tasks_file))
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
                raise exceptions.NonRecoverableError(
                    'ssh user definition missing')
        else:
            user = self.fabric_env['user']
        self.logger.debug('ssh user is: {0}'.format(user))
        return user

    @property
    def key(self):
        """returns the ssh key to use when connecting to the remote host"""
        self.logger.debug('retrieving ssh key...')
        if 'key' not in self.fabric_env:
            key = None
        else:
            key = self.fabric_env['key']
            # log only end of key
            self.logger.debug('ssh user is: ...{0}'.format(key[-100:]))
        return key

    @property
    def key_filename(self):
        """returns the ssh key to use when connecting to the remote host"""
        self.logger.debug('retrieving ssh key...')
        if CLOUDIFY_MANAGER_PRIVATE_KEY_PATH in os.environ:
            key = os.environ[CLOUDIFY_MANAGER_PRIVATE_KEY_PATH]
        elif 'key_filename' not in self.fabric_env:
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
            host_string = self.ctx.instance.host_ip
        self.logger.debug('ssh host_string is: {0}'.format(host_string))
        return host_string


def _fabric_env(fabric_env, warn_only):
    """prepares fabric environment variables configuration

    :param fabric_env: fabric configuration
    """
    ctx.logger.info('preparing fabric environment...')
    fabric_env = fabric_env or {}
    credentials = CredentialsHandler(ctx, fabric_env)
    final_env = {}
    final_env.update(FABRIC_ENV_DEFAULTS)
    final_env.update(fabric_env)
    final_env.update({
        'host_string': credentials.host_string,
        'user': credentials.user,
        'password': credentials.password,
        'warn_only': fabric_env.get('warn_only', warn_only),
        'abort_exception': FabricTaskError,
    })
    if credentials.key:
        final_env.update({
            'key': credentials.key
        })
    else:
        final_env.update({
            'key_filename': credentials.key_filename
        })
    # validations
    if not (
        final_env.get('password') or
        final_env.get('key_filename') or
        final_env.get('key')
    ):
        raise exceptions.NonRecoverableError(
            'access credentials not supplied '
            '(you must supply at least one of key_filename/key or password)')
    ctx.logger.info('environment prepared successfully')
    return final_env


class FabricTaskError(Exception):
    pass


class FabricCommandError(exceptions.CommandExecutionException):

    def __init__(self, command_result):
        out = command_result.stdout
        err = command_result.stderr
        command = command_result.command
        code = command_result.return_code
        super(FabricCommandError, self).__init__(command, err, out, code)
