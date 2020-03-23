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
import sys
import json
import tempfile
import posixpath
import importlib

from StringIO import StringIO
from contextlib import contextmanager

import requests
from fabric import Connection

import cloudify.ctx_wrappers
from cloudify import ctx
from cloudify import utils
from cloudify import exceptions
from cloudify.decorators import operation
from cloudify.proxy.client import CTX_SOCKET_URL
from cloudify.proxy import client as proxy_client
from cloudify.proxy import server as proxy_server
from cloudify.exceptions import NonRecoverableError

from fabric_plugin import tunnel
from fabric_plugin import exec_env

try:
    from cloudify.proxy.client import ScriptException
except ImportError:
    ScriptException = None


ILLEGAL_CTX_OPERATION_ERROR = RuntimeError('ctx may only abort or return once')
UNSUPPORTED_SCRIPT_FEATURE_ERROR = \
    RuntimeError('ctx abort & retry commands are only supported in Cloudify '
                 '3.4 or later')

DEFAULT_BASE_SUBDIR = 'cloudify-ctx'

FABRIC_ENV_DEFAULTS = {
    'connection_attempts': 5,
    'timeout': 10,
    'forward_agent': False,
    'abort_on_prompts': True,
    'keepalive': 0,
    'linewise': False,
    'pool_size': 0,
    'skip_bad_hosts': False,
    'status': False,
    'disable_known_hosts': True,
    'combine_stderr': True,
}

# Very low level workaround used to support manager recovery
# that is executed on a client different than the one used
# to bootstrap
CLOUDIFY_MANAGER_PRIVATE_KEY_PATH = 'CLOUDIFY_MANAGER_PRIVATE_KEY_PATH'


@contextmanager
def ssh_connection(ctx, fabric_env):
    host = fabric_env.get('host_string') or ctx.instance.host_ip
    user = fabric_env.get('user') or ctx.bootstrap_context.cloudify_agent.user
    connect_kwargs = {}
    if 'key' in fabric_env:
        connect_kwargs['key'] = fabric_env['key']
    if 'key_filename' in fabric_env:
        connect_kwargs['key_filename'] = fabric_env['key_filename']
    if 'password' in fabric_env:
        connect_kwargs['password'] = fabric_env['password']
    conn = Connection(
        host=host,
        user=user,
        connect_kwargs=connect_kwargs or None,
        port=fabric_env.get('port') or 22
    )
    conn.open()
    yield conn


@operation(resumable=True)
def run_task(tasks_file, task_name, fabric_env=None,
             task_properties=None, hide_output=None, **kwargs):
    """Runs the specified fabric task loaded from 'tasks_file'

    :param tasks_file: the tasks file
    :param task_name: the task name to run in 'tasks_file'
    :param fabric_env: fabric configuration
    :param task_properties: optional properties to pass on to the task
                            as invocation kwargs
    """
    task = _get_task(tasks_file, task_name)
    ctx.logger.info('Running task: {0} from {1}'.format(task_name, tasks_file))
    return _run_task(task, task_properties, fabric_env, hide_output)


@operation(resumable=True)
def run_module_task(task_mapping, fabric_env=None,
                    task_properties=None, hide_output=None, **kwargs):
    """Runs the specified fabric module task specified by mapping'

    :param task_mapping: the task module mapping
    :param fabric_env: fabric configuration
    :param task_properties: optional properties to pass on to the task
                            as invocation kwargs
    """
    task = _get_task_from_mapping(task_mapping)
    ctx.logger.info('Running task: {0}'.format(task_mapping))
    return _run_task(task, task_properties, fabric_env, hide_output)


def _run_task(task, task_properties, fabric_env, hide_output):
    with fabric_api.settings(
            _hide_output(groups=hide_output),
            **_fabric_env(fabric_env, warn_only=False)):
        task_properties = task_properties or {}
        return task(**task_properties)


@operation(resumable=True)
def run_commands(commands,
                 fabric_env=None,
                 use_sudo=False,
                 hide_output=None,
                 **kwargs):
    """Runs the provider 'commands' in sequence

    :param commands: a list of commands to run
    :param fabric_env: fabric configuration
    """
    with fabric_api.settings(
            _hide_output(groups=hide_output),
            **_fabric_env(fabric_env, warn_only=True)):
        for command in commands:
            ctx.logger.info('Running command: {0}'.format(command))
            run = fabric_api.sudo if use_sudo else fabric_api.run
            result = run(command)
            if result.failed:
                raise FabricCommandError(result)


class _FabricCtx(object):
    def __init__(self, ctx, files):
        self._ctx = ctx
        self._files = files

    def __getattr__(self, name):
        return getattr(self._ctx, name)

    def download_resource(self, resource_path, target_path=None):
        local_target_path = self._ctx.download_resource(resource_path)
        return self._fabric_put_in_remote_path(local_target_path, target_path)

    def download_resource_and_render(self,
                                     resource_path,
                                     target_path=None,
                                     template_variables=None):
        local_target_path = self._ctx.download_resource_and_render(
            resource_path,
            template_variables=template_variables)

        return self._fabric_put_in_remote_path(local_target_path, target_path)

    def _fabric_put_in_remote_path(self, local_target_path, target_path):
        if target_path:
            remote_target_path = target_path
        else:
            remote_target_path = posixpath.join(
                self._files.remote_work_dir,
                os.path.basename(local_target_path))

        self._files.put(local_target_path, remote_target_path)
        return remote_target_path

    def returns(self, _value):
        if self._ctx._return_value is not None:
            self._ctx._return_value = ILLEGAL_CTX_OPERATION_ERROR
            raise self._ctx._return_value
        self._ctx._return_value = _value

    def retry_operation(self, message=None, retry_after=None):
        if self._ctx._return_value is not None:
            self._ctx._return_value = ILLEGAL_CTX_OPERATION_ERROR
            raise self._ctx._return_value
        self._ctx.operation.retry(message=message, retry_after=retry_after)
        self._ctx._return_value = ScriptException(message, retry=True)
        return self._ctx._return_value

    def abort_operation(self, message=None):
        if self._ctx._return_value is not None:
            self._ctx._return_value = ILLEGAL_CTX_OPERATION_ERROR
            raise self._ctx._return_value
        self._ctx._return_value = ScriptException(message)
        return self._ctx._return_value


class _RemoteFiles(object):
    def __init__(self, conn, script_path, base_dir=None):
        self._conn = conn
        self._sftp = conn.sftp()
        self._script_path = script_path
        if base_dir:
            base_dir = posixpath.join(base_dir, DEFAULT_BASE_SUBDIR)
        self.base_dir = base_dir

    def __enter__(self):
        if not self.base_dir:
            self.base_dir = self._find_base_dir()
        self._upload_ctx()
        return self

    def __exit__(self, exc, val, tb):
        # TODO add cleaning of the scripts
        pass

    def put(self, local, remote, **kwargs):
        return self._sftp.put(local, remote, **kwargs)

    def exists(self, path):
        try:
            self._sftp.stat(path)
        except IOError:
            return False
        else:
            return True

    def upload_script(self, script_path):
        base_script_path = os.path.basename(script_path)
        remote_path_suffix = '{0}-{1}'.format(
            base_script_path, utils.id_generator(size=8))
        self.remote_env_script_path = posixpath.join(
            self.remote_scripts_dir,
            'env-' + remote_path_suffix
        )
        self.remote_script_path = posixpath.join(
            self.remote_scripts_dir,
            remote_path_suffix)
        self._sftp.put(script_path, self.remote_script_path)

    def upload_env_script(self, env):
        with self._sftp.file(self.remote_env_script_path, 'w') as env_script:
            env_script.write('chmod +x {0}\n'.format(self.remote_script_path))
            env_script.write('chmod +x {0}\n'.format(self.remote_ctx_path))
            for key, value in env.items():
                env_script.write('export {0}={1}\n'.format(key, value))

    def _upload_ctx(self):
        self.remote_ctx_path = '{0}/ctx'.format(self.base_dir)
        self.remote_ctx_sh_path = '{0}/ctx-sh'.format(self.base_dir)
        self.remote_ctx_py_path = '{0}/cloudify.py'.format(self.base_dir)
        self.remote_work_dir = '{0}/work'.format(self.base_dir)
        self.remote_scripts_dir = '{0}/scripts'.format(self.base_dir)

        if not self.exists(self.remote_ctx_path):
            self._sftp.mkdir(self.base_dir)
            self._sftp.mkdir(self.remote_work_dir)
            self._sftp.mkdir(self.remote_scripts_dir)
            self.put(
                proxy_client.__file__.rstrip('c'),  # strip ".pyc" to ".py"
                self.remote_ctx_path)
            self.put(
                os.path.join(_get_bin_dir(), 'ctx-sh'),
                self.remote_ctx_sh_path)
            self.put(
                os.path.join(
                    os.path.dirname(cloudify.ctx_wrappers.__file__),
                    'ctx-py.py'
                ),
                self.remote_ctx_py_path)

    def _find_base_dir(self):
        """Determine the basedir. In order of precedence:
            * 'base_dir' process input
            * ${CFY_EXEC_TEMP}/cloudify-ctx on the remote machine, if
              CFY_EXEC_TEMP is defined
            * <python default tempdir>/cloudify-ctx
        """
        base_dir = self._conn.run(
            '( [[ -n "${0}" ]] && echo -n ${0} ) || '
            'echo -n $(dirname $(mktemp -u))'.format(
                utils.ENV_CFY_EXEC_TEMPDIR)).stdout.strip()
        if not base_dir:
            raise NonRecoverableError('Could not conclude temporary directory')
        return posixpath.join(base_dir, DEFAULT_BASE_SUBDIR)


@contextmanager
def _make_proxy(ctx, port):
    proxy = proxy_server.HTTPCtxProxy(ctx, port=port)
    try:
        yield proxy
    finally:
        proxy.close()


@operation(resumable=True)
def run_script(ctx,
               script_path,
               fabric_env=None,
               process=None,
               use_sudo=False,
               hide_output=None,
               **kwargs):

    if not process:
        process = {}
    process = _create_process_config(process, kwargs)
    ctx_server_port = process.get('ctx_server_port')

    local_script_path = get_script(ctx.download_resource, script_path)

    env = process.get('env', {})
    args = process.get('args')
    command_prefix = process.get('command_prefix')

    with ssh_connection(ctx, fabric_env) as conn, \
            _RemoteFiles(conn, process.get('base_dir')) as files:
        files.upload_script(local_script_path)
        fabric_ctx = _FabricCtx(ctx, files)

        with _make_proxy(ctx, ctx_server_port) as proxy,
                conn.forward_remote(proxy.port):
            env['PATH'] = '{0}:$PATH'.format(files.base_dir)
            env['PYTHONPATH'] = '{0}:$PYTHONPATH'.format(files.base_dir)

            command = files.remote_script_path
            if command_prefix:
                command = '{0} {1}'.format(command_prefix, command)
            if args:
                command = ' '.join([command] + args)
            cwd = process.get('cwd', files.remote_work_dir)
            env[CTX_SOCKET_URL] = proxy.socket_url
            env['LOCAL_{0}'.format(CTX_SOCKET_URL)] = proxy.socket_url
            files.upload_env_script(env)
            command = 'cd {0} && source {1} && {2}'.format(
                cwd, files.remote_env_script_path, command)
            run = conn.sudo if use_sudo else conn.run
            ctx.logger.info("Running command: %s", command)
            output = run(command)
            ctx.logger.info(
                "Command completed, stdout: %s", output.stdout)
            ctx.logger.info(
                "Command completed, stderr: %s", output.stderr)

        result = getattr(fabric_ctx, '_return_value', None)
        if isinstance(result, ScriptException):
            if result.retry:
                return result
            else:
                raise NonRecoverableError(str(result))
        elif isinstance(result, RuntimeError):
            # this happens when more than 1 ctx operation is invoked
            raise NonRecoverableError(str(result))
        else:
            return result


def get_script(download_resource_func, script_path):
    split = script_path.split('://')
    schema = split[0]
    if schema in ['http', 'https']:
        response = requests.get(script_path)
        if response.status_code == 404:
            raise NonRecoverableError('Failed to download script: {0} ('
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


def _hide_output(groups):
    possible_groups = (
        'status',
        'aborts',
        'warnings',
        'running',
        'stdout',
        'stderr',
        'user',
        'everything'
    )
    groups = groups or ()
    if any(group not in possible_groups for group in groups):
        raise NonRecoverableError(
            '`hide_output` must be a subset of {0} (Provided: {1})'.format(
                ', '.join(possible_groups), ', '.join(groups)))
    return fabric_api.hide(*groups)


def _get_bin_dir():
    bin_dir = os.path.dirname(sys.executable)
    if os.name == 'nt' and 'scripts' != os.path.basename(bin_dir).lower():
        bin_dir = os.path.join(bin_dir, 'scripts')
    return bin_dir


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
    ctx.logger.debug('Getting tasks file...')
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
    """Handler to easily retrieve credentials info"""

    def __init__(self, _ctx, fabric_env):
        self.ctx = _ctx
        self.fabric_env = fabric_env
        self.logger = self.ctx.logger

    @property
    def user(self):
        """Returns the ssh user to use when connecting to the remote host"""
        self.logger.debug('Retrieving ssh user...')
        if 'user' not in self.fabric_env:
            if self.ctx.bootstrap_context.cloudify_agent.user:
                user = self.ctx.bootstrap_context.cloudify_agent.user
            else:
                self.logger.error('No user configured for ssh connections')
                raise exceptions.NonRecoverableError(
                    'ssh user definition missing')
        else:
            user = self.fabric_env['user']
        self.logger.debug('ssh user is: {0}'.format(user))
        return user

    @property
    def key(self):
        """Returns the ssh key to use when connecting to the remote host"""
        self.logger.debug('Retrieving ssh key...')
        if 'key' not in self.fabric_env:
            key = None
        else:
            key = self.fabric_env['key']
            # log only end of key
            self.logger.debug('ssh user is: ...{0}'.format(key[-100:]))
        return key

    @property
    def key_filename(self):
        """Returns the ssh key to use when connecting to the remote host"""
        self.logger.debug('Retrieving ssh key...')
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
        """Returns the ssh pwd to use when connecting to the remote host"""
        self.logger.debug('Retrieving ssh password...')
        if 'password' in self.fabric_env:
            pwd = self.fabric_env['password']
        else:
            self.logger.debug('ssh password not configured')
            return None
        self.logger.debug('ssh pwd is: {0}'.format(pwd))
        return pwd

    @property
    def host_string(self):
        self.logger.debug('Retrieving host string...')
        if 'host_string' in self.fabric_env:
            host_string = self.fabric_env['host_string']
        else:
            host_string = self.ctx.instance.host_ip
        self.logger.debug('ssh host_string is: {0}'.format(host_string))
        return host_string


def _fabric_env(fabric_env, warn_only):
    """Prepares fabric environment variables configuration"""
    ctx.logger.debug('Preparing fabric environment...')
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
            'Access credentials not supplied '
            '(you must supply at least one of key_filename/key or password)')
    ctx.logger.debug('Environment prepared successfully')
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
