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

import io
import os
import sys
import json
import tempfile
import posixpath
import importlib

from functools import wraps
from contextlib import contextmanager

import requests
from fabric2 import (
    Connection,
    task,
    Config,
)
from invoke import Task
from invoke.watchers import StreamWatcher
from paramiko import RSAKey, ECDSAKey, SSHException

# This is done because on 5.0.5 manager and older we will have
# 1.X paramiko version
try:
    from paramiko import Ed25519Key
    ED25519_AVAILABLE = True
except ImportError:
    ED25519_AVAILABLE = False

import cloudify.ctx_wrappers
from cloudify import ctx
from cloudify import utils
from cloudify import exceptions
from cloudify.decorators import operation
from cloudify.proxy.client import CTX_SOCKET_URL
from cloudify.proxy import client as proxy_client
from cloudify.proxy import server as proxy_server
from cloudify.exceptions import NonRecoverableError
from cloudify.state import current_ctx
from cloudify.utils import _get_current_context

# This is done for 5.0.5 and older utils backward compatibility
try:
    from cloudify.utils import ENV_CFY_EXEC_TEMPDIR
except ImportError:
    from cloudify.utils import CFY_EXEC_TEMPDIR_ENVVAR as ENV_CFY_EXEC_TEMPDIR

from fabric_plugin import exec_env
from fabric_plugin._compat import exec_, StringIO, PY311

from cloudify.proxy.client import ScriptException

# fix inspect compatiblity
import inspect
try:
    # in python 3.11 getargspec was removed in favor of getfullargspec
    if PY311:
        from inspect import getfullargspec
        inspect.getargspec = getfullargspec
except ImportError:
    pass


ILLEGAL_CTX_OPERATION_ERROR = RuntimeError('ctx may only abort or return once')
DEFAULT_BASE_SUBDIR = 'cloudify-ctx'

FABRIC_ENV_DEFAULTS = {
    'connect_timeout': 10,
    'port': 22,
    'always_use_pty': False,
    'gateway': None,
    'forward_agent': None,
    'no_agent': False,
    'ssh_config_path': None,
    'sudo_password': None,
    'password': None,
    'key_filename': None,
    'sudo_prompt': '[sudo] password: ',
    'timeout': 10,
    'command_timeout': None,
    'use_ssh_config': False,
    'warn_only': False,
}


# Class to handle stdout from fabric Connection
class OutputWatcher(StreamWatcher):
    def __init__(self, ctx):
        self.ctx = ctx
        self.already_logged = []

    def _log_output(self, lines):
        for line in lines:
            self.ctx.logger.debug(line.rstrip())

    def submit(self, stream):
        lines = stream.splitlines()
        lines = lines[len(self.already_logged):]
        if self.ctx is not None:
            with current_ctx.push(self.ctx):
                self._log_output(lines)
        else:
            self._log_output(lines)
        self.already_logged.extend(lines)
        return []


# inspired by fabric 1.x https://github.com/fabric/fabric/blob/1.10/fabric/utils.py#L186 # NOQA
class _AttributeDict(dict):
    """
    Dictionary subclass enabling attribute lookup/assignment of keys/values.

    For example::

        >>> m = _AttributeDict({'foo': 'bar'})
        >>> m.foo
        'bar'
        >>> m.foo = 'not bar'
        >>> m['foo']
        'not bar'
    """
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError(key)

    def __setattr__(self, key, value):
        self[key] = value


def _load_private_key(key_contents):
    """Load the private key and return a paramiko PKey subclass.

    :param key_contents: the contents of a keyfile, as a string starting
        with "---BEGIN"
    :return: A paramiko PKey subclass - RSA, ECDSA or Ed25519
    """
    keys_classes_list = [RSAKey, ECDSAKey]
    if ED25519_AVAILABLE:
        keys_classes_list.append(Ed25519Key)
    for cls in keys_classes_list:
        try:
            return cls.from_private_key(StringIO(key_contents))
        except SSHException:
            continue
    raise NonRecoverableError(
        'Could not load the private key as an '
        'RSA, ECDSA, or Ed25519 key'
    )


def _resolve_hide_value(groups=None):
    """
    Get the proper `hide` value that should be set for running fabric command
    where the following values are possible for hide values:
       1. out/stdout
       2. err/stderr
       3. both/True
       4. None


    :param groups: list of possible levels that can be passed as `hide_output`
    for `run_commands` & `run_script` operation for cloudify-fabric-1.x & 2.x
    plugin
    :return: str: The hide value value based on groups value

    In all cases, result.stdout & result.stderr are always populated with
    the command result values. By default, results get printed to console
    if hide value is not provided

    For example::
    >>> from fabric import Connection
    >>> connection = {"host": "127.0.0.1", "user": "centos", "port": 22, "connect_kwargs": {"key_filename":"/home/centos/key.pem"}} # NOQA
    >>> result = connection.run('uname -s')
    >>> Linux
    >>> result.stdout
    'Linux\n'
    >>> result.stderr
    ''

    >>> from fabric import Connection
    >>> connection = {"host": "127.0.0.1", "user": "centos", "port": 22, "connect_kwargs": {"key_filename":"/home/centos/key.pem"}} # NOQA
    >>> result = connection.run('uname -s', hide=True)
    >>> result.stdout
    'Linux\n'
    >>> result.stderr
    ''

    >>> from fabric import Connection
    >>> connection = {"host": "127.0.0.1", "user": "centos", "port": 22, "connect_kwargs": {"key_filename":"/home/centos/key.pem"}} # NOQA
    >>> result = connection.run('uname -s', hide="out")
    >>> result.stdout
    'Linux\n'
    >>> result.stderr
    ''
    """
    possible_groups = {
        'status': 'out',
        'aborts': 'out',
        'warnings': 'out',
        'running': 'out',
        'user': 'out',
        'everything': ['out', 'err'],
        'both': ['out', 'err'],
        'stdout': 'out',
        'stderr': 'err',
        'None': False,
    }
    groups = groups or []
    supported_groups = set()
    # By default do not hide anything
    if not groups:
        return False
    if any(group not in possible_groups for group in groups):
        raise NonRecoverableError(
            '`hide_output` must be a subset of {0} (Provided: {1})'.format(
                ', '.join(possible_groups), ', '.join(groups)))

    for group in groups:
        new_group = possible_groups[group]
        if isinstance(new_group, list):
            supported_groups.update(new_group)
        else:
            supported_groups.add(new_group)

    supported_groups = list(supported_groups)
    hide_value = True
    if len(supported_groups) == 1:
        hide_value = supported_groups[0]

    return hide_value


def _hide_or_display_results(hide_value, result):
    """
    This method helps to decide if we need to display/hide the results of
    fabric commands/scripts run on specifec machine
    :param hide_value: The value that helps to decide how should we display
    fabric results. The possible values are:
    1. False --> hide nothing
    2. True ---> Do not display anything
    3. out ---> Do not display stdout results
    4. err ---> Do not display stderr results
    :param result: Instance of result object
    """
    if not hide_value:
        _log_output(ctx, result.stdout, prefix='<out> ')
        _log_output(ctx, result.stderr, prefix='<err> ')
    elif hide_value == "out":
        _log_output(ctx, result.stderr, prefix='<err> ')
    elif hide_value == 'err':
        _log_output(ctx, result.stdout, prefix='<out> ')


def put_host(fabric_env, host_ip=None):
    if 'host' not in fabric_env:
        if 'host_string' in fabric_env:
            fabric_env['host'] = fabric_env.pop('host_string')
        elif host_ip:
            fabric_env['host'] = host_ip
        else:
            raise NonRecoverableError('host ip is missing')


def put_user(fabric_env, agent_user=None):
    if 'user' not in fabric_env:
        if agent_user:
            fabric_env['user'] = agent_user
        else:
            raise NonRecoverableError('ssh user definition missing')


def put_key_or_password(fabric_env, connect_kwargs, agent_key_path=None):
    pkey = fabric_env.get('connect_kwargs', {}).get('pkey')
    if pkey:
        fabric_env['connect_kwargs']['pkey'] = _load_private_key(pkey)
    elif fabric_env.get('key'):
        connect_kwargs['pkey'] = _load_private_key(fabric_env['key'])
    elif fabric_env.get('key_filename'):
        connect_kwargs['key_filename'] = os.path.expanduser(
            fabric_env['key_filename'])
    elif fabric_env.get('password'):
        connect_kwargs['password'] = fabric_env['password']
    elif agent_key_path:
        connect_kwargs['key_filename'] = os.path.expanduser(agent_key_path)
    else:
        raise NonRecoverableError('key_filename/key or password missing')


def prepare_fabric2_env(fabric2_env, fabric_env, connect_kwargs):
    fabric2_env['connect_kwargs'] = fabric_env.setdefault(
        'connect_kwargs', connect_kwargs)
    fabric2_env['run'] = fabric_env.setdefault('run', {})
    fabric2_env['sudo'] = fabric_env.setdefault('sudo', {})
    fabric2_env['timeouts'] = fabric_env.setdefault('timeouts', {})
    fabric2_env['user'] = fabric_env.pop('user')
    fabric2_env['port'] = fabric_env.get('port', 22)


@contextmanager
def ssh_connection(ctx, fabric_env, hide_output=True):
    """Make and establish a fabric ssh connection.

    :param ctx: cloudify operation context
    :param fabric_env: dict containing fabric connection details, with
        keys such as: host/host_string, user, key/key_filename/password,
        connect_timeout, port

    :return: a fabric.Connection instance
    """

    for name, value in FABRIC_ENV_DEFAULTS.items():
        fabric_env.setdefault(name, value)

    try:
        host_ip = ctx.instance.host_ip
        agent_user = ctx.bootstrap_context.cloudify_agent.user
        agent_key_path = ctx.bootstrap_context.cloudify_agent.agent_key_path
    except NonRecoverableError as e:
        ctx.logger.error(
            'Failed to find potentially required data '
            'from context: {}'.format(str(e)))
        host_ip = None
        agent_user = None
        agent_key_path = None

    put_host(fabric_env, host_ip)
    put_user(fabric_env, agent_user)
    connect_kwargs = {}
    put_key_or_password(
        fabric_env,
        connect_kwargs,
        agent_key_path)

    host = fabric_env.pop('host')
    # Prepare the fabric2 env inputs if they passed
    fabric2_env = {}
    prepare_fabric2_env(fabric2_env, fabric_env, connect_kwargs)
    overrides = {'overrides':  fabric2_env}

    # Convert fabric 1.x inputs to fabric 2.x
    fabric_env = _AttributeDict(**fabric_env)
    config = Config.from_v1(fabric_env, **overrides)

    if not config["timeouts"].get("command"):
        config["timeouts"]["command"] = fabric_env.command_timeout
    if fabric_env.connect_timeout != 10:
        config["timeouts"]['connect'] = fabric_env.connect_timeout

    # if we are not hiding let's show response stream as we get it
    if not hide_output:
        config['run'] = {}
        config['run']['watchers'] = [OutputWatcher(_get_current_context())]

    fabric_env_config = {
        'host': host,
        'user': fabric2_env['user'],
        'port': fabric2_env['port'],
        'config': config
    }
    conn = Connection(**fabric_env_config)
    try:
        conn.open()
        yield conn
    finally:
        conn.close()


def handle_fabric_exception(func):
    @wraps(func)
    def f(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            ctx.logger.error('Exception Happend: {0}'.format(str(e)))
            if hasattr(e, 'result'):
                fab_err_code = \
                    e.result.return_code if hasattr(e.result, 'return_code') \
                    else 'NA'
                fab_stdout = \
                    e.result.stdout if hasattr(e.result, 'stdout') else 'NA'
                fab_stderr = \
                    e.result.stderr if hasattr(e.result, 'stderr') else 'NA'
                ctx.logger.error(
                    'Fabric Results:\n'
                    '---------------------------------'
                    '\nreturn_code: {0}\n'
                    '---------------------------------'
                    '\nstdout:\n{1}\n'
                    '---------------------------------'
                    '\nstderr:\n{2}\n'
                    '---------------------------------'.format(
                        fab_err_code, fab_stdout, fab_stderr))

            exit_codes = kwargs.get('non_recoverable_error_exit_codes', [])
            if hasattr(e, 'result')\
                    and e.result.return_code in exit_codes:
                raise NonRecoverableError(e)
            raise e
    return f


@operation(resumable=True)
@handle_fabric_exception
def run_task(ctx, tasks_file, task_name, fabric_env=None,
             task_properties=None, **kwargs):
    """Runs the specified fabric task loaded from 'tasks_file'

    :param tasks_file: the tasks file
    :param task_name: the task name to run in 'tasks_file'
    :param fabric_env: fabric configuration
    :param task_properties: optional properties to pass on to the task
                            as invocation kwargs
    """
    if kwargs.get('hide_output'):
        ctx.logger.debug('`hide_output` input is not '
                         'supported for `run_task` operation')
    func = _get_task(tasks_file, task_name)
    ctx.logger.info('Running task: {0} from {1}'.format(task_name, tasks_file))
    return _run_task(ctx, func, task_properties, fabric_env)


@operation(resumable=True)
@handle_fabric_exception
def run_module_task(ctx, task_mapping, fabric_env=None,
                    task_properties=None, **kwargs):
    """Runs the specified fabric module task specified by mapping'

    :param task_mapping: the task module mapping
    :param fabric_env: fabric configuration
    :param task_properties: optional properties to pass on to the task
                            as invocation kwargs
    """
    if kwargs.get('hide_output'):
        ctx.logger.debug('`hide_output` input is not '
                         'supported for `run_module_task` operation')
    task = _get_task_from_mapping(task_mapping)
    ctx.logger.info('Running task: {0}'.format(task_mapping))
    return _run_task(ctx, task, task_properties, fabric_env)


def _run_task(ctx, task, task_properties, fabric_env):
    with ssh_connection(ctx, fabric_env) as conn:
        task_properties = task_properties or {}
        return task(conn, **task_properties)


def convert_shell_env(env):
    """Convert shell_env dict to string of env variables
    """
    env_str = ""
    for key in env.keys():
        env_str += "export {key}={value};".format(
            key=key, value=str(env.get(key)))
    return env_str


def handle_shell_env(command,
                     use_sudo=False,
                     shell_env=None):
    if not use_sudo:
        command = convert_shell_env(shell_env) +\
                  command
    else:
        command = command[:6] +\
            convert_shell_env(shell_env) +\
            command[6:]
    return command


@operation(resumable=True)
@handle_fabric_exception
def run_commands(ctx,
                 commands,
                 fabric_env=None,
                 use_sudo=False,
                 **kwargs):
    """Runs the provider 'commands' in sequence

    :param commands: a list of commands to run
    :param fabric_env: fabric configuration
    """

    hide_value = _resolve_hide_value(kwargs.get('hide_output'))
    with ssh_connection(ctx, fabric_env, hide_value) as conn:
        for command in commands:
            ctx.logger.info('Running command: {0}'.format(command))
            run, command = handle_sudo(conn, use_sudo, command)
            command = handle_shell_env(command,
                                       use_sudo,
                                       fabric_env.get('shell_env', {}))
            result = run(command, hide=hide_value, pty=True)
            _hide_or_display_results(hide_value, result)


class _FabricCtx(object):
    """A Context object for use with the ctx proxy.

    This is used by the proxy, when tasks/scripts use `ctx` calls.
    """
    def __init__(self, ctx, files):
        self._ctx = ctx
        self._files = files

    def __getattr__(self, name):
        # delegate to the cloudify operationcontext
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
    """Helper for uploading files needed to run fabric scripts."""
    def __init__(self, conn, script_path, base_dir=None, hide_value=False):
        self._conn = conn
        self._sftp = conn.sftp()
        self._script_path = script_path
        self._hide_value = hide_value
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
            env_script.write('chmod +x {0}\n'.format(
                self.remote_proxy_client_path)
            )
            env_script.write('chmod +x {0}\n'.format(
                self.remote_wrapper_ctx_sh_path)
            )
            for key, value in env.items():
                env_script.write('export {0}={1}\n'.format(key, value))

    def folder_creator(self, dirs):
        steps = '/'
        for step in os.path.split(dirs):
            steps = os.path.join(steps, step)
            if self.exists(steps):
                continue
            try:
                self._sftp.mkdir(steps)
            except OSError as e:
                if not self.exists(steps):
                    ctx.logger.error(
                        'Failed to make directory: {}.'.format(steps))
                    raise e

    def _upload_ctx(self):
        self.remote_proxy_client_path = \
            '{0}/proxy_client'.format(self.base_dir)
        self.remote_wrapper_ctx_sh_path = '{0}/ctx'.format(self.base_dir)
        self.remote_ctx_py_path = '{0}/cloudify.py'.format(self.base_dir)
        self.remote_work_dir = '{0}/work'.format(self.base_dir)
        self.remote_scripts_dir = '{0}/scripts'.format(self.base_dir)

        if not self.exists(self.remote_proxy_client_path):
            self.folder_creator(self.base_dir)
            self.folder_creator(self.remote_work_dir)
            self.folder_creator(self.remote_scripts_dir)
            self.put(
                proxy_client.__file__.rstrip('c'),  # strip ".pyc" to ".py"
                self.remote_proxy_client_path)
            with self._sftp.file(self.remote_wrapper_ctx_sh_path,
                                 'w') as wrapper_script:
                wrapper_script.write('#!/usr/bin/env bash\n')
                wrapper_script.write(
                    '$PYTHONBIN {0}/proxy_client \"$@\"'.format(self.base_dir)
                )
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
                ENV_CFY_EXEC_TEMPDIR), hide=self._hide_value).stdout.strip()
        if not base_dir:
            raise NonRecoverableError('Could not conclude temporary directory')
        return posixpath.join(base_dir, DEFAULT_BASE_SUBDIR)


@contextmanager
def _make_proxy(ctx, port):
    """A Cloudify context proxy, wrapped in a contextmanager"""
    proxy = proxy_server.HTTPCtxProxy(ctx, port=port)
    try:
        yield proxy
    finally:
        proxy.close()


def handle_sudo(conn, use_sudo, command):
    if use_sudo:
        command = "echo '{command}' | sudo -i --".format(
            command=command.strip('\n'))
    run = conn.run
    return run, command


@operation(resumable=True)
@handle_fabric_exception
def run_script(ctx,
               script_path,
               fabric_env=None,
               process=None,
               use_sudo=False,
               **kwargs):

    if not process:
        process = {}
    process = _create_process_config(process, kwargs)
    ctx_server_port = process.get('ctx_server_port')

    local_script_path = get_script(ctx.download_resource, script_path)

    env = process.get('env', {})
    args = process.get('args')
    command_prefix = process.get('command_prefix')
    hide_value = _resolve_hide_value(kwargs.get('hide_output'))
    with ssh_connection(ctx, fabric_env, hide_value) as conn, \
            _RemoteFiles(
                conn,
                local_script_path,
                process.get('base_dir'),
                hide_value=hide_value
            ) as files:
        files.upload_script(local_script_path)
        fabric_ctx = _FabricCtx(ctx, files)
        with _make_proxy(fabric_ctx, ctx_server_port) as proxy, \
                conn.forward_remote(proxy.port):
            env['PATH'] = '{0}:$PATH'.format(files.base_dir)
            env['PYTHONPATH'] = '{0}:$PYTHONPATH'.format(files.base_dir)
            # This python set in order to execute proxy client on target
            # system by detecting which python version to run that proxy
            # client so that it can communicate with the proxy server on the
            # manager side
            env['PYTHONBIN'] = '$(command which python ' \
                               '|| command which python3 ' \
                               '|| echo "python")'
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
            ctx.logger.info("Running command: %s", command)
            run, command = handle_sudo(conn, use_sudo, command)
            result = run(command, hide=hide_value)
            _hide_or_display_results(hide_value, result)

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


def _log_output(ctx, data, prefix):
    lines = data.split('\n')
    if not lines:
        return
    if not lines[-1]:  # last line is commonly empty
        lines.pop()
    # can't use cloudify.utils.OutputConsumer because that isn't compatible
    # with sockets, only with subprocess pipes
    for line in lines:
        ctx.logger.info('%s%s', prefix, line)


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
    else:
        script_path = download_resource_func(script_path)
    remove_crlf(script_path)
    return script_path


def remove_crlf(script_path: str):
    """ Remove CRLF by reading the file without newlines
        and returning those lines to the file
    """
    with io.open(script_path, 'rt', newline='') as f:
        lines = f.readlines()
    for idx, line in enumerate(lines):
        lines[idx] = "{0}\n".format(line.rstrip())
    with io.open(script_path, 'wt') as f:
        f.writelines(lines)


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
        func = getattr(module, task_name)
    except Exception as e:
        raise exceptions.NonRecoverableError(
            "Could not find '{0}' in {1} ({2}: {3})"
            .format(task_name, module_name,
                    type(e).__name__, e))
    if not callable(func):
        raise exceptions.NonRecoverableError(
            "'{0}' in '{1}' is not callable"
            .format(task_name, module_name))
    return _normalize_task_func(func)


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
        exec_(tasks_code, exec_globs)
    except Exception as e:
        raise exceptions.NonRecoverableError(
            "Could not load '{0}' ({1}: {2})".format(tasks_file,
                                                     type(e).__name__, e))
    func = exec_globs.get(task_name)
    if not func:
        raise exceptions.NonRecoverableError(
            "Could not find task '{0}' in '{1}'"
            .format(task_name, tasks_file))
    if not callable(func):
        raise exceptions.NonRecoverableError(
            "'{0}' in '{1}' is not callable"
            .format(task_name, tasks_file))
    return _normalize_task_func(func)


def _normalize_task_func(func):
    """Adapt the given func to be a fabric Task.

    Fabric tasks (in fabric 2.x) get the ssh connection instance as
    the first argument. For compatibility with existing tasks, if
    the function is not already decorated with @task, let's skip that
    first argument.

    For new tasks, the user should decorate their task with @task,
    which will make it receive the ssh connection as the first argument.
    """
    if not isinstance(func, Task):
        @task
        @wraps(func)
        def _inner(conn, *args, **kwargs):
            return func(*args, **kwargs)
        return _inner
    return func
