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
import time
import importlib

from fabric.api import run as execute
from fabric.api import settings, env

from cloudify.decorators import operation
from cloudify.manager import get_rest_client
from cloudify import ctx

DEFAULT_ATTEMPTS = 3
DEFAULT_ATTEMPTS_SLEEP = 3
DEFAULT_CONNECTION_ATTEMPTS = 5
DEFAULT_SUDO = False
DEFAULT_TIMEOUT = 10
DEFAULT_WARN_ONLY = True
DEFAULT_FORWARD_AGENT = True

FABRIC_CONFIG = 'fabric_config'


@operation
def run_command(commands, **kwargs):
    """runs a list of fabric commands

    :param commands: list of commands
    """
    context_manager = ContextManager(ctx)
    fabric_config = context_manager.get_fabric_config()
    _configure_fabric_env(ctx, context_manager, fabric_config)
    with settings(host_string=ctx.host_ip):
        for command in command_list:
            _run_with_retries(ctx, command, fabric_config)


@operation
def run_task(tasks_file, task_name, **kwargs):
    """runs the specified fabric task loaded from 'tasks_file'

    :param tasks_file: the tasks file
    :param task_name: the task name to run in 'tasks_file'
    """
    def _import_tasks_module(tasks_file):
        tasks_file = ctx.download_resource(tasks_file)
        ctx.logger.debug('importing tasks file...')
        sys.path.append(os.path.dirname(tasks_file))
        try:
            module = importlib.import_module(
                os.path.basename(os.path.splitext(
            os.path.join(tasks_file))[0]))
        finally:
            sys.path.remove(os.path.dirname(tasks_file))

    context_manager = ContextManager(ctx)
    fabric_config = context_manager.get_fabric_config()
    _configure_fabric_env(ctx, context_manager, fabric_config)
    tasks_module = _import_tasks_module(tasks_file)
    with settings(host_string=ctx.host_ip):
        ctx.logger.info('running task: {0} from {1}'.format(
            operation_simple_name, tasks_file))
        task = getattr(tasks_module, task_name)
        task(ctx)


class ContextManager():
    """context handler to easily retrieve context info
    """
    def __init__(self, ctx):
        """initializes fabric env configuration and context logger
        """
        self.ctx = ctx
        self.fabric_config = ctx.properties['fabric_config']
        self.logger = ctx.logger

    def get_fabric_config(self):
        """returns fabric env config properties"""
        return self.fabric_config

    def get_ssh_user(self):
        """returns the ssh user to use when connecting to the remote host"""
        self.logger.debug('retrieving ssh user...')
        if 'ssh_user' not in self.fabric_config:
            if self.ctx.bootstrap_context.cloudify_agent.user:
                user = self.ctx.bootstrap_context.cloudify_agent.user
            else:
                self.logger.error('no user configured for ssh connections')
                raise RuntimeError('ssh user definition missing')
        else:
            user = self.fabric_config['ssh_user']
        self.logger.debug('ssh user is: {0}'.format(user))
        return user

    def get_ssh_key(self):
        """returns the ssh key to use when connecting to the remote host"""
        self.logger.debug('retrieving ssh key...')
        if 'ssh_key' not in self.fabric_config:
            if self.ctx.bootstrap_context.cloudify_agent.agent_key_path:
                key = self.ctx.bootstrap_context.cloudify_agent.agent_key_path
            else:
                self.logger.debug('ssh key path not configured')
                return None
        else:
            key = self.fabric_config['ssh_key']
        self.logger.debug('ssh key path is: {0}'.format(key))
        return key

    def get_ssh_password(self):
        """returns the ssh pwd to use when connecting to the remote host"""
        self.logger.debug('retrieving ssh password...')
        if 'ssh_pwd' in self.fabric_config:
            pwd = self.fabric_config['ssh_pwd']
        else:
            self.logger.debug('ssh password not configured')
            return None
        self.logger.debug('ssh pwd is: {0}'.format(pwd))
        return pwd


def _configure_fabric_env(ctx, context_manager, fabric_config):
    """configures fabric environment variables

    Most of the configuration is overridable, like ssh_user, ssh_key_path,
    ssh_password..
    Some are defined by default like linewise, and keepalive.

    :param ctx: CloudifyContext
    :param instance context_manager: ContextManager instance
    :param dict fabric_config: configuration for running the commands
    """
    ctx.logger.info('configuring fabric environment...')
    # configure ssh user
    env.user = context_manager.get_ssh_user(ctx)
    # configure an ssk key file to use for remote connections
    env.key_filename = context_manager.get_ssh_key()
    # configure a password to use for remote connections
    env.password = context_manager.get_ssh_password()
    if not env.password and not env.key_filename:
        ctx.logger.error('you must supply at least one of ssh_key or ssh_pwd')
        raise RuntimeError('access creds not supplied')
    # should the command abort (sys.exit) upon error?
    env.warn_only = fabric_config['warn_only'] \
        if fabric_config['warn_only'] \
        else DEFAULT_WARN_ONLY
    # how many connection attempts to host should be initiated?
    env.connection_attempts = \
        fabric_config['connection_attempts'] \
        if fabric_config['connection_attempts'] \
        else DEFAULT_CONNECTION_ATTEMPTS
    # timeout for a single connection to the host
    env.timeout = fabric_config['timeout'] \
        if fabric_config['timeout'] \
        else DEFAULT_TIMEOUT
    # forward the ssh agent to the remote machine
    env.forward_agent = fabric_config['forward_agent'] \
        if fabric_config['forward_agent'] \
        else DEFAULT_FORWARD_AGENT

    # only defaults
    env.abort_on_prompts = True
    env.keepalive = 0
    env.linewise = False
    env.pool_size = 0
    env.skip_bad_hosts = False
    env.status = False
    env.disable_known_hosts = False
    ctx.logger.info('environment configured successfully')


def _run_with_retries(ctx, command, fabric_config):
    """runs a fabric command with retries

    :param ctx: CloudifyContext
    :param string command: command to run
    :param dict fabric_config: configuration for running the commands
    """
    # configure retry count, sleep time between retries, accepted error codes
    # and sudo state.
    attempts = fabric_config['attempts'] \
        if 'attempts' in fabric_config \
        else DEFAULT_ATTEMPTS
    sleep_between_attempts = fabric_config['sleep_between_attempts'] \
        if 'sleep_between_attempts' in fabric_config \
        else DEFAULT_ATTEMPTS_SLEEP
    accepted_err_codes = fabric_config['accepted_err_codes'] \
        if 'accepted_err_codes' in fabric_config \
        else []
    sudo = fabric_config['use_sudo'] \
        if 'use_sudo' in fabric_config \
        else DEFAULT_SUDO

    if attempts < 1:
        raise RuntimeError('attempts must be at least 1')
    if not sleep_between_attempts > 0:
        raise RuntimeError('sleep_time must be larger than 0')

    for execution in xrange(attempts):
        ctx.logger.info('running command: {0}'
                  .format(command))
        r = execute('sudo {0}'.format(command)) \
            if sudo \
            else execute(command)
        if r.succeeded or r.return_code in accepted_err_codes:
            ctx.logger.info('successfully ran command: {0}'
                      .format(command))
            # SUCCESS
            return r
        # RETRY
        ctx.logger.warning('failed to run: {0} -retrying ({1}/{2})'.format(
            command, execution + 1, attempts))
        time.sleep(sleep_between_attempts)
    ctx.logger.error('failed to run: {0}, {1}'.format(command, r.stderr))
    # FAILURE
    return r
