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


from time import sleep
import sys
import os

from fabric.api import run as execute
from fabric.api import settings, env

from cloudify.decorators import operation
from cloudify.manager import get_rest_client


DEFAULT_ATTEMPTS = 3
DEFAULT_ATTEMPTS_SLEEP = 3
DEFAULT_CONNECTION_ATTEMPTS = 5
DEFAULT_SUDO = False
DEFAULT_TIMEOUT = 10
DEFAULT_WARN_ONLY = True
DEFAULT_FORWARD_AGENT = True

FABRIC_CONFIG = 'fabric_config'


@operation
def run_command(ctx, **kwargs):
    """runs a fabric command

    for each workflow operation (create, start, stop, etc..)
    runs a list of commands

    :param ctx: CloudifyContext
    :returns: None if no commands were specified, else runs the commands.
    :rtype: None
    """
    if 'commands' in ctx.properties:
        # create context manager instance
        context_manager = ContextManager(ctx)
        # extract fabric configuration from context properties.
        fabric_config = context_manager.get_fabric_config()
        # extract workflow task name
        operation_simple_name = context_manager.get_operation_simple_name
        # configure fabric environment
        _configure_fabric_env(ctx, context_manager, fabric_config)
        # get commands list from context
        command_list = context_manager.get_commands_list(operation_simple_name)
        # if no commands are supplied, return.
        if not command_list:
            ctx.logger.info("no command mapping found for operation {0}. "
                            "nothing to do.".format(operation_simple_name))
            return None
        # iterate over the commands list and run the command
        # the remote host's ip is retrieved prior to this
        with settings(host_string=context_manager.get_host_ip(ctx)):
            for command in command_list:
                _run_with_retries(ctx, command, fabric_config)


@operation
def run_task(ctx, **kwargs):
    """runs a set of fabric tasks

    imports a tasks file with basic workflow operations (create, start, stop..)
    and runs the called task accordingly to the mapped operation in the
    blueprint.

    :param ctx: CloudifyContext
    :returns: None if no commands were specified, else runs the task.
    :rtype: None
    """
    def _import_tasks_file(tasks_file):
        """returns the imported tasks file

        :param string tasks_file: path to file containing fabric tasks
        """
        ctx.logger.debug('importing tasks file...')
        sys.path.append(os.path.dirname(tasks_file))
        return __import__(os.path.basename(os.path.splitext(
            os.path.join(tasks_file))[0]))
        # TODO: check format
        sys.path.remove(os.path.dirname(tasks_file))

    if 'tasks_file' in ctx.properties:
        # create context manager instance
        context_manager = ContextManager(ctx)
        # extract fabric configuration from context properties.
        fabric_config = context_manager.get_fabric_config()
        # extract workflow task name
        operation_simple_name = context_manager.get_operation_simple_name
        # configure fabric environment
        _configure_fabric_env(ctx, context_manager, fabric_config)
        # download the tasks file
        tasks_file = context_manager.get_tasks_file()
        # imports the tasks file to retrieve its attributes
        all_tasks = _import_tasks_file(tasks_file)
        # if no task file is supplied, return.
        if not hasattr(all_tasks, operation_simple_name):
            ctx.logger.info("no task mapping found for operation {0}. "
                            "nothing to do.".format(operation_simple_name))
            return None
        # run the task
        # the remote host's ip is retrieved prior to this
        with settings(host_string=context_manager.get_host_ip(ctx)):
            ctx.logger.info('running task: {0} from {1}'.format(
                operation_simple_name, tasks_file))
            getattr(all_tasks, operation_simple_name)(ctx)


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

    # TODO: add this to plugins common
    def get_host_ip(self):
        """returns the host ip to run tasks or commands on"""
        self.logger.debug('getting remote host ip...')
        # initialize rest client
        client = get_rest_client()
        # get the node instance id
        node_instance = client.node_instances.get(self.ctx.id)
        # get the host id from the node instance
        host_id = node_instance.host_id
        # if the node to run on is the vm itself, just return the ip
        if host_id == self.ctx.id:
            ip = node_instance.runtime_properties['ip']
        # else, get the host_id for the node, and then return the ip
        else:
            host_node_instance = client.node_instances.get(host_id)
            ip = host_node_instance.runtime_properties['ip']
        self.logger.debug('remote host ip is: {0}'.format(ip))
        return ip

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

    def get_operation_simple_name(self):
        return self.ctx.operation.split('.')[-1:].pop()

    def get_commands_list(self, operation_simple_name):
        """returns a list of commands"""
        return self.ctx.properties['commands'][operation_simple_name]

    def get_tasks_file(self, operation_simple_name):
        """downloads the tasks file and returns its path"""
        return self.ctx.download_resource(self.ctx.properties['tasks_file'])


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
        sleep(sleep_between_attempts)
    ctx.logger.error('failed to run: {0}, {1}'.format(command, r.stderr))
    # FAILURE
    return r
