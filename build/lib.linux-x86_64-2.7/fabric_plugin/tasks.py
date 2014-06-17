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

from cloudify.decorators import operation
from fabric.api import run as execute
from fabric.api import settings, env
from time import sleep
import sys
import os

DEFAULT_ATTEMPTS = 3
DEFAULT_ATTEMPTS_SLEEP = 3
DEFAULT_CONNECTION_ATTEMPTS = 5
DEFAULT_TIMEOUT = 10
DEFAULT_WARN_ONLY = True
DEFAULT_FORWARD_AGENT = True


@operation
def run_command(ctx, **kwargs):
    """runs a fabric command

    :param ctx: CloudifyContext
    """
    _configure_fabric_env(ctx)
    with settings(host_string=ctx):
        # iterate over a list of commands to execute
        for command in ctx.properties['commands']:
            _run_with_retries(ctx, command)


@operation
def run_task(ctx, **kwargs):
    """runs a set of fabric tasks

    Can receive a tasks file, a list of tasks and a list of excluded tasks,
    create a list of tasks to run, and execute them.
    """
    def _import_tasks_file(tasks_file):
        """imports the tasks file

        :param string tasks_file: path to file containing fabric tasks
        """
        ctx.logger.debug('importing tasks file...')
        sys.path.append(os.path.dirname(tasks_file))
        return __import__(os.path.basename(os.path.splitext(
            os.path.join(tasks_file))[0]))
        # TODO: check format
        sys.path.remove(os.path.dirname(tasks_file))

    # def _build_tasks_list(tasks, excluded_tasks, all_tasks):
    #     """builds the tasks list according to the excluded tasks list

    #     :param list tasks: list of task names to execute
    #     :param excluded_tasks: list of tasks to exclude
    #     :param
    #     """
    #     ctx.logger.debug('building tasks list...')
    #     tasks_list = tasks
    #     if tasks:
    #         # and raise if same task appears in both lists
    #         if set(tasks) & set(excluded_tasks):
    #             ctx.logger.error('your tasks list and excluded tasks '
    #                              'list contain a similar item.')
    #             raise RuntimeError('tasks list and excluded list '
    #                                'are conflicting')
    #     else:
    #         for task in tasks:
    #             if hasattr(all_tasks, 'task_{}'.format(task)):
    #                 tasks_list.append(task)

    #         # and rewrite the list after removing excluded tasks
    #         for ex_task in excluded_tasks:
    #             tasks_list = [task for task in tasks_list if task != ex_task]
    #     return tasks_list

    _configure_fabric_env(ctx)

    # tasks_list = ctx.properties['tasks_list']
    # excluded_list = ctx.properties['excluded_list']
    # tasks = _build_tasks_list(tasks_list, excluded_list)
    all_tasks = _import_tasks_file(tasks_file)

    if 'tasks_file' in ctx.properties:
        tasks_file = ctx.download_resource(properties['tasks_file'])
        operation_simple_name = ctx.operation.split('.')[-1:].pop()
        if not hasattr(all_tasks, operation_simple_name):
            ctx.logger.info("No task mapping found for operation {0}. "
                            "Nothing to do.".format(operation_simple_name))
            return None
        with settings(host_string=ctx):
            getattr(all_tasks, task)(ctx.properties)


def _configure_fabric_env(ctx):
    """configures fabric environment variables
    """
    try:
        # configure ssh user
        env.user = ctx.properties['fabric_config']['ssh_user']
    except:
        ctx.logger.error('no user configured for ssh connections')
        raise RuntimeError('no user configured')
    try:
        # configure an ssk key file to use for remote connections
        env.key_filename = ctx.properties['fabric_config']['ssh_key_path']
    except KeyError:
        # configure a password to use for remote connections
        env.password = ctx.properties['fabric_config']['ssh_password']
    except:
        ctx.logger.error('missing ssh key or password')
        raise RuntimeError('key or password must be supplied')

    # should the command abort (sys.exit) upon error?
    env.warn_only = ctx.properties['fabric_config']['warn_only'] \
        if ctx.properties['fabric_config']['warn_only'] else DEFAULT_WARN_ONLY
    # should the command abort upon prompt for user
    env.abort_on_prompts = True
    # how many connection attempts to host should be initiated?
    env.connection_attempts = ctx.properties['fabric_config']['connection_attempts'] \  # NOQA
        if ctx.properties['fabric_config']['warn_only'] else DEFAULT_CONNECTION_ATTEMPTS  # NOQA
    env.keepalive = 0
    env.linewise = False
    env.pool_size = 0
    env.skip_bad_hosts = False
    # timeout for a single connection to the host
    env.timeout = ctx.properties['fabric_config']['timeout'] \
        if ctx.properties['fabric_config']['timeout'] else DEFAULT_TIMEOUT
    # forward the ssh agent to the remote machine
    env.forward_agent = ctx.properties['fabric_config']['forward_agent'] \
        if ctx.properties['fabric_config']['forward_agent'] \
        else DEFAULT_FORWARD_AGENT
    env.status = False
    env.disable_known_hosts = False


def _run_with_retries(ctx, command):
    """runs a fabric command with retries
    """
    # configure retries and sleep time
    attempts = ctx.properties['fabric_config']['attempts'] \
        if ctx.properties['fabric_config']['attempts'] else DEFAULT_ATTEMPTS
    sleep_between_attempts = \
        ctx.properties['fabric_config']['sleep_between_attempts'] \
        if ctx.properties['fabric_config']['sleep_between_attempts'] \
        else DEFAULT_ATTEMPTS_SLEEP
    accepted_err_codes = \
        ctx.properties['fabric_config']['accepted_err_codes'] \
        if ctx.properties['fabric_config']['accepted_err_codes'] else []

    if attempts < 1:
        raise RuntimeError('attempts must be at least 1')
    if not sleep_between_attempts > 0:
        raise RuntimeError('sleep_time must be larger than 0')

    for execution in xrange(attempts):
        ctx.logger.debug('running command: {0}'
                  .format(command))
        r = execute('sudo {0}'.format(command)) \
            if ctx.properties['fabric_config']['use_sudo'] \
            else execute(command)
        if r.succeeded or r.return_code in accepted_err_codes:
            ctx.logger.debug('successfully ran command: {0}'
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
