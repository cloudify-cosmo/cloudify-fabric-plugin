
Execution Methods
=================

There are 4 modes for working with this plugin.

* Executing a list of `commands`_.
* Executing Fabric `tasks`_ from a ``tasks_file`` included in the blueprint's directory.
* Executing a Fabric task by specifying its path in the current python environment.
  (`run_module_task`_)
* Executing `scripts`_ by specifying the script's path or URL.


.. _commands:

Commands
--------

::

    imports:
        - {{< field "yaml_link" >}}

    node_templates:
      example_node:
        type: cloudify.nodes.WebServer
        interfaces:
          cloudify.interfaces.lifecycle:
              start:
                implementation: fabric.fabric_plugin.tasks.run_commands
                inputs:
                  commands:
                    - echo "source ~/myfile" >> ~/.bashrc
                    - apt-get install -y python-dev git
                    - pip install my_module

Here, we use the ``run_commands`` plugin task and specify a list of commands to execute on the agent host.


.. _tasks:

Tasks
-----

::

    imports:
        - {{< field "yaml_link" >}}

    node_templates:
      example_node:
        type: cloudify.nodes.WebServer
        interfaces:
          cloudify.interfaces.lifecycle:
            start:
              implementation: fabric.fabric_plugin.tasks.run_task
              inputs:
                tasks_file: my_tasks/tasks.py
                task_name: install_nginx
                task_properties:
                  important_prop1: very_important
                  important_prop2: 300

Here, we specify the tasks file path relative to the blueprint's directory,
the task's name in that file and (optional) task properties
that will be used when actually calling the task.

An example of a tasks file would be:

.. code-block:: python

    #my_tasks/tasks.py
    from fabric.api import run, put
    from cloudify import ctx

    def install_nginx(important_prop1, important_prop2):
        ctx.logger.info('Installing nginx. Some important props:'
                        ' prop1: {0}, prop2: {1}'
                        .format(important_prop1, important_prop2))
        run('sudo apt-get install nginx')


    def configure_nginx(config_file_path):
        # configure the webserver to run with our premade configuration file.
        conf_file = ctx.download_resource(config_file_path)
        put(conf_file, '/etc/nginx/conf.d/')


    def start_nginx(ctx):
        run('sudo service nginx restart')


.. _run_module_task:

Module Tasks
------------

::

    imports:
        - {{< field "yaml_link" >}}

    node_templates:
      example_node:
        type: cloudify.nodes.WebServer
        interfaces:
          cloudify.interfaces.lifecycle:
            start:
              implementation: fabric.fabric_plugin.tasks.run_module_task
              inputs:
                task_mapping: some_package.some_module.install_nginx
                task_properties:
                  important_prop1: very_important
                  important_prop2: 300

This example is very similar to the previous one with the following difference.
If the fabric task you want to execute is already installed
in the python environment in which the operation will run,
you can specify the python path to this function.


.. _scripts:

Scripts
-------

The fabric plugin can execute scripts remotely and provides access to the ``ctx`` API for interacting with Cloudify
in the same manner as the `script plugin <../script/>`_ does.

Example::

    node_templates:
      example_node:
        type: cloudify.nodes.WebServer
        interfaces:
          cloudify.interfaces.lifecycle:
            start:
              implementation: fabric.fabric_plugin.tasks.run_script
              inputs:
                # Path to the script relative to the blueprint directory
                script_path: scripts/start.sh
                MY_ENV_VAR: some-value

.. note::
   Starting with Cloudify 3.4,
   the `ctx` object can be used in Python scripts executed
   by the fabric plugin the same way it is used in the script plugin
   aside from a few minor differences.
   See `ctx for fabric-plugin`_ for more info.


Operation Inputs
^^^^^^^^^^^^^^^^

Operation inputs passed to the ``run_script`` task will be available
as environment variables in the script's execution environment.
Complex data structures such as dictionaries and lists will be
JSON encoded when exported as environment variables.

.. note::
    ``fabric_env``, ``script_path``, ``use_sudo``, ``hide_output`` and ``process``
    are reserved operation inputs used by the ``run_script`` task
    and therefore won't be available as environment variables.


Process Configuration
^^^^^^^^^^^^^^^^^^^^^

The ``run_script`` task accepts a ``process`` input which allows configuring the process which runs the script:

* ``cwd`` - The working directory to use when running the script.
* ``args`` - List of arguments to pass to the script.
* ``command_prefix`` - The command prefix to use when running the script. This is not necessary if the script contains the ``#!`` line.
* ``env`` - Dictionary of environment variables to be incorporated into the script's process.

Example::

    node_templates:
      example_node:
        type: cloudify.nodes.WebServer
        interfaces:
          cloudify.interfaces.lifecycle:
            start:
              implementation: fabric.fabric_plugin.tasks.run_script
              inputs:
                script_path: scripts/start.sh
                # Optional
                process:
                  # Optional
                  cwd: /home/ubuntu
                  # Optional
                  command_prefix:
                  # Optional
                  args: [--arg1, --arg2, arg3]
                  # Optional
                  env:
                    MY_VAR_1: my_value_1
                    MY_VAR_2: my_value_2


Executing commands or scripts with sudo privileges
==================================================

The ``run_commands`` and ``run_script`` execution methods both accept a ``use_sudo`` input (which defaults to ``false``).
When true, the commands or script will be executed using sudo.
This allows, for instance, to use the ``sudo_prefix`` fabric env property to run an alternative implementation of sudo.
See additional sudo-related configuration which you can apply to your fabric env
:fabric_usage:`here <output_controls>`.

An example that uses ``use_sudo`` and ``sudo_prefix``::

    imports:
        - {{< field "yaml_link" >}}

    node_templates:
      example_node:
        type: cloudify.nodes.WebServer
        interfaces:
          cloudify.interfaces.lifecycle:
              create:
                implementation: fabric.fabric_plugin.tasks.run_commands
                inputs:
                  commands:
                    - apt-get install -y python-dev git
                    - echo 'config' > /etc/my_config
                  # if ``use_sudo`` is omitted, it defaults to ``false``
                  use_sudo: true
                  fabric_env:
                    host_string: 10.10.1.10
                    user: some_username
                    password: some_password
                    sudo_prefix: 'mysudo -c'


Hiding output
=============

Fabric generates output of its command execution.
You can hide some of that output to maybe make your execution logs more readable
or just ignore irrelevant data.

To hide output,
you can use the ``hide_output`` input to any of the four execution methods.
The ``hide_output`` input is a list of ``groups`` of outputs to hide as specified
:fabric_usage:`here <output_controls>`.
 
An example that uses ``hide_output``::

    imports:
        - {{< field "yaml_link" >}}

    node_templates:
      example_node:
        type: cloudify.nodes.WebServer
        interfaces:
          cloudify.interfaces.lifecycle:
            start:
              implementation: fabric.fabric_plugin.tasks.run_script
              inputs:
                # Path to the script relative to the blueprint directory
                script_path: scripts/start.sh
                MY_ENV_VAR: some-value
                # If omitted, nothing will be hidden
                hide_output:
                  - running
                  - warnings


SSH Configuration
=================

The fabric plugin will extract the correct host IP address based on the node's host.
It will also use the username and key file path if they were set globally during the bootstrap process.
However, it is possible to override these values and additional SSH configuration by passing ``fabric_env`` to operation inputs.
This applies to ``run_commands``, ``run_task`` and ``run_module_task``.
The ``fabric_env`` input is passed as is to the underlying library,
so check their :fabric_usage:`documentation <env>` for additional details.


An example that uses ``fabric_env``::

    imports:
        - {{< field "yaml_link" >}}

    node_templates:
      example_node:
        type: cloudify.nodes.WebServer
        interfaces:
          cloudify.interfaces.lifecycle:
            start:
              implementation: fabric.fabric_plugin.tasks.run_commands
              inputs:
                commands: [touch ~/my_file]
                fabric_env:
                  host_string: 192.168.10.13
                  user: some_username
                  key_filename: /path/to/key/file

.. note::
    Using a tasks file instead of a list of commands will allow you to use python code to execute commands. In addition, you would be able to use the ``ctx`` object to perform actions based on contextual data.

    Using a list of commands might be a good solution for very simple cases in which you wouldn't want to maintain a tasks file.


.. _ctx for fabric-plugin:

ctx for fabric-plugin
=====================

.. tip:: new in 1.4

Starting with Cloudify 3.4 and fabric-plugin 1.4, Cloudify now supports using ``ctx`` in Python scripts executed by the fabric plugin on remote machines. Most of the functionality is similiar to how the script plugin exposes the ``ctx`` object.

Executing ctx commands
----------------------

.. highlight:: python

Previously, to use the fabric plugin to execute Python scripts
you had to use ``ctx`` commands like so::

    os.system('ctx logger info Hello!')

Instead, you can now do one of two things to achieve the same result::

    from cloudify import ctx

    ctx.logger.info("Hello!")

or ::

    from cloudify import ctx

    ctx('logger info Hello!')

The first example shows native ``ctx`` usage
which can be used to perform most of the trivial actions
you can perform using the script plugin,
like

    * using the logger
    * retrieving runtime properties and setting them for node instances
    * setting the source/target node instances runtime properties in relationship operations
    * retrieving node properties
    * downloading blueprint resources
    * aborting operations, and more.

The second example shows that you can still use ``ctx``
to execute commands as if you're running it from a bash script.

The most notable difference is that to get all properties
for a node or runtime properties for a node instance
you would have to do the following::

    from cloudify import ctx

    my_node_properties = ctx.node.properties.get_all()
    my_instance_runtime_properties = ctx.instance.runtime_properties.get_all()

This is also true for ``source`` and ``target`` node properties and node instance runtime properties.
