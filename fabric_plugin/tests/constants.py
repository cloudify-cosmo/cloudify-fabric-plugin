CONFIG_ARG = {
    'connect_kwargs': {
        'key_filename': '/mock_os_path_expanduser/',
        'allow_agent': True,
        'password': None
    },
    'port': 22222,
    'timeouts': {'command': None, 'connect': 10},
    'forward_agent': None,
    'load_ssh_configs': False,
}

SET_DEFAULTS = {
    'run': {
        'asynchronous': False,
        'disown': False,
        'dry': False,
        'echo': False,
        'echo_stdin': None,
        'encoding': None,
        'env': {},
        'err_stream': None,
        'fallback': True,
        'hide': None,
        'in_stream': None,
        'out_stream': None,
        'echo_format': '\x1b[1;37m{command}\x1b[0m',
        'pty': False,
        'replace_env': True,
        'shell': '/bin/bash',
        'warn': False,
        'watchers': []
    },
    'sudo': {
        'password': None,
        'prompt': '[sudo] password: ',
        'user': None
    },
    'tasks': {
        'auto_dash_names': True,
        'collection_name': 'fabfile',
        'dedupe': True,
        'executor_class': None,
        'ignore_unknown_help': False,
        'search_root': None
    },
    'timeouts': {
        'command': None,
        'connect': 10
    },
    'gateway': None,
    'inline_ssh_env': False,
    'port': 22222,
    'ssh_config_path': None,
    'user': 'foo_user'
}
