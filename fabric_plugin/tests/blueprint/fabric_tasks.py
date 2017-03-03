from cloudify import ctx


def task():
    ctx.instance.runtime_properties['task_called'] = 'called'


def test_task_properties(arg):
    ctx.instance.runtime_properties['arg'] = arg


def test_implicit_host_string():
    ctx.instance.runtime_properties['expected_host_string'] = \
        ctx.instance.host_ip


non_callable = 1
