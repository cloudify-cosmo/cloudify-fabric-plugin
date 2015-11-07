from cloudify import ctx


def task():
    ctx.instance.runtime_properties['task_called'] = 'called'


def test_task_properties(arg):
    ctx.instance.runtime_properties['arg'] = arg


def test_implicit_host_string():
    # TODO: use a different value, internal_manager_host is canceled
    # ctx.instance.runtime_properties['expected_host_string'] = \
    #     ctx.instance.internal_manager_host
    ctx.instance.runtime_properties['expected_host_string'] = \
        ctx.instance.private_ip

non_callable = 1
