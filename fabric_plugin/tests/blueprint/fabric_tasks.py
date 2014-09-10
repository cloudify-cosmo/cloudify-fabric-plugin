

def task(ctx):
    ctx.runtime_properties['task_called'] = 'called'


def test_implicit_host_string(ctx):
    ctx.runtime_properties['expected_host_string'] = ctx.host_ip

non_callable = 1
