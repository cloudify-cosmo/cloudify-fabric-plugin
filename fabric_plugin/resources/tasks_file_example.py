from fabric.api import run


# define an example task
# each task receives ctx so that it can refer to the node's properties
def example_task(ctx):
    # since you get ctx.. you can also use the logger
    ctx.logger.info('running example task...')
    # and then you can just run commands on the remote host.
    run('echo Hi!')
    # or commands with relation to the context
    run('echo {}'.format(ctx.properties['test_property']))
