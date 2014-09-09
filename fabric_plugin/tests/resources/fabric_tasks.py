from fabric import api

def stub(ctx):
    pass

def task(ctx):
    api.run('echo {0}'.format(ctx.blueprint_id))
    api.run('ls')
