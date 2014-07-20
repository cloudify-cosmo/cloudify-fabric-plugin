from fabric.api import run, put, cd
import os

PYLOG_DIR = '/opt/pylog'
PYLOG_CONFIG_FILE_PATH = os.path.join(PYLOG_DIR, 'config.py')

PIP_URL = 'https://bootstrap.pypa.io/get-pip.py'


def create(ctx):
    run('sudo apt-get install curl -y')
    run('sudo curl --silent --show-error --retry 5 {} | sudo python'.format(
        PIP_URL))
    run('sudo pip install pylog')


def configure(ctx):
    pylog_config_file = ctx.download_resource(
        ctx.properties['pylog_config_file'])
    put(pylog_config_file, PYLOG_CONFIG_FILE_PATH)


def start(ctx):
    with cd(PYLOG_DIR):
        run('sudo nohup pylog -m 1000000000 -g 1')


def stop(ctx):
    run('sudo pkill -f pylog')


def delete(ctx):
    run('sudo pkill -f pylog')
    run('sudo pip uninstall pylog')
    run('sudo rm -rf {}'.format(PYLOG_DIR))
