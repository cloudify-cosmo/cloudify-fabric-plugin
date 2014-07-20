from fabric.api import run, cd
import os

KIBANA_DIR = '/opt/kibana'
KIBANA_FILE_NAME = 'kibana.tar.gz'
KIBANA_FILE_PATH = os.path.join(KIBANA_DIR, KIBANA_FILE_NAME)
KIBANA_CONFIG_FILE_PATH = os.path.join(KIBANA_DIR, 'config.js')


def create(ctx):
    run('sudo mkdir -p {}'.format(KIBANA_DIR))
    with cd(KIBANA_DIR):
        run('sudo wget {0} -O {1}'.format(
            ctx.properties['kibana_url'], KIBANA_FILE_NAME))
        run('sudo tar -xzvf {} --strip=1'.format(KIBANA_FILE_NAME))
        run('sudo rm {}'.format(KIBANA_FILE_NAME))


def configure(ctx):
    # kibana_config_file = ctx.download_resource(
    #     ctx.properties['KIBANA_config_file'])
    # put(kibana_config_file, KIBANA_CONFIG_FILE_PATH)
    run('sudo sed -i "s/\"+window.location.hostname+\"/{0}/g" {1}'.format(
        ctx.related.properties['ip'], KIBANA_CONFIG_FILE_PATH))


def start(ctx):
    run('sudo start KIBANA')


def stop(ctx):
    run('sudo stop KIBANA')


def delete(ctx):
    run('sudo stop KIBANA')
    run('sudo rm -rf {}'.format(KIBANA_DIR))
