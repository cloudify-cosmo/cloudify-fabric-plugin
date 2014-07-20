from fabric.api import run, put, cd
import os

LOGSTASH_DIR = '/opt/logstash'
LOGSTASH_FILE_NAME = 'logstash.deb'
LOGSTASH_FILE_PATH = os.path.join(LOGSTASH_DIR, LOGSTASH_FILE_NAME)
LOGSTASH_CONFIG_FILE_PATH = os.path.join(LOGSTASH_DIR, 'logstash.conf')


def create(ctx):
    run('sudo apt-get update')
    run('sudo apt-get install openjdk-7-jdk -y')
    run('sudo mkdir -p {}'.format(LOGSTASH_DIR))
    with cd(LOGSTASH_DIR):
        run('sudo wget {0} -O {1}'.format(
            ctx.properties['logstash_url'], LOGSTASH_FILE_NAME))
        # run('sudo tar -xzvf {} --strip=1'.format(LOGSTASH_FILE_NAME))
        run('sudo dpkg -i {}'.format(LOGSTASH_FILE_NAME))
        run('sudo rm {}'.format(LOGSTASH_FILE_NAME))


def configure(ctx):
    logstash_config_file = ctx.download_resource(
        ctx.properties['logstash_config_file'])
    put(logstash_config_file, LOGSTASH_CONFIG_FILE_PATH)
    run('sudo sed -i "s/{{ logstash_port }}/{0}/g" {1}'.format(
        ctx.properties['logstash_pot'], LOGSTASH_CONFIG_FILE_PATH))


def start(ctx):
    run('sudo start logstash')


def stop(ctx):
    run('sudo stop logstash')


def delete(ctx):
    run('sudo stop logstash')
    run('sudo rm -rf {}'.format(LOGSTASH_DIR))
