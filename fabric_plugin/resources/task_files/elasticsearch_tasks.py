from fabric.api import run, cd
import os


ELASTICSEARCH_DIR = '/opt/elasticsearch'
ELASTICSEARCH_FILE_NAME = 'elasticsearch.deb'
ELASTICSEARCH_FILE_PATH = os.path.join(
    ELASTICSEARCH_DIR, ELASTICSEARCH_FILE_NAME)
ELASTICSEARCH_URL = 'https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.2.1.tar.gz'  # NOQA


def create(ctx):
    run('sudo apt-get update')
    run('sudo apt-get install openjdk-7-jdk -y')
    run('sudo mkdir -p {}'.format(ELASTICSEARCH_DIR))
    with cd(ELASTICSEARCH_DIR):
        run('sudo wget {0} -O {1}'.format(
            ctx.properties['elasticsearch_url'], ELASTICSEARCH_FILE_NAME))
        # run('sudo tar -xzvf {} --strip=1'.format(ELASTICSEARCH_FILE_NAME))
        run('sudo dpkg -i {}'.format(ELASTICSEARCH_FILE_NAME))
        run('sudo rm {}'.format(ELASTICSEARCH_FILE_NAME))


def configure(ctx):
    run('sudo update-rc.d elasticsearch defaults 95 10')


def start(ctx):
    run('sudo start elasticsearch')


def stop(ctx):
    run('sudo stop elasticsearch')


def delete(ctx):
    run('sudo stop elasticsearch')
    run('sudo rm -rf {}'.format(ELASTICSEARCH_DIR))
