from fabric.api import run, cd
import os

LOGSTASH_DIR = '/opt/logstash'
LOGSTASH_FILE_NAME = 'logstash.tar.gz'
LOGSTASH_FILE_PATH = os.path.join(LOGSTASH_DIR, LOGSTASH_FILE_NAME)
LOGSTASH_URL = 'https://download.elasticsearch.org/logstash/logstash/logstash-1.4.1.tar.gz'  # NOQA
LOGSTASH_CONFIG_FILE_PATH = os.path.join(LOGSTASH_DIR, 'logstash.conf')

ELASTICSEARCH_DIR = '/opt/elasticsearch'
ELASTICSEARCH_FILE_NAME = 'elasticsearch.tar.gz'
ELASTICSEARCH_FILE_PATH = os.path.join(ELASTICSEARCH_DIR, LOGSTASH_FILE_NAME)
ELASTICSEARCH_URL = 'https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-1.2.1.tar.gz'  # NOQA

KIBANA_DIR = '/opt/kibana'
KIBANA_FILE_NAME = 'kibana.tar.gz'
KIBANA_FILE_PATH = os.path.join(KIBANA_DIR, KIBANA_FILE_NAME)
KIBANA_URL = 'https://download.elasticsearch.org/kibana/kibana/kibana-3.1.0.tar.gz'  # NOQA

NGINX_DIR = '/opt/nginx'
NGINX_SOURCE_REPOS = [
    'deb http://nginx.org/packages/mainline/ubuntu/ precise nginx',
    'deb-src http://nginx.org/packages/mainline/ubuntu/ precise nginx',
]
NGINX_SOURCE_KEY_URL = 'http://nginx.org/keys/nginx_signing.key'

GENERATOR_DIR = '/opt/generator'
GENERATOR_FILE_NAME = 'pylog.tar.gz'
GENERATOR_FILE_PATH = os.path.join(GENERATOR_DIR, GENERATOR_FILE_NAME)
GENERATOR_URL = 'https://github.com/nir0s/pylog/archive/master.tar.gz'


def install_logstash(ctx):
    run('sudo mkdir -p {}'.format(LOGSTASH_DIR))
    ctx.runtime_properties['logstash_config_path'] = ctx.download_resource(
        ctx.properties['logstash_config_file'])
    run('mv {0} {1}'.format(
        ctx.runtime_properties['logstash_config_path'],
        LOGSTASH_CONFIG_FILE_PATH))
    with cd(LOGSTASH_DIR):
        run('sudo wget {0} -O {1}'.format(LOGSTASH_URL, LOGSTASH_FILE_NAME))
        run('sudo tar -xzvf {} --strip=1'.format(LOGSTASH_FILE_NAME))
        run('sudo rm {}'.format(LOGSTASH_FILE_NAME))


def configure_logstash(ctx):
    run('sed -i s/ELASTICSEARCH_IP/{0}/g {1}'.format(
        ctx.related.run_time_properties['ip'], LOGSTASH_CONFIG_FILE_PATH))


def start_logstash(ctx):
    cores = run('nproc', capture=True)
    run('bin/logstash -w {0} -f {1}'.format(
        cores, LOGSTASH_CONFIG_FILE_PATH))


def stop_logstash(ctx):
    run('pkill -f logstash')


def install_elasticsearch(ctx):
    run('sudo mkdir -p {}'.format(ELASTICSEARCH_DIR))
    with cd(ELASTICSEARCH_DIR):
        run('sudo wget {0} -O {1}'.format(
            ELASTICSEARCH_URL, ELASTICSEARCH_FILE_NAME))
        run('sudo tar -xzvf {} --strip=1'.format(ELASTICSEARCH_FILE_NAME))
        run('sudo rm {}'.format(ELASTICSEARCH_FILE_NAME))


def start_elasticsearch(ctx):
    run('bin/elasticsearch')


def stop_elasticsearch(ctx):
    run('pkill -f elasticsearch')


def install_kibana(ctx):
    run('sudo mkdir -p {}'.format(KIBANA_DIR))
    with cd(KIBANA_DIR):
        run('sudo wget {0} -O {1}'.format(KIBANA_URL, KIBANA_FILE_NAME))
        run('sudo tar -xzvf {} --strip=1'.format(KIBANA_FILE_NAME))
        run('sudo rm {}'.format(KIBANA_FILE_NAME))


def configure_kibana(ctx):
    run('sed -i s/ELASTICSEARCH_IP/{0}/g {1}'.format(
        ctx.related.runtime_properties['ip'],
        os.path.join(KIBANA_DIR, 'config.js')))


def install_nginx(ctx):

    key_path = os.path.join(NGINX_DIR, 'repo_key.key')
    for repo in NGINX_SOURCE_REPOS:
        run('sudo sed -i "2i {0}" /etc/apt/sources.list'.format(repo))
    run('sudo wget {0} -O {1}'.format(
        NGINX_SOURCE_KEY_URL, key_path))
    run('sudo apt-key add {0}'.format(key_path))
    run('sudo apt-get install nginx -y')


def configure_nginx(ctx):
    return


def start_nginx(ctx):
    run('sudo service nginx start')


def stop_nginx(ctx):
    run('sudo service nginx stop')


def install_generator(ctx):
    with cd(GENERATOR_DIR):
        run('sudo wget {0} -O {1}'.format(GENERATOR_URL, GENERATOR_FILE_NAME))
        run('sudo tar -xzvf {} --strip=1')


def start_generator(ctx):
    run('python {0}'.format(os.path.join(GENERATOR_DIR, 'pylog.py')))


def stop_generator(ctx):
    run('pkill -f pylog')
