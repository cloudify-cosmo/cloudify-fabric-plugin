from fabric.api import run, cd
import os

LOGSTASH_DIR = '/opt/logstash'
LOGSTASH_FILE_NAME = 'logstash.tar.gz'
LOGSTASH_FILE_PATH = os.path.join(LOGSTASH_DIR, LOGSTASH_FILE_NAME)
LOGSTASH_URL = 'https://download.elasticsearch.org/logstash/logstash/logstash-1.4.1.tar.gz'  # NOQA


def install_logstash(ctx):
    run('sudo mkdir -p {}'.format(LOGSTASH_DIR))
    cores = run('nproc', capture=True)
    with cd(LOGSTASH_DIR):
        run('sudo wget {0} -O {1}'.format(LOGSTASH_URL, LOGSTASH_FILE_NAME))
        run('sudo tar -xzvf {} --strip=1'.format(LOGSTASH_FILE_NAME))
        run('sudo rm {}'.format(LOGSTASH_FILE_NAME))
        run('bin/logstash -w {} -f '.format(cores))
