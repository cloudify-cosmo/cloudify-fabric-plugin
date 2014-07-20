from fabric.api import run, put
import os

NGINX_CONFIG_FILE_PATH = os.path.join('/etc/nginx/conf.d', 'nginx.conf')


def create(ctx):
    run('sudo apt-get update')
    for repo in ctx.properties['nginx_source_repos']:
        run('sudo sed -i "2i {0}" /etc/apt/sources.list'.format(repo))
    run('sudo apt-key add {0}'.format(ctx.properties['nginx_source_key']))
    run('sudo apt-get install nginx -y')


def configure(ctx):
    run('sudo service nginx stop')
    nginx_config_file = ctx.download_resource(
        ctx.properties['nginx_config_file'])
    put(nginx_config_file, NGINX_CONFIG_FILE_PATH)
    run('sudo sed -i "s/{{ kibana_port }}/{0}/g" {1}'.format(
        ctx.properties['kibana_port'], NGINX_CONFIG_FILE_PATH))


def start(ctx):
    run('sudo service nginx start')


def stop(ctx):
    run('sudo service nginx stop')


def delete(ctx):
    run('sudo service nginx stop')
    run('sudo apt-get remove nginx')
    run('sudo apt-get purge nginx')
