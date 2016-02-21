# standard library imports
import base64
import os.path
import sys

# installed libraries imports
import winrm

# our library imports
from cloudify import ctx
from cloudify.decorators import operation
from cloudify.exceptions import NonRecoverableError


@operation
def run_script(address, username, password, process, local_file_path,
               delete_after_running=True, remote_script_path=None,
               winrm_port=5985, winrm_protocol="http", **kwargs):

    remote_script_file_name = "\\script" + os.path.splitext(local_file_path)[1]

    conn = get_conn(winrm_protocol, address, password, username, winrm_port)

    remote_shell_id = get_remote_shell_id(conn)

    powershell_path = define_script_path(remote_script_path, False)

    encoded_script = create_script_creation_command(
            local_file_path, powershell_path, remote_script_file_name)

    # copy the script file
    ctx.logger.info('Copying script file on remote machine')
    run_remote_command(remote_shell_id, 'powershell', '-encodedcommand',
                       ' {0}'.format(encoded_script), conn)

    cmd_path = define_script_path(remote_script_path)
    ctx.logger.info('Running the script on remote machine')
    run_remote_command(remote_shell_id, process, cmd_path,
                       remote_script_file_name, conn)

    if delete_after_running:
        ctx.logger.info('Removing script file from remote machine')
        run_remote_command(remote_shell_id, 'del', cmd_path,
                           remote_script_file_name, conn)


@operation
def run_commands(commands, address, username, password,
                 process, winrm_port=5985, winrm_protocol='http', **kwargs):

    conn = get_conn(winrm_protocol, address, password, username, winrm_port)

    remote_shell_id = get_remote_shell_id(conn)

    for command in commands:
        encode_command = create_encoded_command(command)
        ctx.logger.info('running command: {0}'.format(encode_command))
        run_remote_command(remote_shell_id, process,  encode_command, ' ', conn)


def define_script_path(remote_script_path, is_cmd=True):

    tmp_env_var = '%TEMP%' if is_cmd else '$env:TEMP'
    return remote_script_path if remote_script_path else tmp_env_var


def get_conn(winrm_protocol, address, password, username, winrm_port):

    endpoint = '{0}://{1}:{2}/wsman'.format(winrm_protocol, address, winrm_port)
    return winrm.Protocol(endpoint=endpoint, transport="plaintext",
                          username=username, password=password)


def get_remote_shell_id(conn):
    try:
        return conn.open_shell()
    except winrm.exceptions.UnauthorizedError as remote_shell_error:
        raise NonRecoverableError('Can\'t create connection.'
                                  '({0})').format(str(remote_shell_error))
        sys.exit()


def create_script_creation_command(local_file_path, powershell_path,
                                   remote_script_file_name):

    with open(local_file_path, 'r') as script_file:
        script_content = script_file.read()
    script_creator_cmd_prefix = '''$stream = [System.IO.StreamWriter] "{0}{1}";
                                   $s = @'\n'''.format(powershell_path,
                                                       remote_script_file_name)

    script_creator_cmd_suffix = \
        '''\n'@ | %{ $_.Replace('`n','`r`n') }; $stream.WriteLine($s)
        $stream.close()'''
    command = \
        script_creator_cmd_prefix + script_content + script_creator_cmd_suffix
    return base64.b64encode(command.encode("utf_16_le"))


def create_encoded_command(command):
    return base64.b64encode(command.encode("utf_16_le"))


def run_remote_command(remote_shell_id, process, cmd_path,
                       remote_script_file_name, conn):
    command_id = conn.run_command(
            remote_shell_id, '{0} {1}{2}'.format(process, cmd_path,
                                                 remote_script_file_name))
    stdout, stderr, return_code = conn.get_command_output(remote_shell_id,
                                                          command_id)
    conn.cleanup_command(remote_shell_id, command_id)
    ctx.logger.info('STDOUT: {0}'.format(stdout))
    ctx.logger.info('STDERR: {0}'.format(stderr))
