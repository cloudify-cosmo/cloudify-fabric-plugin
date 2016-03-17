
from winrn_plugin import get_remote_shell_id
import winrm

from cloudify.exceptions import NonRecoverableError


def test_failed_to_get_remote_shell(self):
    try:
        get_remote_shell_id('banana')
    except NonRecoverableError as ex:
        self.assertIn('Can\'t create connection.', str(ex))


def test_get_conn(self)
    conn = get_conn('http', '1.1.1.1', 'x', 'y', 5985)
    self.assertEqual(conn, )