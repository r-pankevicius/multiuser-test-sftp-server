import time
import socket
import optparse
import sys
import textwrap
import os
import os.path

import paramiko
from paramiko import ServerInterface, SFTPServerInterface, SFTPServer, SFTPAttributes, \
    SFTPHandle, SFTP_OK, AUTH_SUCCESSFUL, AUTH_FAILED, OPEN_SUCCEEDED

import threading

HOST, PORT = 'localhost', 3373
BACKLOG = 10
# SFTP root folder: String
DATAFOLDER = None
# User names-passwords: Dictionary(string, string)
USERS = {}

from sftpserver.stub_sftp import StubServer, StubSFTPServer

class MyStubSFTPServer(StubSFTPServer):
    global DATAFOLDER, USERS

    def __init__(self, *largs, **kwargs):
        self.ROOT = DATAFOLDER
        userFolder = os.path.join(DATAFOLDER, largs[0].USERNAME) # largs[0] is MyStubServer
        if os.path.isdir(userFolder):
            self.ROOT = userFolder

class MyStubServer(ServerInterface):
    USERNAME = None

    def check_auth_password(self, username, password):
        if username in USERS and USERS[username] == password:
            self.USERNAME = username
            return AUTH_SUCCESSFUL
        return AUTH_FAILED
        
    def check_auth_publickey(self, username, key):
        # Don't allow publickey
        return AUTH_FAILED
        
    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        """List availble auth mechanisms."""
        return "password"


class ConnHandlerThd(threading.Thread):
    def __init__(self, conn, keyfile):
        threading.Thread.__init__(self)
        self._conn = conn
        self._keyfile = keyfile

    def run(self):
        
        host_key = paramiko.RSAKey.from_private_key_file(self._keyfile)
        transport = paramiko.Transport(self._conn)
        transport.add_server_key(host_key)
        transport.set_subsystem_handler(
            'sftp', paramiko.SFTPServer, MyStubSFTPServer)

        server = MyStubServer()
        transport.start_server(server=server)

        channel = transport.accept()
        while transport.is_active():
            time.sleep(1)


def start_server(host, port, keyfile, level):
    paramiko_level = getattr(paramiko.common, level)
    paramiko.common.logging.basicConfig(level=paramiko_level)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    server_socket.bind((host, port))
    server_socket.listen(BACKLOG)

    while True:
        conn, addr = server_socket.accept()

        srv_thd = ConnHandlerThd(conn, keyfile)
        srv_thd.setDaemon(True)
        srv_thd.start()

def read_users_config(folder):
    # Find file .sftpusers.cfg, it contains username:password pairs
    global DATAFOLDER, USERS
    users = {}
    user_config_file_path = os.path.join(folder, '.sftpusers.cfg')
    if not os.path.isfile(user_config_file_path):
        raise ValueError(f'Required users configuration file was not found {user_config_file_path}')

    if os.path.isfile(user_config_file_path):
        with open(user_config_file_path, 'r') as fstream:
            line_number = 0
            for line in fstream:
                line_number += 1
                line = line.strip()
                
                def raiseError(error):
                    raise ValueError(f'Error in file {user_config_file_path} line {line_number}: "{line}". {error}.')

                if line != '' and line[0] != '#':
                    parts = line.split(':')
                    if len(parts) == 2 and len(parts[0]) != 0 and len(parts[1]) != 0:
                        username = parts[0]
                        if username in users:
                            raiseError('Username is already configured')
                        userFolder = os.path.join(DATAFOLDER, username)
                        if not os.path.isdir(userFolder):
                            raiseError(f'There is no folder for user {username}')
                        password = parts[1]
                        users[username] = password
                    else:
                        raiseError('Syntax error')

    if len(users) > 0:
        USERS = users

def main():
    usage = """\
    usage: sftpserver [options]
    -k/--keyfile should be specified
    """
    parser = optparse.OptionParser(usage=textwrap.dedent(usage))
    parser.add_option(
        '--host', dest='host', default=HOST,
        help='listen on HOST [default: %default]')
    parser.add_option(
        '-p', '--port', dest='port', type='int', default=PORT,
        help='listen on PORT [default: %default]'
        )
    parser.add_option(
        '-l', '--level', dest='level', default='INFO',
        help='Debug level: WARNING, INFO, DEBUG [default: %default]'
        )
    parser.add_option(
        '-k', '--keyfile', dest='keyfile', metavar='FILE',
        help='Path to private key, for example /tmp/test_rsa.key'
        )
    parser.add_option(
        '-d', '--data', dest='data',
        help='Folder where data files are (default is current folder)'
        )

    options, args = parser.parse_args()

    if options.keyfile is None:
        parser.print_help()
        sys.exit(-1)

    global DATAFOLDER, USERS
    if options.data is not None:
        DATAFOLDER = os.path.abspath(options.data)
    else:
        DATAFOLDER = os.getcwd()

    # Both for setting root files folder and failing at start if it doesn't exist
    os.chdir(DATAFOLDER)

    read_users_config('.')
    print(f'Working folder is "{DATAFOLDER}"". Number of users is {len(USERS)}.')

    if len(USERS) == 0:
        print('No users configured - server won\'t start')
        return

    start_server(options.host, options.port, options.keyfile, options.level)

if __name__ == '__main__':
    main()
