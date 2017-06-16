#!/usr/bin/env python

"""
Proxy for project Honepot as a Service by CZ.NIC. This proxy is needed to
tag SSH activity with your account ID so you can watch your log online.

Script has hardcoded address of honeypot running at CZ.NIC. It shouldn't
be changed but if does or you need to use proxy or send it to own honeypot,
use optional arguments honeypot-host and honeypot-port.

Script contains one pre-generated key. If you want to use own, create one
with following command:

    $ ssh-keygen -t rsa -b 4096

Store it in some path and then pass it as:

    --public-key "$(< /path/id_rsa.pub)" --private-key "$(< /path/id_rsa)"
"""

import argparse
import fcntl
import json
import os
import pwd
import struct
import sys
import tty

from twisted import cred
from twisted.conch.avatar import ConchUser
from twisted.conch.ssh import factory, keys, userauth, connection, session
from twisted.conch.unix import SSHSessionForUnixConchUser
from twisted.internet import reactor, defer
from twisted.python import log
from twisted.python import components


DEFAULT_PORT = 5022
DEFAULT_HONEYPOT_HOST = 'localhost'
DEFAULT_HONEYPOT_PORT = 2222

# pylint: disable=line-too-long
DEFAULT_PUBLIC_KEY = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC2jdAE4EAAKikW6W/dDmWS/0lQ1jWM6c6Ef+KpGr+jW83/XIR2reWXeeDTIEluL20JV/P2+2bvVShNr4w8SWitcYKTpwkSgGYHo2vAQvXArx/CsRnTAP6NwrxuZoLNO52fMXQWSrqs0tEvkzYXR3PcR6Cq07RN7QkYNWctCYJxdw=='
DEFAULT_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC2jdAE4EAAKikW6W/dDmWS/0lQ1jWM6c6Ef+KpGr+jW83/XIR2
reWXeeDTIEluL20JV/P2+2bvVShNr4w8SWitcYKTpwkSgGYHo2vAQvXArx/CsRnT
AP6NwrxuZoLNO52fMXQWSrqs0tEvkzYXR3PcR6Cq07RN7QkYNWctCYJxdwIDAQAB
AoGAMOy4v1XKUUD7WiSd0kS1fDvmzj9agrV2n5QWjvOYQJOuFa4Z4iSgz4PeeTbB
90HGmyZzP9IIuEO+VXOixdV2s/DQ9fGjaBUb95+tYu94KM3tIq9B3kETQwtl+TxE
FywSM9kQGt65ob26K6BbOIZPnF2e6rMEy0pD1UJ2vKDs1wECQQDsEmXZtqh7ktC6
MIKmXegADwEiwnQN+lnboAXDNVQCMWKiWg/Ih4NpDoG9x+OIuVRRz5jEHYyRz8nt
/yvnsRZhAkEAxfbfWWZT+TjwbiSj2/rHg0+2W0LxiJhJJNZDaL/Ad0KcW702CoAc
xWk5uC4dzS9xq9fULN0IYXmPe/5vNZ5m1wJAD3E4pmAzbznwW22W7kkQRwi0O1Db
BJsOy7YRCm7vmuEeIZ6gj66Foxam2AI+WRA+eseIp7ODIXqlK+NYPOSxoQJAYbMt
F5oA54bKYhGDLRXfUVcN0IyBV8CQmLWGHzRDcJhXQo9nFFeV23fLHLLl0lYP65dh
B6Mud6zeu3set3+tkQJBAK8bVknHYkapijQNoM7slRZqgeBUImktJI0qq+YTEspr
za4ElES2AJye2cxYTx8zn59ppadHV2GIJZpj+hJvkzU=
-----END RSA PRIVATE KEY-----"""


def main():
    """
    Main endpoint to run script.
    """
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-u', '--user-id',
        dest='user_id',
        required=True,
        help='Your ID at honeypot.labs.nic.cz. If you don\'t have one, sign up first.',
    )
    parser.add_argument(
        '-p', '--port',
        dest='port',
        type=int,
        default=DEFAULT_PORT,
        help='Port to listen to, default {}.'.format(DEFAULT_PORT),
    )
    parser.add_argument('--honeypot-host', dest='honeypot_host', default=DEFAULT_HONEYPOT_HOST)
    parser.add_argument('--honeypot-port', dest='honeypot_port', default=DEFAULT_HONEYPOT_PORT)
    parser.add_argument('--public-key', dest='public_key', default=DEFAULT_PUBLIC_KEY)
    parser.add_argument('--private-key', dest='private_key', default=DEFAULT_PRIVATE_KEY)
    args = parser.parse_args()

    log.startLogging(sys.stderr)
    reactor.listenTCP(args.port, ProxySSHFactory(args))  # pylint: disable=no-member
    reactor.run()  # pylint: disable=no-member


def force_text(value):
    """
    Helper to deal with bytes and str in Python 2 vs. Python 3. Needed to have
    always username and password as a string (i Python 3 it's bytes).
    """
    if issubclass(type(value), str):
        return value
    if isinstance(value, bytes):
        return str(value, 'utf-8')
    return str(value)


# pylint: disable=abstract-method
class ProxySSHFactory(factory.SSHFactory):
    """
    Factory putting together all pieces of SSH proxy to honeypot together.
    """

    def __init__(self, cmd_args):
        self.publicKeys = {b'ssh-rsa': keys.Key.fromString(data=cmd_args.public_key)}
        self.privateKeys = {b'ssh-rsa': keys.Key.fromString(data=cmd_args.private_key)}
        self.services = {
            b'ssh-userauth': userauth.SSHUserAuthServer,
            b'ssh-connection': connection.SSHConnection,
        }
        self.portal = cred.portal.Portal(ProxySSHRealm(), checkers=[ProxyPasswordChecker()])
        ProxySSHSession.cmd_args = cmd_args
        components.registerAdapter(ProxySSHSession, ProxySSHUser, session.ISession)


class ProxyPasswordChecker:
    """
    Simple object checking credentials. For this SSH proxy we allow only passwords
    because we need to pass some information to session and the easiest way is to
    send it mangled in password.
    """

    credentialInterfaces = (cred.credentials.IUsernamePassword,)

    # pylint: disable=invalid-name
    def requestAvatarId(self, credentials):
        """
        Proxy allows any password. Honeypot decide what will accept later.
        """
        return defer.succeed(credentials)


class ProxySSHRealm:
    """
    Simple object to implement getting avatar used in :py:any:`portal.Portal`
    after checking credentials.
    """

    # pylint: disable=invalid-name,unused-argument
    def requestAvatar(self, avatarId, mind, *interfaces):
        """
        Normaly :py:any:`ProxyPasswordChecker` should return only username but
        we need also password so we unwrap it here.
        """
        avatar = ProxySSHUser(avatarId.username, avatarId.password)
        return interfaces[0], avatar, lambda: None


class ProxySSHUser(ConchUser):
    """
    Avatar returned by :py:any:`ProxySSHRealm`. It stores username and password
    for later usage in :py:any:`ProxySSHSession`.
    """

    def __init__(self, username, password):
        ConchUser.__init__(self)
        self.username = username
        self.password = password
        self.channelLookup.update({b'session': session.SSHSession})


class ProxySSHSession(SSHSessionForUnixConchUser):
    """
    Main function of SSH proxy - connects to honeypot and change password
    to JSON with more information needed to tag activity with user's account.
    """

    cmd_args = None  # Will inject ProxySSHFactory.

    # pylint: disable=invalid-name
    def openShell(self, proto):
        """
        Custom implementation of shell - proxy to real SSH to honeypot.
        """
        user = pwd.getpwuid(os.getuid())
        # pylint: disable=no-member
        self.pty = reactor.spawnProcess(
            proto,
            executable='/usr/bin/sshpass',
            args=self.honeypot_ssh_arguments,
            env=self.environ,
            path='/',
            uid=user.pw_uid,
            gid=user.pw_gid,
            usePTY=self.ptyTuple,
        )
        fcntl.ioctl(self.pty.fileno(), tty.TIOCSWINSZ, struct.pack('4H', *self.winSize))
        self.avatar.conn.transport.transport.setTcpNoDelay(1)

    @property
    def honeypot_ssh_arguments(self):
        """
        Command line arguments to call SSH to honeypot. Uses sshpass to be able
        pass password from command line.
        """
        return [
            'sshpass',
            '-p', self.mangled_password,
            'ssh',
            '-p', str(self.cmd_args.honeypot_port),
            '{}@{}'.format(force_text(self.avatar.username), self.cmd_args.honeypot_host),
        ]

    @property
    def mangled_password(self):
        """
        Password as JSON string containing more information needed to
        tag activity with user's account.
        """
        peer = self.avatar.conn.transport.transport.getPeer()
        password_data = {
            'password': force_text(self.avatar.password),
            'user_id': self.cmd_args.user_id,
            'remote': peer.host,
            'remote_port': peer.port,
        }
        return json.dumps(password_data)


if __name__ == '__main__':
    main()
