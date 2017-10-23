"""
Implementation of SSH proxy using Twisted.
"""

import fcntl
import json
import struct
import tty

from twisted import cred
from twisted.application import service
from twisted.conch.avatar import ConchUser
from twisted.conch.ssh import factory, keys, userauth, connection, session
from twisted.conch.unix import SSHSessionForUnixConchUser
from twisted.internet import reactor, defer
from twisted.python import components

from haas_proxy.utils import force_text


class ProxyService(service.Service):
    """
    Service to be able to run it daemon with ``twistd`` command.
    """

    def __init__(self, args):
        self.args = args
        self._port = None

    def startService(self):
        # pylint: disable=no-member
        self._port = reactor.listenTCP(self.args.port, ProxySSHFactory(self.args))

    def stopService(self):
        return self._port.stopListening()


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
        # pylint: disable=no-member
        self.pty = reactor.spawnProcess(
            proto,
            executable='/usr/bin/sshpass',
            args=self.honeypot_ssh_arguments,
            env=self.environ,
            path='/',
            uid=None,
            gid=None,
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
            '-o', 'UserKnownHostsFile=/dev/null',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'LogLevel=error',  # Ignore warning of permanently added host to list of known hosts.
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
            'pass': force_text(self.avatar.password),
            'device_token': self.cmd_args.device_token,
            'remote': peer.host,
            'remote_port': peer.port,
        }
        return json.dumps(password_data)
