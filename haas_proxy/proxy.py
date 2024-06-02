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
from twisted.conch.openssh_compat import primes
from twisted.conch.ssh import common, factory, keys, session, userauth
from twisted.conch.ssh.connection import MSG_CHANNEL_OPEN_FAILURE, OPEN_CONNECT_FAILED
from twisted.conch.ssh.connection import SSHConnection as SSHConnectionTwisted
from twisted.conch.ssh.transport import SSHServerTransport as SSHServerTransportTwisted
from twisted.conch.unix import SSHSessionForUnixConchUser
import twisted.cred.checkers
from twisted.internet import defer, reactor
from twisted.python import components
from twisted.python.compat import networkString
from zope.interface import implementer

from haas_proxy import constants, log
from haas_proxy.balancer import Balancer
from haas_proxy.utils import force_text, which


class ProxyService(service.Service):
    """
    Service to be able to run it daemon with ``twistd`` command.
    """

    def __init__(self, args):
        self.args = args
        self._port = None

    def startService(self):  # pylint: disable=invalid-name
        # pylint: disable=no-member
        self._port = reactor.listenTCP(
            self.args.port, ProxySSHFactory(self.args))

        # Acknowledge our configuration
        log.get_logger().info('HaaS Proxy service successfully started.')
        log.get_logger().info('Device token: %s', self.args.device_token)
        log.get_logger().info('Listening on port %d.', self.args.port)

    def stopService(self):  # pylint: disable=invalid-name
        return self._port.stopListening()


class SSHConnection(SSHConnectionTwisted):
    """
    Overridden SSHConnection for disabling logs a traceback about a failed direct-tcpip connections
    """

    # pylint: disable=invalid-name,inconsistent-return-statements
    def ssh_CHANNEL_OPEN(self, packet):
        # pylint: disable=unbalanced-tuple-unpacking
        channel_type, rest = common.getNS(packet)

        if channel_type != b'direct-tcpip':
            return SSHConnectionTwisted.ssh_CHANNEL_OPEN(self, packet)

        try:
            senderChannel, _ = struct.unpack('>3L', rest[:12])
        except ValueError:
            # Some bad packet, ignore it completely without responding.
            pass
        else:
            self.transport.sendPacket(
                MSG_CHANNEL_OPEN_FAILURE,
                struct.pack('>2L', senderChannel, OPEN_CONNECT_FAILED) +
                common.NS(networkString('unknown failure')) + common.NS(b'')
            )

    # pylint: disable=invalid-name,inconsistent-return-statements
    def ssh_CHANNEL_DATA(self, packet):
        try:
            return SSHConnectionTwisted.ssh_CHANNEL_DATA(self, packet)
        except KeyError:
            # Some packets send data to the channel even it's not successfully opened.
            # Very probably direct-tcpip types which has bad packet resulting in not
            # responding in `ssh_CHANNEL_OPEN`. Ignore it as it's unimportant.
            pass

class SSHServerTransport(SSHServerTransportTwisted):
    """
    Overriden SSHServerTransport to avoid logging a RuntimeError during key exchange
    we actually don't care about.
    We also set the version string ("SSH banner") to be the same as the HaaS server.
    """

    # Use same version string as haas-app's server
    ourVersionString = constants.DEFAULT_BANNER_STRING

    def sendKexInit(self):  # pylint: disable=invalid-name
        try:
            SSHServerTransportTwisted.sendKexInit(self)
        except RuntimeError:
            pass

    def receiveError(self, reasonCode, description):  # pylint: disable=invalid-name
        # Parent just logs an error
        pass


# pylint: disable=abstract-method
class ProxySSHFactory(factory.SSHFactory):
    """
    Factory putting together all pieces of SSH proxy to honeypot together.
    """

    # Make Twisted less verbose
    noisy = False
    protocol = SSHServerTransport

    def __init__(self, cmd_args):
        public_key = keys.Key.fromString(data=cmd_args.public_key)
        private_key = keys.Key.fromString(data=cmd_args.private_key)
        self.publicKeys = {public_key.sshType(): public_key}  # pylint: disable=invalid-name
        self.privateKeys = {private_key.sshType(): private_key}  # pylint: disable=invalid-name

        # Try to read moduli file, doesn't actually matter if it doesn't succeed
        try:
            self.primes = primes.parseModuliFile('/etc/ssh/moduli')
        except IOError:
            pass

        self.services = {
            b'ssh-userauth': userauth.SSHUserAuthServer,
            b'ssh-connection': SSHConnection,
        }
        self.portal = cred.portal.Portal(
            ProxySSHRealm(), checkers=[ProxyPasswordChecker()])
        ProxySSHSession.cmd_args = cmd_args
        ProxySSHSession.balancer = Balancer(cmd_args.balancer_address)
        components.registerAdapter(
            ProxySSHSession, ProxySSHUser, session.ISession)

        reactor.addSystemEventTrigger('before', 'shutdown', self.shutdown_callback)

    def shutdown_callback(self):
        log.get_logger().info('Received SIGTERM -- exiting.')


@implementer(twisted.cred.checkers.ICredentialsChecker)
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


@implementer(cred.portal.IRealm)
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

    # pylint: disable=invalid-name
    def getUserGroupId(self):
        """
        Returns tuple with user and group ID.
        Method needed by `SSHSessionForUnixConchUser.openShell`.
        """
        return 0, 0

    # pylint: disable=invalid-name
    def getHomeDir(self):
        """
        Method needed by `SSHSessionForUnixConchUser.openShell`.
        """
        return "/root"

    # pylint: disable=invalid-name
    def getShell(self):
        """
        Method needed by `SSHSessionForUnixConchUser.openShell`.
        """
        return "/bin/bash"


class ProxySSHSession(SSHSessionForUnixConchUser):
    """
    Main function of SSH proxy - connects to honeypot and change password
    to JSON with more information needed to tag activity with user's account.
    """
    balancer = None  # Injected from ProxySSHFactory.
    cmd_args = None  # Injected from ProxySSHFactory.
    pty = None

    # pylint: disable=invalid-name
    def openShell(self, proto):
        """
        Custom implementation of shell - proxy to real SSH to honeypot.
        This method handles interactive SSH sessions from the user. It requires
        ProxySSHUser to have `getUserGroupId`, `getHomeDir` and `getShell` implemented.
        """
        self.pty = reactor.spawnProcess(
            proto,
            executable=which('sshpass'),
            args=self.honeypot_ssh_arguments,
            env=self.environ,
            path='/',
            uid=None,
            gid=None,
            usePTY=self.ptyTuple,
        )
        if self.ptyTuple:
            fcntl.ioctl(self.pty.fileno(), tty.TIOCSWINSZ,
                        struct.pack('4H', *self.winSize))
        self.avatar.conn.transport.transport.setTcpNoDelay(1)

    def execCommand(self, proto, cmd):
        """
        Custom implementation of exec - proxy to real SSH to honeypot.
        This function handles executing of commands from SSH:
            `ssh root@honeypot "cmd"`
        """
        self.pty = reactor.spawnProcess(
            proto,
            executable=which('sshpass'),
            args=self.honeypot_ssh_arguments + [cmd],
            env=self.environ,
            path='/',
            uid=None,
            gid=None,
            usePTY=self.ptyTuple,
        )

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
            # Ignore warning of permanently added host to list of known hosts.
            '-o', 'LogLevel=error',
            '-p', str(self.balancer.port),
            '{}@{}'.format(force_text(self.avatar.username),
                           self.balancer.host),
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
