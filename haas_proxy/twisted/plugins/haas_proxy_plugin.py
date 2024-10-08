"""
Twisted plugin to be able tu run it directly with ``twistd`` command.
"""
# pylint: disable=missing-docstring,invalid-name

from pathlib import Path
from socket import AF_INET

import requests
from twisted.application.service import IServiceMaker
from twisted.internet import abstract
from twisted.plugin import IPlugin
from twisted.python import usage
from zope.interface import implementer

from haas_proxy import ProxyService, constants, __doc__ as haas_proxy_doc
from haas_proxy.log import init_python_logging, get_logger


def read_key(filename, default):
    if not filename:
        return default
    try:
        return open(filename, 'rb').read()
    except Exception as exc:
        raise usage.UsageError(
            'Problem reading the key {}: {}'.format(filename, exc))


class Options(usage.Options):
    optParameters = [
        ['device-token', 'd', None, 'Your ID at haas.nic.cz. If you don\'t have one, sign up first and add a device.'],
        ['listen-address', 'a', '', 'Local IP address to listen on. Ignored if running in a Docker container.'],
        ['port', 'p', constants.DEFAULT_PORT, 'Port to listen to.', int],
        ['max-connections', None, '0:0',
            'Limit maximum connections per peer and/or globally. Format: peer:global, 0 means unlimited.'],
        ['balancer-address', None, constants.DEFAULT_BALANCER_ADDRESS],
        ['validate-token-address', None, constants.DEFAULT_VALIDATE_TOKEN_ADDRESS],
        ['public-key'],
        ['private-key'],
        ['log-file', 'l', 'syslog', 'Turn on Python logging to this file (default: syslog).'],
        # Secret syntax for developers: <our log level>:<Twisted log level> (f.e. info:debug)
        ['log-level', None, 'info', 'Possible options: error / warning / info / debug.'],
    ]

    @property
    def device_token(self):
        return self['device-token']

    @property
    def listen_address(self):
        return self['listen-address']

    @property
    def port(self):
        return self['port']

    @property
    def max_connections(self):
        return self['max-connections']

    @property
    def balancer_address(self):
        return self['balancer-address']

    @property
    def validate_token_address(self):
        return self['validate-token-address']

    @property
    def public_key(self):
        return self['public-key']

    @property
    def private_key(self):
        return self['private-key']

    @property
    def log_file(self):
        return self['log-file']

    @property
    def log_level(self):
        return self['log-level']

    def postOptions(self):
        self.validate_log_level()
        init_python_logging(self['log-file'], self['log-level'])
        self.validate_address()
        self.validate_connections_limits()
        self.validate_token()
        self['public-key'] = read_key(self['public-key'], constants.DEFAULT_PUBLIC_KEY)
        self['private-key'] = read_key(self['private-key'], constants.DEFAULT_PRIVATE_KEY)

    def getSynopsis(self):
        return super(Options, self).getSynopsis() + '\n' + haas_proxy_doc

    def validate_log_level(self):
        levels = self['log-level'].split(':')
        if len(levels) < 2 or len(levels[1].strip()) == 0:
            self['log-level'] = levels[0]

    def validate_address(self):
        # To ensure that health checks work reliably, this option is ignored if running in a Docker container.
        if Path('/.dockerenv').is_file():
            self['listen-address'] = ''

        # Check whether we got a valid IPv4 address
        if len(self['listen-address']) > 0 and not abstract.isIPAddress(self['listen-address'], AF_INET):
            get_logger().warning('%s is not a valid IPv4 address, defaulting to 0.0.0.0',
                self['listen-address'])
            # Empty string means "all address" (0.0.0.0) for Twisted
            self['listen-address'] = ''

    def validate_connections_limits(self):
        limits = self['max-connections'].split(':')
        error = False
        try:
            self['max-connections'] = {'peer': int(limits[0]), 'global': int(limits[1])}
        except ValueError:
            error = True

        if error or self['max-connections']['peer'] < 0 or self['max-connections']['global'] < 0:
            get_logger().warning('Invalid values for --max-connections. Defaulting to non-limited.')
            self['max-connections'] = {'peer': 0, 'global': 0}

    def validate_token(self):
        if not self['device-token']:
            raise usage.UsageError('Device token is required')

        token_is_valid = requests.post(
            self['validate-token-address'],
            data={'device-token': self['device-token']},
            timeout=1.0
        ).json()['valid']

        if not token_is_valid:
            raise usage.UsageError('Device token is not valid')

        get_logger().debug('Token %s validated successfully.', self['device-token'])


# pylint: disable=useless-object-inheritance
@implementer(IServiceMaker, IPlugin)
class MyServiceMaker(object):
    tapname = 'haas_proxy'
    description = 'Start HaaS proxy'
    options = Options

    def makeService(self, options):
        return ProxyService(options)


service_maker = MyServiceMaker()
