"""
Twisted plugin to be able tu run it directly with ``twistd`` command.
"""
# pylint: disable=missing-docstring,invalid-name

import requests
from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from twisted.python import usage
from zope.interface import implementer

from haas_proxy import ProxyService, constants, __doc__ as haas_proxy_doc
from haas_proxy.log import init_python_logging


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
        ['device-token', 'd', None, 'Your ID at honeypot.labs.nic.cz. If you don\'t have one, sign up first.'],
        ['port', 'p', constants.DEFAULT_PORT, 'Port to listen to.', int],
        ['balancer-address', None, constants.DEFAULT_BALANCER_ADDRESS],
        ['validate-token-address', None, constants.DEFAULT_VALIDATE_TOKEN_ADDRESS],
        ['public-key'],
        ['private-key'],
        ['log-file', 'l', None, 'Turn on Python logging to this file. It\' wise to disable Twisted logging.'],
        ['log-level', None, 'warning', 'Possible options: error / warning / info / debug.'],
    ]

    @property
    def device_token(self):
        return self['device-token']

    @property
    def port(self):
        return self['port']

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
        self.validate_token()
        self['public-key'] = read_key(self['public-key'], constants.DEFAULT_PUBLIC_KEY)
        self['private-key'] = read_key(self['private-key'], constants.DEFAULT_PRIVATE_KEY)
        if self['log-file']:
            init_python_logging(self['log-file'], self['log-level'])

    def getSynopsis(self):
        return super(Options, self).getSynopsis() + '\n' + haas_proxy_doc

    def validate_token(self):
        if not self['device-token']:
            raise usage.UsageError('Device token is required')

        token_is_valid = requests.post(
            self['validate-token-address'],
            data={'device-token': self['device-token']}
        ).json()['valid']

        if not token_is_valid:
            raise usage.UsageError('Device token is not valid')


# pylint: disable=useless-object-inheritance
@implementer(IServiceMaker, IPlugin)
class MyServiceMaker(object):
    tapname = 'haas_proxy'
    description = 'Start HaaS proxy'
    options = Options

    def makeService(self, options):
        return ProxyService(options)


service_maker = MyServiceMaker()
