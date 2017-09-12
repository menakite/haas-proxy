"""
Twisted plugin to be able tu run it directly with ``twistd`` command.
"""
# pylint: disable=missing-docstring,invalid-name

from twisted.python import usage
from twisted.plugin import IPlugin
from twisted.application.service import IServiceMaker
from zope.interface import implementer

from haas_proxy import ProxyService, constants, __doc__ as haas_proxy_doc


class Options(usage.Options):
    optParameters = [
        ['device-token', 'd', None, 'Your ID at honeypot.labs.nic.cz. If you don\'t have one, sign up first.'],
        ['port', 'p', constants.DEFAULT_PORT, 'Port to listen to.', int],
        ['honeypot-host', None, constants.DEFAULT_HONEYPOT_HOST],
        ['honeypot-port', None, constants.DEFAULT_HONEYPOT_PORT],
        ['public-key'],
        ['private-key'],
    ]

    @property
    def device_token(self):
        return self['device-token']

    @property
    def port(self):
        return self['port']

    @property
    def honeypot_host(self):
        return self['honeypot-host']

    @property
    def honeypot_port(self):
        return self['honeypot-port']

    @property
    def public_key(self):
        return self['public-key']

    @property
    def private_key(self):
        return self['private-key']

    def postOptions(self):
        if not self['device-token']:
            raise usage.UsageError('Device token is required')
        if not self['public-key']:
            self['public-key'] = constants.DEFAULT_PUBLIC_KEY
        if not self['private-key']:
            self['private-key'] = constants.DEFAULT_PRIVATE_KEY

    def getSynopsis(self):
        return super(Options, self).getSynopsis() + '\n' + haas_proxy_doc


@implementer(IServiceMaker, IPlugin)
class MyServiceMaker(object):
    tapname = 'haas_proxy'
    description = 'Start HaaS proxy'
    options = Options

    def makeService(self, options):
        return ProxyService(options)


service_maker = MyServiceMaker()
