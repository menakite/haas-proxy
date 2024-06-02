"""
Wrapping factory to limit the total amount of connections to the proxy.
Heavily based on code contained in the Twisted Python framework.
Twisted is licensed under the terms of the MIT License:
Copyright (c) 2001-2024 Twisted Matrix Laboratories.
"""

from twisted.protocols.policies import WrappingFactory


class LimitConnectionsFactory(WrappingFactory):  # pylint: disable=missing-class-docstring
    connection_limit_global = 0  # Unlimited
    connection_limit_peer = 0  # Unlimited
    # Make Twisted less verbose
    noisy = False
    peers_connections = {}
    total_connections = 0

    def buildProtocol(self, addr):  # pylint: disable=invalid-name
        if self.connection_limit_global == 0 or self.total_connections < self.connection_limit_global:
            host = addr.host
            peer_connections = self.peers_connections.get(host, 0)

            if self.connection_limit_peer == 0 or peer_connections < self.connection_limit_peer:
                self.total_connections += 1
                self.peers_connections[host] = peer_connections + 1
                return WrappingFactory.buildProtocol(self, addr)

        return None

    def unregisterProtocol(self, p):  # pylint: disable=invalid-name
        WrappingFactory.unregisterProtocol(self, p)
        host = p.getPeer().host
        self.total_connections -= 1
        self.peers_connections[host] -= 1
        if self.peers_connections[host] == 0:
            del self.peers_connections[host]
