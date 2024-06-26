# -*- encoding: utf-8 -*-

import json
try:
    from unittest import mock
except ImportError:
    import mock

import pytest

from haas_proxy.proxy import ProxySSHSession
from haas_proxy.utils import force_text


@pytest.fixture
def cmd_args():
    return mock.Mock(
        device_token=42,
        honeypot_host='localhost',
        honeypot_port=2222,
    )


@pytest.fixture(params=(
    ('user', 'pass'),
    (b'user', b'pass'),
))
def avatar(request):
    avatar = mock.Mock(
        username=request.param[0],
        password=request.param[1],
    )
    avatar.conn.transport.transport.getPeer.return_value = mock.Mock(
        host='hacker', port=12345)
    return avatar


@pytest.fixture
def proxy_ssh_session(cmd_args, avatar):
    session = ProxySSHSession(avatar)
    session.cmd_args = cmd_args
    session.balancer = mock.Mock(host="localhost", port=2222)
    return session


@pytest.mark.parametrize('value, expected', (
    ('abc', 'abc'),
    (b'abc', 'abc'),
    ('háčkyčárky', 'háčkyčárky'),
    (b'h\xc3\xa1\xc4\x8dky\xc4\x8d\xc3\xa1rky', 'háčkyčárky'),
))
def test_force_text(value, expected):
    assert force_text(value) == expected


def test_honeypot_ssh_arguments(proxy_ssh_session):
    assert proxy_ssh_session.honeypot_ssh_arguments[3:] == [
        'ssh',
        '-o', 'UserKnownHostsFile=/dev/null',
        '-o', 'StrictHostKeyChecking=no',
        '-o', 'LogLevel=error',
        '-p', '2222',
        'user@localhost',
    ]


def test_mangle_password(proxy_ssh_session):
    assert json.loads(proxy_ssh_session.mangled_password) == {
        'pass': 'pass',
        'device_token': 42,
        'remote': 'hacker',
        'remote_port': 12345,
    }
