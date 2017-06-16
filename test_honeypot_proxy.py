# -*- encoding: utf-8 -*-

import json
try:
    from unittest import mock
except ImportError:
    import mock

import pytest

from honeypot_proxy import force_text, ProxySSHSession


@pytest.fixture
def cmd_args():
    return mock.Mock(
        user_id=42,
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
    avatar.conn.transport.transport.getPeer.return_value = mock.Mock(host='hacker', port=12345)
    return avatar


@pytest.fixture
def proxy_ssh_session(cmd_args, avatar):
    session = ProxySSHSession(avatar)
    session.cmd_args = cmd_args
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
    assert proxy_ssh_session.honeypot_ssh_arguments[3:] == ['ssh', '-p', '2222', 'user@localhost']


def test_mangle_password(proxy_ssh_session):
    assert json.loads(proxy_ssh_session.mangled_password) == {
        'password': 'pass',
        'user_id': 42,
        'remote': 'hacker',
        'remote_port': 12345,
    }
