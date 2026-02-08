import socket

import pytest
from pydantic import ValidationError

from backend.models.scan import ScanModules, ScanRequest
from backend.utils.validators import validate_target_address, validate_target_url


@pytest.mark.parametrize(('value', 'expected'), [
    (' localhost:3000 ', 'http://localhost:3000'),
    ('127.0.0.1:8080/path?q=1#part', 'http://127.0.0.1:8080/path?q=1'),
    ('https://[::1]:443', 'https://[::1]:443'),
    ('HTTP://localhost', 'http://localhost'),
])
def test_normalizes_valid_urls(value, expected):
    assert validate_target_url(value) == expected


@pytest.mark.parametrize('value', [
    '', 'ftp://localhost', 'file:///etc/passwd', 'http://', 'http://localhost:0',
    'http://localhost:65536', 'http://localhost:abc', 'http://[::1',
    'http://user:secret@localhost', 'http://local host', 'http://localhost\n/evil',
    'http://8.8.8.8', 'http://[2001:4860:4860::8888]', 'http://0.0.0.0',
    'http://localhost\\@example.com',
])
def test_rejects_invalid_or_nonlocal_urls(value):
    with pytest.raises(ValueError):
        validate_target_url(value)


@pytest.mark.parametrize('ports', [[], [0], [65536], [-1], [1.5], [True], list(range(1, 1026))])
def test_port_constraints(ports):
    with pytest.raises(ValidationError):
        ScanRequest(target_url='localhost', ports_to_scan=ports)


def test_deduplicates_ports_and_rejects_empty_modules():
    assert ScanRequest(target_url='localhost', ports_to_scan=[443, 80, 443]).ports_to_scan == [80, 443]
    with pytest.raises(ValidationError, match='at least one'):
        ScanRequest(target_url='localhost', modules=ScanModules(**{key: False for key in ScanModules.model_fields}))


@pytest.mark.parametrize('addresses', [['127.0.0.1', '::1'], ['192.168.1.20'], ['8.8.8.8'], ['127.0.0.1', '8.8.8.8']])
async def test_dns_must_resolve_only_to_private_addresses(monkeypatch, addresses):
    import asyncio
    async def resolve(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 80)) for address in addresses]
    monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
    if '8.8.8.8' in addresses:
        with pytest.raises(ValueError, match='private'):
            await validate_target_address('http://dev.example')
    else:
        await validate_target_address('http://dev.example')
