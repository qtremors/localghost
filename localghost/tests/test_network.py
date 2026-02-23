import asyncio
import socket
import ssl

import pytest
from aiohttp import web

from backend.models.scan import ScanModules, ScanRequest
from backend.services.scanner import execute_scan
from backend.utils.network import open_target_connection, pin_target, scanner_session, target_addresses


async def test_scan_resolves_once_and_keeps_http_host_and_dns_evidence(local_server, monkeypatch):
    hosts = []
    async def handler(request):
        hosts.append(request.host)
        return web.Response(text='<html>Local fixture</html>', content_type='text/html')
    async with local_server(handler) as url:
        port = int(url.rsplit(':', 1)[1])
        lookups = []
        async def resolve(host, *args, **kwargs):
            lookups.append(host)
            if len(lookups) > 1:
                raise AssertionError('Target DNS was resolved again after validation')
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', ('127.0.0.1', port))]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        selected = {'port_scan', 'vuln_scan', 'cors_scan', 'cookie_scan', 'tech_detect', 'dns_scan', 'ssl_scan'}
        result = await execute_scan(ScanRequest(
            target_url=f'http://changing.test:{port}', ports_to_scan=[port],
            modules=ScanModules(**{key: key in selected for key in ScanModules.model_fields}),
        ))
    assert lookups == ['changing.test']
    assert result.resolved_addresses == ['127.0.0.1']
    assert result.dns_scan.records['A'] == ['127.0.0.1']
    assert result.port_scan.open_ports[0]['port'] == port
    assert hosts and set(hosts) == {f'changing.test:{port}'}
    assert target_addresses('unrelated.test') is None


async def test_http_scope_rejects_other_literal_hosts_and_redirects(local_server):
    async def redirect(request):
        raise web.HTTPFound('/destination')
    async with local_server(redirect) as url:
        with pin_target(url, ('127.0.0.1',)):
            async with scanner_session() as session:
                with pytest.raises(ValueError, match='outside'):
                    await session.get('http://127.0.0.2')
                with pytest.raises(ValueError, match='redirects are not followed'):
                    await session.get(url, allow_redirects=True)


async def test_tls_connection_retains_hostname_while_using_numeric_addresses(monkeypatch):
    calls = []
    async def connect(host, port, **kwargs):
        calls.append((host, port, kwargs))
        if host == '127.0.0.2':
            raise ConnectionRefusedError()
        return 'reader', 'writer'
    monkeypatch.setattr(asyncio, 'open_connection', connect)
    context = ssl.create_default_context()
    with pin_target('https://dev.test:8443', ('127.0.0.2', '127.0.0.1')):
        assert await open_target_connection('dev.test', 8443, ssl=context) == ('reader', 'writer')
        with pytest.raises(ValueError, match='outside'):
            await open_target_connection('other.test', 8443)
    assert [call[0] for call in calls] == ['127.0.0.2', '127.0.0.1']
    assert all(call[2]['server_hostname'] == 'dev.test' for call in calls)


async def test_snapshot_is_task_local_and_resets_after_cancellation():
    async def worker(name, address):
        with pin_target(f'http://{name}', (address,)):
            await asyncio.sleep(0)
            assert target_addresses(name) == (address,)
            with pytest.raises(ValueError):
                target_addresses('unrelated.test')
    await asyncio.gather(worker('one.test', '127.0.0.1'), worker('two.test', '127.0.0.2'))
    assert target_addresses('unrelated.test') is None
    with pytest.raises(asyncio.CancelledError):
        with pin_target('http://cancelled.test', ('127.0.0.1',)):
            raise asyncio.CancelledError()
    assert target_addresses('unrelated.test') is None


@pytest.mark.parametrize('addresses', [(), ('8.8.8.8',), ('127.0.0.1', '8.8.8.8')])
def test_snapshot_rejects_empty_or_public_addresses(addresses):
    with pytest.raises(ValueError, match='validated private'):
        with pin_target('http://dev.test', addresses):
            pass


async def test_equivalent_ipv6_notation_uses_the_same_snapshot():
    from backend.utils.network import PinnedResolver, TargetSnapshot
    expanded = '0:0:0:0:0:0:0:1'
    with pin_target(f'http://[{expanded}]:3000', ('::1',)):
        assert target_addresses('::1') == ('::1',)
    resolver = PinnedResolver(TargetSnapshot(expanded, ('::1',)))
    result = await resolver.resolve('::1', 3000)
    assert result[0]['host'] == '::1'
    assert result[0]['family'] == socket.AF_INET6
