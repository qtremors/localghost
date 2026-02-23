"""Discovery must find real HTTP apps without following links or scanning other hosts."""

from urllib.parse import urlsplit

from aiohttp import web
from httpx import ASGITransport, AsyncClient

from backend.main import app
from backend.routers import projects


async def test_discovery_finds_local_app_title_and_does_not_follow_redirects(monkeypatch, local_server):
    async def target(request):
        return web.Response(text='<title>My &amp; local app</title>', headers={'X-Powered-By': 'Fixture'})

    async def redirect(request):
        return web.Response(status=302, headers={'Location': 'http://never-follow.example'})

    async with local_server(target) as first, local_server(redirect) as second:
        ports = (urlsplit(first).port, urlsplit(second).port)
        monkeypatch.setattr(projects, 'COMMON_PORTS', ports)
        result = await projects.discover_projects()
        assert result['checked_ports'] == 2
        assert len(result['projects']) == 2
        assert result['projects'][0]['name'] == 'My & local app'
        assert result['projects'][0]['server'] == 'Fixture'
        assert result['projects'][1]['http_status'] == 302
        assert all(item['target'].startswith('http://127.0.0.1:') for item in result['projects'])
        excluded = await projects.discover_projects(ports[0])
        assert len(excluded['projects']) == 1
        assert excluded['projects'][0]['port'] == ports[1]


async def test_discovery_limits_concurrency_and_excludes_this_server(monkeypatch):
    observed = []

    async def discover(excluded_port):
        observed.append(excluded_port)
        return {'projects': [], 'checked_ports': 0}

    monkeypatch.setattr(projects, 'discover_projects', discover)
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://localhost:13666') as client:
        result = await client.post('/api/projects/discover')
        assert result.status_code == 200
        assert observed == [13666]
        await projects._discovery_lock.acquire()
        try:
            assert (await client.post('/api/projects/discover')).status_code == 429
        finally:
            projects._discovery_lock.release()


async def test_slow_response_body_does_not_hide_a_running_server(monkeypatch, local_server):
    import asyncio

    async def target(request):
        response = web.StreamResponse()
        await response.prepare(request)
        await asyncio.sleep(.4)
        return response
    async with local_server(target) as url:
        monkeypatch.setattr(projects, 'COMMON_PORTS', (urlsplit(url).port,))
        result = await projects.discover_projects()
    assert len(result['projects']) == 1
    assert result['projects'][0]['http_status'] == 200


async def test_discovery_retains_distinct_ipv4_and_ipv6_apps(monkeypatch, local_server):
    import pytest

    async def ipv4(request):
        return web.Response(text='<title>IPv4 app</title>')
    async def ipv6(request):
        return web.Response(text='<title>IPv6 app</title>')
    async with local_server(ipv4) as url:
        port = urlsplit(url).port
        app = web.Application()
        app.router.add_get('/', ipv6)
        runner = web.AppRunner(app)
        await runner.setup()
        try:
            try:
                await web.TCPSite(runner, '::1', port).start()
            except OSError:
                pytest.skip('IPv6 loopback is unavailable')
            monkeypatch.setattr(projects, 'COMMON_PORTS', (port,))
            result = await projects.discover_projects()
            assert len(result['projects']) == 2
            assert {item['name'] for item in result['projects']} == {'IPv4 app', 'IPv6 app'}
        finally:
            await runner.cleanup()
