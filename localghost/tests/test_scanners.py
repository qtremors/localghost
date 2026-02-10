import ssl
from datetime import datetime, timedelta, timezone

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.scanners.cookie_scan import scan_cookies
from backend.scanners.cors_scan import scan_cors
from backend.scanners.port_scan import scan_ports
from backend.scanners.ssl_scan import scan_ssl
from backend.scanners.vuln_scan import check_vulnerabilities


async def test_spa_fallback_does_not_report_every_sensitive_file(local_server):
    async def handler(request):
        return web.Response(text='<html>Application shell</html>', content_type='text/html')
    async with local_server(handler) as url:
        result = await check_vulnerabilities(url + '/nested?query=1')
    assert not any(result.sensitive_files.values())
    assert not any('Exposed' in finding.title for finding in result.findings)


async def test_real_sensitive_file_uses_origin_root(local_server):
    paths = []
    async def handler(request):
        paths.append(request.path)
        if request.path == '/.env':
            return web.Response(text='DATABASE_PASSWORD=example')
        return web.Response(status=404)
    async with local_server(handler) as url:
        result = await check_vulnerabilities(url + '/nested?query=1')
    assert result.sensitive_files['/.env'] is True
    assert '/.env' in paths
    assert not any(path.startswith('/nested/') for path in paths)


async def test_redirects_do_not_scan_another_target(local_server):
    calls = []
    async def destination(request):
        calls.append(request.path)
        return web.Response(text='destination')
    async with local_server(destination) as other:
        async def redirect(request):
            raise web.HTTPFound(other)
        async with local_server(redirect) as url:
            await check_vulnerabilities(url)
            await scan_cookies(url)
            await scan_cors(url)
    assert calls == []


async def test_port_scan_includes_custom_target_port(local_server):
    async def handler(request):
        return web.Response(text='ok')
    async with local_server(handler) as url:
        result = await scan_ports(url)
    assert int(url.rsplit(':', 1)[1]) in [port['port'] for port in result.open_ports]


async def test_self_signed_certificate_is_inspected_but_not_trusted(tmp_path, local_server):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=60))
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    async def handler(request):
        return web.Response(text='ok')
    async with local_server(handler, context) as url:
        result = await scan_ssl(url)
    assert result.has_ssl
    assert result.certificate['subject'] == 'localhost'
    assert result.protocol_version in ('TLSv1.2', 'TLSv1.3')
    assert not result.cert_valid
    assert 58 <= result.days_until_expiry <= 60
    assert any(finding.title == 'SSL Certificate Not Trusted' for finding in result.findings)


async def test_load_latency_includes_response_body(local_server):
    import asyncio

    import aiohttp

    from backend.scanners.load_test import send_request

    async def handler(request):
        response = web.StreamResponse()
        await response.prepare(request)
        await asyncio.sleep(.04)
        await response.write(b'complete body')
        await response.write_eof()
        return response
    async with local_server(handler) as url:
        async with aiohttp.ClientSession() as session:
            success, latency = await send_request(session, url)
    assert success
    assert latency >= 35


async def test_slow_connection_cancellation_closes_sockets():
    import asyncio
    from contextlib import suppress

    from backend.scanners.ddos_test import _test_slowloris

    connected, closed = asyncio.Event(), asyncio.Event()
    async def handler(reader, writer):
        connected.set()
        try:
            await reader.read()
            closed.set()
        finally:
            writer.close()
            await writer.wait_closed()
    server = await asyncio.start_server(handler, '127.0.0.1', 0)
    try:
        port = server.sockets[0].getsockname()[1]
        task = asyncio.create_task(_test_slowloris(f'http://127.0.0.1:{port}', num_connections=1, hold_seconds=30))
        await asyncio.wait_for(connected.wait(), timeout=2)
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        await asyncio.wait_for(closed.wait(), timeout=2)
    finally:
        server.close()
        await server.wait_closed()


async def test_plain_text_reflection_is_not_reported_as_html_xss(local_server, monkeypatch):
    from backend.scanners import xss_scan
    monkeypatch.setattr(xss_scan, 'XSS_PAYLOADS', ['<svg/onload=alert(1)>'])
    monkeypatch.setattr(xss_scan, 'COMMON_PARAMS', ['q'])
    monkeypatch.setattr(xss_scan, 'INJECTABLE_PATHS', ['/'])
    async def handler(request):
        return web.Response(text=request.query.get('q', request.path), content_type='text/plain')
    async with local_server(handler) as url:
        result = await xss_scan.scan_xss(url)
    assert not result['vulnerable']
    assert result['reflections_found'] == 0
    assert not any('X-XSS-Protection' in finding['title'] for finding in result['findings'])


async def test_xss_probes_do_not_follow_redirects(local_server, monkeypatch):
    from backend.scanners import xss_scan
    monkeypatch.setattr(xss_scan, 'XSS_PAYLOADS', ['<svg/onload=alert(1)>'])
    monkeypatch.setattr(xss_scan, 'COMMON_PARAMS', ['q'])
    monkeypatch.setattr(xss_scan, 'INJECTABLE_PATHS', ['/'])
    calls = []
    async def destination(request):
        calls.append(request.path)
        return web.Response(text='destination')
    async with local_server(destination) as other:
        async def redirect(request):
            raise web.HTTPFound(other)
        async with local_server(redirect) as url:
            await xss_scan.scan_xss(url)
    assert calls == []


async def test_endpoint_rate_limit_detection_updates_overall_result(monkeypatch):
    from backend.scanners import rate_limit_test
    async def headers(*args, **kwargs):
        return {'headers': {}, 'completed': True}
    async def burst(*args, **kwargs):
        return {'rate_limited_count': 0, 'total_requests': 50, 'accepted': 50, 'errors': 0, 'unavailable': 0, 'first_429_at': 0}
    async def sustained(*args, **kwargs):
        return {'rate_limited_count': 0, 'total_requests': 80, 'rps_target': 10, 'duration_sec': 8, 'accepted': 80, 'errors': 0, 'unavailable': 0}
    async def endpoints(*args, **kwargs):
        return [{'path': '/login', 'rate_limited': True, 'requests_sent': 20, 'accepted': 19, 'rejected': 1, 'errors': 0, 'unavailable': 0}]
    monkeypatch.setattr(rate_limit_test, '_check_rate_limit_headers', headers)
    monkeypatch.setattr(rate_limit_test, '_burst_test', burst)
    monkeypatch.setattr(rate_limit_test, '_sustained_test', sustained)
    monkeypatch.setattr(rate_limit_test, '_test_endpoint_limits', endpoints)
    result = await rate_limit_test.test_rate_limits('http://localhost')
    assert result['has_rate_limiting']
    assert not any(finding['title'] == 'No Rate Limiting Detected' for finding in result['findings'])
