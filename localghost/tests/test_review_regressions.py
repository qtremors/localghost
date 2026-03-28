"""Regressions reproduced during the live vulnerable-server review."""

import asyncio
import json

import pytest
from aiohttp import web
from httpx import ASGITransport, AsyncClient

from backend.database import db
from backend.main import app
from backend.scanners.cookie_scan import parse_set_cookie, scan_cookies
from backend.scanners.cors_scan import scan_cors
from backend.scanners.port_scan import scan_ports
from backend.scanners.tech_detect import detect_technologies
from backend.scanners.vuln_scan import check_vulnerabilities
from backend.services.header_checks import check_header_value
from backend.services.scoring import compute_score
from backend.utils.html import has_active_html_reflection


@pytest.mark.parametrize('status', [302, 403, 429, 503])
async def test_error_or_redirect_cannot_pass_app_audits(local_server, status):
    async def handler(request):
        return web.Response(status=status, headers={'Location': '/login'} if status == 302 else {})
    async with local_server(handler) as url:
        cookies, cors, tech, files = await asyncio.gather(scan_cookies(url), scan_cors(url), detect_technologies(url), check_vulnerabilities(url))
    assert all(result.status == 'error' for result in (cookies, cors, tech))
    assert not any(finding.severity == 'pass' for result in (cookies, cors, tech) for finding in result.findings)
    assert compute_score(cookies=cookies, cors=cors).coverage == 0
    assert files.security_headers == {}
    if status != 403:
        assert all(value is None for value in files.sensitive_files.values())


async def test_dynamic_fallback_does_not_expose_files(local_server):
    import uuid
    async def handler(request):
        return web.Response(text=f'<html><h1>Not found: {request.path}</h1><p>{uuid.uuid4().hex}</p></html>', content_type='text/html')
    async with local_server(handler) as url:
        result = await check_vulnerabilities(url)
    assert all(value is False for value in result.sensitive_files.values())
    assert not any('Exposed' in finding.title for finding in result.findings)


async def test_secret_leaking_catch_all_is_still_reported(local_server):
    async def handler(request):
        return web.Response(text='DATABASE_PASSWORD=lab-only\nDEBUG=true')
    async with local_server(handler) as url:
        result = await check_vulnerabilities(url)
    assert result.sensitive_files['/.env'] is True


@pytest.mark.parametrize(('name', 'value', 'accepted'), [
    ('Strict-Transport-Security', 'max-age=0', False),
    ('Strict-Transport-Security', 'max-age=31536000', True),
    ('X-Frame-Options', 'ALLOWALL', False),
    ('X-Frame-Options', 'SAMEORIGIN', True),
    ('X-Content-Type-Options', 'incorrect', False),
    ('Referrer-Policy', 'garbage', False),
    ('Referrer-Policy', 'unsafe-url', False),
    ('Permissions-Policy', 'garbage', False),
    ('Permissions-Policy', 'camera=(), microphone=()', True),
    ('Content-Security-Policy', "default-src * 'unsafe-inline'", False),
    ('Content-Security-Policy', "default-src 'self'; style-src 'unsafe-inline'", True),
    ('Content-Security-Policy', "script-src 'nonce-dGVzdA==' 'unsafe-inline'", True),
    ('Cross-Origin-Opener-Policy', 'unsafe-none', False),
])
def test_header_values_affect_protection(name, value, accepted):
    assert check_header_value(name, value)[0] is accepted


async def test_csp_frame_policy_replaces_xfo_and_http_does_not_require_hsts(local_server):
    async def handler(request):
        return web.Response(text='<html>app</html>', content_type='text/html', headers={
            'Content-Security-Policy': "default-src 'self'; frame-ancestors 'none'",
            'X-Content-Type-Options': 'incorrect',
        })
    async with local_server(handler) as url:
        result = await check_vulnerabilities(url)
    assert not result.security_headers['Strict-Transport-Security'].applicable
    assert not result.security_headers['X-Frame-Options'].applicable
    assert result.security_headers['X-Content-Type-Options'].valid is False
    assert not any(finding.title in ('Missing Strict-Transport-Security', 'Missing X-Frame-Options') for finding in result.findings)
    assert compute_score(vuln=result).breakdown.headers == 6  # One accepted header out of five applicable checks.


async def test_safe_preflight_does_not_hide_credentialed_get_reflection(local_server):
    async def handler(request):
        origin = 'https://trusted.example' if request.method == 'OPTIONS' else request.headers['Origin']
        return web.Response(headers={'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true'})
    async with local_server(handler) as url:
        result = await scan_cors(url)
    assert result.allow_origin == 'https://evil-attacker.com'
    assert any(finding.severity == 'high' for finding in result.findings)
    assert compute_score(cors=result).score == 0
    assert len(result.observations) == 4


async def test_wildcard_credentials_are_not_reported_as_credential_theft(local_server):
    async def handler(request):
        return web.Response(headers={'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true'})
    async with local_server(handler) as url:
        result = await scan_cors(url)
    assert result.findings[0].severity == 'medium'
    assert 'Browsers block' in result.findings[0].description


async def test_invalid_cookie_attributes_do_not_pass_and_values_are_redacted(local_server):
    async def handler(request):
        return web.Response(headers={'Set-Cookie': '__Host-session=lab-secret; Secure; HttpOnly; SameSite=invalid; Domain=localhost'})
    async with local_server(handler) as url:
        result = await scan_cookies(url)
    assert not any(finding.severity == 'pass' for finding in result.findings)
    assert result.cookies[0]['value'] == '[redacted]'
    assert compute_score(cookies=result).score == 0
    assert parse_set_cookie('token=short-secret')['value'] == '[redacted]'


async def test_existing_cookie_values_are_removed_from_storage():
    import aiosqlite
    report = {'cookie_scan': {'cookies': [{'name': 'session', 'value': 'old-cookie-prefix'}]}}
    async with aiosqlite.connect(db.DB_PATH) as connection:
        await connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)', ('old', 'http://localhost', '2026-01-01', 50, 'D', json.dumps(report)))
        await connection.execute('PRAGMA user_version = 0')
        await connection.commit()
    await db.init_db()
    async with aiosqlite.connect(db.DB_PATH) as connection:
        async with connection.execute('SELECT results_json FROM scans') as cursor:
            encoded = (await cursor.fetchone())[0]
    assert 'old-cookie-prefix' not in encoded
    assert json.loads(encoded)['cookie_scan']['cookies'][0]['name'] == 'session'


async def test_custom_port_list_includes_the_app(local_server):
    async def handler(request):
        return web.Response(text='ok')
    async with local_server(handler) as url:
        result = await scan_ports(url, ports=[1])
    assert int(url.rsplit(':', 1)[1]) in [item['port'] for item in result.open_ports]
    assert result.total_scanned == 2


@pytest.mark.parametrize(('body', 'payload', 'active'), [
    ('<p>\'-alert(1)-\'</p>', "'-alert(1)-'", False),
    ('<!-- <svg onload=alert(1)> -->', '<svg onload=alert(1)>', False),
    ('<textarea><svg onload=alert(1)></textarea>', '<svg onload=alert(1)>', False),
    ('<script>const example="<svg onload=alert(1)>"</script>', '<svg onload=alert(1)>', False),
    ('<html><svg onload=alert(1)></html>', '<svg onload=alert(1)>', True),
    ('<div>"><img src=x onerror=alert(1)></div>', '"><img src=x onerror=alert(1)>', True),
])
def test_html_reflection_requires_a_parsed_active_tag(body, payload, active):
    assert has_active_html_reflection(body, payload) is active


async def test_unknown_charset_does_not_crash_fingerprinting(local_server):
    async def handler(request):
        return web.Response(body=b'<html>app</html>', headers={'Content-Type': 'text/html; charset=not-a-real-encoding', 'X-Powered-By': 'Express'})
    async with local_server(handler) as url:
        result = await detect_technologies(url)
    assert result.status == 'success'
    assert any(tech['name'] == 'Express.js' for tech in result.technologies)


async def test_api_rejects_foreign_origin_and_rebinding_hosts(monkeypatch):
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://localhost:13666') as client:
        for path in ('/api/scan', '/api/scan/stream', '/api/projects/discover'):
            assert (await client.post(path, json={}, headers={'Origin': 'https://other.example'})).status_code == 403
        assert (await client.delete('/api/history', headers={'Origin': 'null'})).status_code == 403
        assert (await client.post('/api/scan', json={}, headers={'Sec-Fetch-Site': 'cross-site'})).status_code == 403
        assert (await client.get('/api/history', headers={'Host': 'rebind.example'})).status_code == 400
        assert (await client.post('/api/scan', content='x' * 65537)).status_code == 413
        async def body():
            yield b'x' * 40000
            yield b'x' * 40000
        assert (await client.post('/api/scan', content=body())).status_code == 413
        page = await client.get('/')
        assert "script-src 'self'" in page.headers['content-security-policy']
        assert page.headers['x-frame-options'] == 'DENY'
        assert (await client.get('/api/history')).headers['cache-control'] == 'no-store'
        monkeypatch.setenv('LOCALGHOST_ALLOWED_HOSTS', 'dev.example')
        assert (await client.get('/health', headers={'Host': 'dev.example'})).status_code == 200


async def test_load_test_stops_at_deadline_even_during_response_body(local_server):
    import time

    from backend.scanners.load_test import run_load_test

    async def handler(request):
        response = web.StreamResponse()
        await response.prepare(request)
        await asyncio.sleep(.3)
        return response
    async with local_server(handler) as url:
        started = time.monotonic()
        result = await run_load_test(url, concurrency=1, duration_seconds=.04)
        elapsed = time.monotonic() - started
    assert elapsed < .2
    assert result.requests_failed == 0
    assert result.requests_incomplete == 1
    assert result.error_rate is None
    assert result.avg_latency_ms is None


async def test_latency_storage_is_bounded_and_sampling_is_disclosed(local_server, monkeypatch):
    from backend.scanners import load_test
    monkeypatch.setattr(load_test, 'MAX_LATENCY_SAMPLES', 3)

    async def handler(request):
        return web.Response(text='ok')
    async with local_server(handler) as url:
        result = await load_test.run_load_test(url, concurrency=2, duration_seconds=.05)
    assert result.requests_attempted > 3
    assert result.latency_samples == 3
    assert result.latency_sampled
    assert result.min_latency_ms <= result.avg_latency_ms <= result.max_latency_ms


async def test_project_pages_group_paths_without_loading_each_report():
    for number in range(30):
        target = f'http://localhost:{3000 + number}'
        await db.save_scan(str(number), target, f'2026-01-01T00:{number:02d}:00Z', 60, 'C', {'score': {'coverage': 25}, 'status': 'partial'})
    await db.save_scan('same-app', 'http://localhost:3000/path', '2026-02-01T00:00:00Z', 80, 'A', {'score': {'coverage': 100}, 'status': 'success'})
    first = await db.get_project_history(limit=24)
    second = await db.get_project_history(limit=24, offset=24)
    assert first['total_projects'] == 30
    assert first['total_reports'] == 31
    assert len(first['projects']) == 24
    assert len(second['projects']) == 6
    assert first['projects'][0]['reports'] == 2
    assert first['projects'][0]['latest']['scan_id'] == 'same-app'
    assert first['projects'][1]['latest']['coverage'] == 25
    assert first['projects'][1]['latest']['status'] == 'partial'


async def test_generic_text_does_not_fingerprint_react(local_server):
    async def handler(request):
        return web.Response(text='<html>React to changes using a bootstrap plan.</html>', content_type='text/html', headers={'Server': 'Custom'})
    async with local_server(handler) as url:
        result = await detect_technologies(url)
    assert not result.technologies
    assert not any(finding.severity == 'pass' for finding in result.findings)


async def test_app_score_is_withheld_when_all_http_audits_see_errors(local_server):
    from backend.models.scan import ScanRequest
    from backend.services.scanner import execute_scan

    async def handler(request):
        return web.Response(status=503, text='Maintenance')
    async with local_server(handler) as url:
        result = await execute_scan(ScanRequest(target_url=url, ports_to_scan=[1]))
    assert result.port_scan.open_ports
    assert result.score is None
    assert 'HTTP 503' in result.warnings[0]


def test_request_typos_and_non_integer_load_settings_are_rejected():
    from pydantic import ValidationError

    from backend.models.scan import ScanRequest

    for payload in ({'moduels': {}}, {'modules': {'port_sacn': True}}, {'benchmark_config': {'concurrency': True}}, {'benchmark_config': {'duration_seconds': 1.5}}):
        with pytest.raises(ValidationError):
            ScanRequest(target_url='http://localhost', **payload)


async def test_json_api_does_not_require_html_document_headers(local_server):
    async def handler(request):
        if request.path != '/':
            return web.Response(status=404)
        return web.json_response({'status': 'ok'}, headers={'X-Content-Type-Options': 'nosniff'})
    async with local_server(handler) as url:
        result = await check_vulnerabilities(url)
    assert not result.security_headers['Content-Security-Policy'].applicable
    assert not result.security_headers['X-Frame-Options'].applicable
    assert not result.security_headers['Permissions-Policy'].applicable
    assert not any(finding.title.startswith('Missing ') for finding in result.findings)
    assert compute_score(vuln=result).breakdown.headers == 30
