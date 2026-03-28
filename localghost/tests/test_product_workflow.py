"""Exercise real findings, session privacy, project context, and fix verification."""

import asyncio
import json
import sys

import pytest
from aiohttp import web
from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from backend.cli import exit_status, html_report
from backend.database.db import get_scan
from backend.main import app
from backend.models.scan import ScanModules, ScanRequest, ScanSession
from backend.services.scanner import execute_scan
from backend.services.source import inspect_source


def request_for(url, *modules, **options):
    return ScanRequest(target_url=url, modules=ScanModules(**{name: name in modules for name in ScanModules.model_fields}), **options)


def test_source_context_identifies_next_routes_without_executing_code(tmp_path):
    (tmp_path / 'package.json').write_text(json.dumps({'name': 'example', 'dependencies': {'next': '16'}, 'scripts': {'build': 'arbitrary command'}}))
    (tmp_path / 'next.config.mjs').write_text("throw new Error('must never execute');\nexport default {typescript: {ignoreBuildErrors: true}}")
    for file in ('app/page.tsx', 'app/(site)/about/page.tsx', 'app/items/[id]/page.tsx', 'node_modules/fake/page.tsx', 'public/.env'):
        path = tmp_path / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('private-example-value')
    (tmp_path / 'public' / 'linked').symlink_to(tmp_path / 'node_modules', target_is_directory=True)
    result = inspect_source(str(tmp_path))
    assert result['framework'] == 'Next.js'
    assert {route['path'] for route in result['routes']} == {'/', '/about'}
    assert result['dynamic_routes'][0]['route'] == '/items/[id]'
    assert len(result['findings']) == 2
    assert result['findings'][0]['fix_line'] == 2
    assert 'private-example-value' not in json.dumps(result)
    assert not any('node_modules' in item['file'] for item in result['routes'])


def test_source_handles_non_object_package_metadata(tmp_path):
    (tmp_path / 'package.json').write_text('{"dependencies": [], "scripts": 5}')
    result = inspect_source(str(tmp_path))
    assert result['status'] == 'partial'
    assert result['framework'] == 'Unknown'
    with pytest.raises(ValueError):
        inspect_source('relative-folder')


@pytest.mark.parametrize('path', ['https://example.com', '//example.com/path', '/%2fexample.com', '/a\\b', '/x%0d%0aHeader:x', '/#fragment'])
def test_routes_cannot_leave_the_selected_app(path):
    with pytest.raises(ValidationError):
        ScanRequest(target_url='localhost:3000', paths=[path])


async def test_real_file_fix_recheck_preserves_before_and_after(local_server):
    state = {'exposed': True, 'unavailable': False}

    async def handler(request):
        if state['unavailable']:
            return web.Response(status=503)
        if request.path == '/.env':
            return web.Response(text='DATABASE_PASSWORD=example-only' if state['exposed'] else '', status=200 if state['exposed'] else 404)
        if request.path == '/':
            return web.Response(text='<html>App</html>', content_type='text/html')
        return web.Response(status=404)

    async with local_server(handler) as url, AsyncClient(transport=ASGITransport(app=app), base_url='http://localhost') as client:
        report = (await client.post('/api/scan', json=request_for(url, 'vuln_scan').model_dump())).json()
        finding = next(item for item in report['findings'] if item['rule_id'] == 'file:/.env')
        assert finding['verification'] == 'confirmed'
        assert finding['evidence'][0]['status'] == 200
        assert 'example-only' not in json.dumps(report)
        route = f"/api/history/{report['scan_id']}/findings/{finding['id']}/recheck"
        same = (await client.post(route, json={})).json()
        assert same['state'] == 'still_present'
        state['exposed'] = False
        fixed = (await client.post(route, json={})).json()
        assert fixed['state'] == 'resolved'
        state['unavailable'] = True
        unavailable = (await client.post(route, json={})).json()
        assert unavailable['state'] == 'not_checked'
        original = (await client.get(f"/api/history/{report['scan_id']}")).json()['results']
        assert next(item for item in original['findings'] if item['id'] == finding['id']) == finding
        assert [item['state'] for item in original['rechecks']] == ['still_present', 'resolved', 'not_checked']
        assert (await get_scan(fixed['scan_id']))['results']['vuln_scan']['sensitive_files']['/.env'] is False


async def test_sessions_reach_target_but_never_reports_and_must_be_resupplied(local_server):
    secret = 'example-session-secret-value'
    observed = []

    async def handler(request):
        observed.append(request.headers.get('Cookie', ''))
        if request.path == '/':
            return web.Response(text='<html>Private app</html>', content_type='text/html', headers={'Server': secret, 'Set-Cookie': f'login={secret}'})
        return web.Response(status=404)

    async with local_server(handler) as url, AsyncClient(transport=ASGITransport(app=app), base_url='http://localhost') as client:
        config = request_for(url, 'cookie_scan', 'vuln_scan').model_dump()
        config['session'] = {'cookie': f'login={secret}'}
        report = (await client.post('/api/scan', json=config)).json()
        assert report['authentication_used'] is True
        assert observed and all(secret in header for header in observed)
        assert secret not in json.dumps(report)
        assert 'session' not in report['request']
        assert secret not in json.dumps(await get_scan(report['scan_id']))
        finding = next(item for item in report['findings'] if item['module'] == 'cookie_scan' and item['recheckable'])
        response = await client.post(f"/api/history/{report['scan_id']}/findings/{finding['id']}/recheck", json={})
        assert response.status_code == 422
        assert 'Supply the session again' in response.json()['detail']


async def test_cookie_disappearing_is_not_proof_of_fix(local_server):
    state = {'cookie': True}

    async def handler(request):
        return web.Response(text='app', headers={'Set-Cookie': 'login=example'} if state['cookie'] else {})

    async with local_server(handler) as url, AsyncClient(transport=ASGITransport(app=app), base_url='http://localhost') as client:
        report = (await client.post('/api/scan', json=request_for(url, 'cookie_scan').model_dump())).json()
        finding = next(item for item in report['findings'] if item['recheckable'])
        state['cookie'] = False
        result = (await client.post(f"/api/history/{report['scan_id']}/findings/{finding['id']}/recheck", json={})).json()
        assert result['state'] == 'not_checked'


async def test_browser_detects_js_and_request_failures_without_sending_writes(local_server):
    requests = []
    token = 'example-browser-session-token'

    async def handler(request):
        requests.append((request.path, request.method, request.headers.get('Cookie', '')))
        if request.path == '/':
            return web.Response(text="<html><title>App</title><script>fetch('/write', {method:'POST'}); fetch('/broken'); throw new Error(document.cookie);</script></html>", content_type='text/html')
        return web.Response(status=500)

    async with local_server(handler) as url:
        report = await execute_scan(request_for(url, 'browser_check', session=ScanSession(cookie=f'login={token}')))
    assert report.module_status['browser_check'] == 'partial', report.errors
    assert report.summary['confirmed'] >= 2
    assert any(item.rule_id.startswith('browser.javascript') for item in report.findings)
    assert any(item.rule_id.startswith('browser.http') for item in report.findings)
    assert all(method == 'GET' for _, method, _ in requests)
    assert any(token in cookie for _, _, cookie in requests)
    assert token not in json.dumps(report.model_dump())
    assert report.browser_check['blocked_requests']['writes'] == 1


async def test_cli_uses_same_engine_and_returns_failing_exit_status(local_server):
    async def handler(request):
        if request.path == '/.env':
            return web.Response(text='PASSWORD=example-cli-only')
        if request.path == '/':
            return web.Response(text='<html>app</html>', content_type='text/html')
        return web.Response(status=404)

    async with local_server(handler) as url:
        process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'backend.cli', 'scan', url, '--format', 'json', '--no-save',
                                                       stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
        assert process.returncode == 1, stderr.decode()
    report = json.loads(stdout)
    assert report['summary']['confirmed'] >= 1
    assert report['saved'] is False
    assert any(item['rule_id'] == 'file:/.env' for item in report['findings'])
    assert exit_status(dict(report, findings=[], status='partial')) == 2
    assert exit_status(dict(report, findings=[], status='success')) == 0
    markup = html_report(dict(report, target='<script>alert(1)</script>'))
    assert '<script>alert(1)</script>' not in markup
    assert '&lt;script&gt;' in markup


async def test_production_browser_check_identifies_development_script(local_server):
    async def handler(request):
        if request.path == '/@vite/client':
            return web.Response(text='', content_type='application/javascript')
        return web.Response(text='<html><script src="/@vite/client"></script></html>', content_type='text/html')
    async with local_server(handler) as url:
        result = await execute_scan(request_for(url, 'browser_check', environment='production'))
    finding = next(item for item in result.findings if item.rule_id == 'browser.development-build')
    assert finding.verification == 'confirmed'
    assert finding.evidence[0].observation == 'Development script: /@vite/client'
    assert result.score is None


def test_comparisons_exclude_changed_source_paths_and_browser_routes():
    from backend.services.comparison import compare_scans
    common = {'target': 'http://localhost:3000', 'timestamp': '2026-10-17', 'scanner_version': 3, 'score': None,
              'source_scan': {'status': 'success'}, 'browser_check': {'status': 'success'},
              'module_status': {'source_scan': 'success', 'browser_check': 'success'},
              'findings': [{'id': 'one', 'module': 'browser_check', 'title': 'Broken page', 'severity': 'medium'}]}
    before = dict(common, scan_id='before', request={'source_path': '/one', 'paths': ['/account']})
    after = dict(common, scan_id='after', findings=[], request={'source_path': '/two', 'paths': ['/settings']})
    comparison = compare_scans(before, after)
    assert comparison['comparable_modules'] == []
    assert comparison['resolved_findings'] == []
    assert comparison['score_delta'] is None
