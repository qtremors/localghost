"""Acceptance checks for route coverage, private evidence, login, Docker, and CLI fixes."""

import asyncio
import hashlib
import json
import sys

import pytest
from aiohttp import web
from pydantic import SecretStr

from backend.cli import html_report, text_report
from backend.database.db import get_scan
from backend.models.scan import ScanModules, ScanRequest, ScanSession
from backend.services.authentication import restricted_state
from backend.services.fixes import route_file
from backend.services.javascript import config_settings, router_paths
from backend.services.rechecks import perform_recheck
from backend.services.scanner import execute_scan
from backend.services.source import inspect_source
from backend.utils.redaction import private_values


def config(url, *checks, **options):
    return ScanRequest(target_url=url, modules=ScanModules(**{key: key in checks for key in ScanModules.model_fields}), **options)


def test_config_parser_ignores_comments_and_resolves_known_modes():
    body = '''// ignoreBuildErrors: true
    const ignored = false;
    export default { typescript: { ignoreBuildErrors: ignored },
      productionBrowserSourceMaps: process.env.NODE_ENV !== 'production',
      server: { cors: import.meta.env.DEV },
      unknown: [getOrigins()] };'''
    settings, errors = config_settings(body, 'vite.config.ts')
    assert not errors
    values = {item['key']: item for item in settings}
    assert values['typescript.ignoreBuildErrors']['production'] is False
    assert values['productionBrowserSourceMaps']['production'] is False
    assert values['productionBrowserSourceMaps']['development'] is True
    assert values['server.cors']['production'] is False
    assert values['server.cors']['development'] is True
    assert values['unknown']['known']['production'] is False
    json.dumps(settings)


@pytest.mark.parametrize(('body', 'expected'), [
    ('''import {createBrowserRouter as router} from 'react-router-dom';
        const routes = [{path:'/', children:[{path:'account'}, {path:'users/:id'}, {index:true}]}];
        const app = router(routes);''', {'/', '/account', '/users/:id'}),
    ('''import {Route as R, HashRouter} from 'react-router-dom';
        const section = 'account'; const app = <HashRouter><R path="/"><R path={section}/><R path="items/:id"/></R></HashRouter>;''', {'/#/', '/#/account', '/#/items/:id'}),
    ('''import {createHashRouter} from 'react-router-dom';
        createHashRouter([{path:'/', children:[{path:'account'}]}]);''', {'/#/', '/#/account'}),
])
def test_client_router_paths_include_nested_constants_and_hash_routes(body, expected):
    routes, unresolved = router_paths(body, 'src/routes.tsx')
    assert {item['path'] for item in routes} == expected
    assert not unresolved
    assert all(item['file'] == 'src/routes.tsx' for item in routes)


def test_computed_route_is_explicitly_unchecked():
    _, unresolved = router_paths("import {createBrowserRouter} from 'react-router-dom'; createBrowserRouter([{path:getPath()}]);", 'routes.js')
    assert unresolved and unresolved[0]['line'] == 1


def test_known_route_file_can_be_linked_with_real_dynamic_paths():
    source = {'dynamic_routes': [{'route': '/items/[id]', 'file': 'app/items/[id]/page.tsx'}, {'route': '/docs/[...slug]', 'file': 'app/docs/[...slug]/page.tsx'}]}
    assert route_file(source, 'http://localhost/items/123')['file'] == 'app/items/[id]/page.tsx'
    assert route_file(source, 'http://localhost/docs/one/two')['file'] == 'app/docs/[...slug]/page.tsx'


def test_source_fixes_are_real_diffs_and_secret_values_never_leave_preview(tmp_path):
    credential = 'ghp_4M9uZ2pC8xR6kN3wY7sT5aB1dF0qHjLVEiQo'
    (tmp_path / 'package.json').write_text('{"dependencies":{"next":"16"}}')
    (tmp_path / 'next.config.ts').write_text("// ignoreBuildErrors: true\nexport default {typescript:{ignoreBuildErrors:true}};\n")
    (tmp_path / 'private.js').write_text(f'const privateKey = "{credential}";')
    result = inspect_source(str(tmp_path))
    finding = next(item for item in result['findings'] if item['rule_id'] == 'source.next.ignore-build-errors')
    assert finding['fix_line'] == 2
    assert '-export default {typescript:{ignoreBuildErrors:true}};' in finding['fix_diff']
    assert '+export default {typescript:{ignoreBuildErrors:false}};' in finding['fix_diff']
    assert credential not in json.dumps(result)
    assert any(item['rule_id'].startswith('source.secret:') for item in result['findings'])
    assert (tmp_path / 'next.config.ts').read_text().endswith('ignoreBuildErrors:true}};\n')


async def test_selected_routes_get_cors_cookie_and_actual_response_evidence(local_server):
    async def handler(request):
        if request.path == '/private':
            return web.Response(text='private page', headers={'Set-Cookie': 'sid=internal-value; Path=/',
                                'Access-Control-Allow-Origin': request.headers.get('Origin', ''), 'Access-Control-Allow-Credentials': 'true'})
        return web.Response(text='<html>Public app</html>' if request.path == '/' else '', status=200 if request.path == '/' else 404)
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'vuln_scan', 'cookie_scan', 'cors_scan', paths=['/private']))
    private = report.route_results[url + '/private']
    assert set(private) == {'vuln_scan', 'cookie_scan', 'cors_scan'}
    finding = next(item for item in report.findings if item.module == 'cors_scan' and item.location == url + '/private' and item.severity.value == 'high')
    assert finding.evidence and all(item.captured for item in finding.evidence)
    assert any(item.request_headers.get('Origin') and item.response_headers.get('Access-Control-Allow-Origin') for item in finding.evidence)
    cookie = next(item for item in report.findings if item.module == 'cookie_scan' and item.location == url + '/private')
    assert cookie.evidence[0].status == 200
    assert 'internal-value' not in json.dumps(report.model_dump())
    assert 'sid=[redacted]' in json.dumps(report.model_dump())
    assert cookie.affected_pages == [url + '/private']
    assert cookie.recheckable


async def test_browser_observed_get_apis_receive_server_checks(local_server):
    async def handler(request):
        if request.path == '/':
            return web.Response(text="<html><script>fetch('/api/private')</script></html>", content_type='text/html')
        if request.path == '/api/private':
            return web.json_response({'ok': True}, headers={'Set-Cookie': 'api_session=value'})
        return web.Response(status=404)
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'browser_check', 'cookie_scan'))
    assert url + '/api/private' in report.audit_targets
    assert report.route_results[url + '/api/private']['cookie_scan']['cookies'][0]['name'] == 'api_session'


async def test_configured_secret_source_build_and_served_script_have_private_exact_evidence(local_server, tmp_path):
    credential = 'Z7b2H9q4L8w1M6n3P0d5R2c9T4v7F8k1'
    script = f'window.CONFIG = {{ service: "{credential}" }};'
    (tmp_path / '.env.production').write_text('SERVICE_SECRET=' + credential)
    (tmp_path / 'index.html').write_text('<script src="/assets/app.js"></script>')
    folder = tmp_path / 'dist' / 'assets'
    folder.mkdir(parents=True)
    (folder / 'app.js').write_text(script)
    state = {'fixed': False}

    async def handler(request):
        if request.path == '/assets/app.js':
            return web.Response(text='window.CONFIG={};' if state['fixed'] else script, content_type='application/javascript')
        return web.Response(text='<html><script src="/assets/app.js"></script></html>' if request.path == '/' else '', content_type='text/html', status=200 if request.path == '/' else 404)
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'source_scan', 'vuln_scan', source_path=str(tmp_path), environment='production'))
        assert report.environment_observation['observed'] == 'production'
        assert report.source_scan['production_assets'][0]['sha256'] == hashlib.sha256(script.encode()).hexdigest()
        finding = next(item for item in report.findings if item.rule_id.startswith('web.secret:'))
        assert finding.fix_file == '.env.production' and finding.fix_line == 1
        item = finding.evidence[0]
        assert item.captured and item.request_headers['Host'] and item.response_headers['Content-Type']
        assert '[redacted]' in item.response_body_excerpt
        assert item.page_url == url
        assert credential not in json.dumps(report.model_dump())
        assert credential not in json.dumps(await get_scan(report.scan_id))
        assert credential not in html_report(report.model_dump())
        assert credential not in text_report(report.model_dump())
        assert (await perform_recheck(report.model_dump(), finding.id))['state'] == 'still_present'
        state['fixed'] = True
        result = await perform_recheck(report.model_dump(), finding.id)
        assert result['state'] == 'resolved'
        assert result['report']['source_scan'] is not None
        original = (await get_scan(report.scan_id))['results']
        assert any(item['id'] == finding.id for item in original['findings'])


async def test_debug_evidence_captures_failing_response(local_server):
    async def handler(request):
        return web.Response(status=500 if request.path == '/broken' else 200 if request.path == '/' else 404,
                            text='Werkzeug Debugger __debugger__=yes' if request.path == '/broken' else 'App', content_type='text/html')
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'vuln_scan', paths=['/broken'], environment='production'))
    finding = next(item for item in report.findings if item.rule_id == 'web.debug:werkzeug')
    assert finding.verification == 'confirmed'
    assert finding.location == url + '/broken'
    assert finding.evidence[0].status == 500
    assert 'Werkzeug Debugger' in finding.evidence[0].response_body_excerpt
    assert report.module_status['vuln_scan'] == 'partial'


async def test_browser_form_login_audits_post_cookie_and_preserves_assertion_on_recheck(local_server):
    password, username, token = 'p7L2z9U4q6X1v8M3', 'local-review-user', 's4D1j7W9m3E8r5T2'
    state = {'fixed': False, 'authorized': [], 'posts': []}

    async def handler(request):
        if request.path == '/login':
            return web.Response(text='<form method="post" action="/session"><input name="username"><input name="password" type="password"><button type="submit">Log in</button></form>', content_type='text/html', headers={'Set-Cookie': 'bootstrap=initial-session-cookie; Path=/'})
        if request.path == '/session' and request.method == 'POST':
            body = await request.post()
            state['posts'].append(dict(body))
            if body.get('username') == username and body.get('password') == password:
                return web.Response(status=303, headers={'Location': '/private', 'Set-Cookie': f'sid={token}; Path=/' + ('; HttpOnly; SameSite=Lax' if state['fixed'] else '')})
            return web.Response(status=401)
        if request.path == '/private':
            state['authorized'].append(request.cookies.get('sid') == token)
            return web.Response(text='<main id="account">Signed in</main>' if request.cookies.get('sid') == token else 'Sign in',
                                status=200 if request.cookies.get('sid') == token else 401, content_type='text/html')
        return web.Response(text='App' if request.path == '/' else '', status=200 if request.path == '/' else 404, content_type='text/html')
    def session():
        return ScanSession(login={'path': '/login', 'username': username, 'password': password, 'allowed_post_paths': ['/session'], 'success_selector': '#account'})
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'cookie_scan', 'browser_check', paths=['/private'], session=session()))
        assert report.authentication['status'] == 'verified', report.authentication
        assert report.authentication['profile']['check_path'] == '/private'
        assert report.authentication['profile']['check_selector'] == '#account'
        assert state['authorized'] and all(state['authorized'])
        assert len(state['posts']) == 1
        bootstrap = next(item for item in report.findings if "Cookie 'bootstrap' Missing HttpOnly" in item.title)
        assert bootstrap.evidence[0].method == 'GET'
        assert bootstrap.evidence[0].url == url + '/login'
        finding = next(item for item in report.findings if "Cookie 'sid' Missing HttpOnly" in item.title)
        assert finding.evidence[0].method == 'POST'
        assert finding.evidence[0].url == url + '/session'
        assert finding.evidence[0].status == 303
        encoded = json.dumps(report.model_dump())
        for value in (password, username, token):
            assert value not in encoded
        state['fixed'] = True
        assert (await perform_recheck(report.model_dump(), finding.id, session()))['state'] == 'resolved'
        expired = ScanSession(cookie='sid=expired')
        result = await perform_recheck(report.model_dump(), finding.id, expired)
        assert result['state'] == 'not_checked'
        assert result['report']['authentication']['status'] == 'error'


async def test_failed_login_and_failed_header_assertions_do_not_scan_anonymous_pages(local_server):
    visited = []

    async def handler(request):
        visited.append(request.path)
        if request.path == '/login':
            return web.Response(text='<form><input name="username"><input type="password"><button type="submit">Login</button></form>', content_type='text/html')
        return web.Response(status=401)
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'vuln_scan', 'cookie_scan', session=ScanSession(cookie='sid=expired', check_path='/account')))
    assert report.authentication['status'] == 'error'
    assert report.status == 'error'
    assert visited == ['/account']
    assert not report.route_results
    assert all(item.verification == 'not_checked' for item in report.findings)


async def test_session_assertion_connection_failure_produces_report():
    report = await execute_scan(config('http://127.0.0.1:1', 'cookie_scan', session=ScanSession(cookie='sid=expired', check_path='/account')), persist=False)
    assert report.authentication['status'] == 'error'
    assert report.authentication['evidence'][0]['error']
    assert report.status == 'error'


def test_browser_state_rejects_foreign_origin_or_cookie():
    with private_values(), pytest.raises(ValueError):
        restricted_state(json.dumps({'cookies': [{'domain': 'other.local', 'value': 'private'}]}), 'http://127.0.0.1:3000')
    with private_values(), pytest.raises(ValueError):
        restricted_state(json.dumps({'origins': [{'origin': 'http://other.local', 'localStorage': []}]}), 'http://127.0.0.1:3000')


async def test_local_storage_login_refreshes_session_before_server_audits(local_server):
    first, refreshed = 'first-9Q3h8V2m5K1w', 'fresh-7T4c9P2b6D8z'
    observed, posts = [], []

    async def handler(request):
        if request.method == 'POST':
            posts.append(request.path)
            if request.path == '/signin':
                return web.json_response({'token': first})
            if request.path == '/refresh':
                return web.json_response({'token': refreshed})
        if request.path == '/login':
            return web.Response(text='''<input name="username"><input type="password"><button type="submit" onclick="fetch('/signin',{method:'POST'}).then(r=>r.json()).then(data=>{localStorage.setItem('access_token',data.token);location.href='/account';})">Log in</button>''', content_type='text/html')
        if request.path == '/account':
            return web.Response(text='''<main id="signed-in">Account</main><script>if(localStorage.getItem('access_token'))fetch('/refresh',{method:'POST'}).then(r=>r.json()).then(data=>{localStorage.setItem('access_token',data.token);});</script>''', content_type='text/html')
        observed.append(request.headers.get('Authorization'))
        return web.Response(text='App')
    session = ScanSession(login={'username': 'local-user', 'password': SecretStr('private-password'), 'success_selector': '#signed-in', 'allowed_post_paths': ['/signin']},
                          refresh_path='/refresh', authorization_storage_key='access_token')
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'cookie_scan', 'browser_check', paths=['/account'], session=session))
    assert report.authentication['status'] == 'verified'
    assert '/signin' in posts and '/refresh' in posts
    assert observed[-1] == 'Bearer ' + refreshed
    assert first not in json.dumps(report.model_dump()) and refreshed not in json.dumps(report.model_dump())
    assert report.browser_check['blocked_requests']['writes'] == 0


async def test_docker_discovery_uses_filtered_inspection_and_source_mounts(tmp_path, monkeypatch):
    from backend.services import docker
    calls = []

    async def docker_json(*args, **kwargs):
        calls.append(args)
        if args[0] == 'ps':
            return [{'ID': 'fixture'}]
        return {'id': 'fixture', 'name': '/app', 'image': 'fixture:latest', 'ports': {'3000/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '33000'}], '9090/udp': None},
                'mounts': [{'Type': 'bind', 'Source': str(tmp_path), 'Destination': '/app'}], 'working_dir': '/app', 'compose_project': 'project', 'compose_service': 'web'}
    monkeypatch.setattr(docker, 'docker_json', docker_json)
    result = await docker.discover_containers()
    item = result['containers'][0]
    assert item['targets'] == [{'url': 'http://127.0.0.1:33000', 'container_port': 3000}]
    assert item['source_path'] == str(tmp_path)
    assert item['compose_service'] == 'web'
    template = calls[1][2]
    assert '.Config.Env' not in template and '{{json .Config}}' not in template
    assert '--host=' in docker.local_docker_command()[1]


async def test_cli_config_and_file_recheck_use_the_shared_checks(local_server, tmp_path):
    state = {'exposed': True}

    async def handler(request):
        if request.path == '/.env' and state['exposed']:
            return web.Response(text='PASSWORD=not-a-real-secret')
        return web.Response(text='App' if request.path == '/' else '', status=200 if request.path == '/' else 404)
    async def cli(*args):
        process = await asyncio.create_subprocess_exec(sys.executable, '-m', 'backend.cli', *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await asyncio.wait_for(process.communicate(), 25)
        assert not stderr, stderr.decode()
        return process.returncode, json.loads(stdout)
    async with local_server(handler) as url:
        setup = tmp_path / 'config.json'
        setup.write_text(json.dumps(config(url, 'vuln_scan', paths=['/other']).model_dump()))
        code, report = await cli('scan', '--config', str(setup), '--no-save', '--format', 'json')
        assert code == 1
        assert url + '/other' in report['route_results']
        finding = next(item for item in report['findings'] if item['rule_id'] == 'file:/.env')
        baseline = tmp_path / 'baseline.json'
        baseline.write_text(json.dumps(report))
        code, result = await cli('recheck', str(baseline), finding['id'], '--no-save', '--format', 'json')
        assert code == 1 and result['state'] == 'still_present'
        state['exposed'] = False
        code, result = await cli('recheck', str(baseline), finding['id'], '--no-save', '--format', 'json')
        assert code == 0 and result['state'] == 'resolved'


async def test_invalid_session_input_is_not_echoed_by_api():
    from httpx import ASGITransport, AsyncClient

    from backend.main import app
    secret = 'private-input-7C2x9L5m'
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://localhost') as client:
        response = await client.post('/api/scan', json={'target_url': 'localhost:3000', 'session': {'cookie': secret, 'login': {'password': secret}}})
    assert response.status_code == 422
    assert secret not in response.text
    assert all('input' not in item for item in response.json()['detail'])


async def test_generated_javascript_cannot_stall_credential_patterns():
    # A child process makes the deadline effective even if a regex blocks Python.
    script = "from backend.services.secrets import scan_text; from backend.utils.redaction import redact_text; text='a'*500000; assert not scan_text(text); assert redact_text(text)==text"
    process = await asyncio.create_subprocess_exec(sys.executable, '-c', script, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    try:
        _, stderr = await asyncio.wait_for(process.communicate(), 8)
        assert process.returncode == 0, stderr.decode()
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


def test_unused_config_objects_do_not_become_configuration_findings():
    settings, error = config_settings("const unused = {typescript:{ignoreBuildErrors:true}}; export default {typescript:{ignoreBuildErrors:false}}", 'next.config.js')
    assert not error
    assert len(settings) == 1 and settings[0]['production'] is False


@pytest.mark.parametrize('value', ['low', 'high', 'success', 'error', 'unknown'])
async def test_preference_cookies_cannot_corrupt_scanner_schema(local_server, value):
    async def handler(request):
        return web.Response(text='App', headers={'Set-Cookie': f'security={value}; Path=/'})
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'cookie_scan', session=ScanSession(cookie='security=' + value)))
    assert report.status == 'success'
    assert all(item.severity.value in ('medium', 'low') for item in report.findings)
    assert report.cookie_scan.cookies[0]['value'] == '[redacted]'


async def test_sensitive_query_values_are_redacted_from_history_summary(local_server):
    secret = 'n6Q2v8L5b9T1m4C7'
    async def handler(request):
        return web.Response(text='App')
    async with local_server(handler) as url:
        report = await execute_scan(config(url + '?access_token=' + secret, 'cookie_scan'))
    stored = await get_scan(report.scan_id)
    assert secret not in json.dumps(stored)


async def test_rate_limit_classification_survives_exchange_capture(local_server, monkeypatch):
    from backend.services import scanner
    async def rate_check(url):
        return {'status': 'success', 'error': None, 'has_rate_limiting': True, 'evidence': 'headers', 'findings': []}
    monkeypatch.setattr(scanner, 'test_rate_limits', rate_check)
    async def handler(request):
        return web.Response(text='App')
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'rate_limit_test'), persist=False)
    assert report.rate_limit_test['evidence'] == 'headers'
    assert report.rate_limit_test['exchanges'][0]['captured'] is True


async def test_unavailable_check_can_be_repeated_without_claiming_failed_retries_are_fixed(local_server):
    state = {'ready': False}
    async def handler(request):
        return web.Response(text='App', status=200 if state['ready'] else 503)
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'cookie_scan'))
        finding = next(item for item in report.findings if item.verification == 'not_checked')
        assert finding.recheckable
        assert (await perform_recheck(report.model_dump(), finding.id))['state'] == 'not_checked'
        state['ready'] = True
        assert (await perform_recheck(report.model_dump(), finding.id))['state'] == 'resolved'


def test_truncated_private_key_excerpts_are_redacted():
    from backend.utils.redaction import redact_text
    partial = '-----BEGIN PRIVATE KEY-----\n' + 'QWERTY23456789' * 100
    assert 'QWERTY' not in redact_text(partial)


async def test_same_served_secret_keeps_every_affected_page(local_server, tmp_path):
    credential = 'c7G2v9M4k1S8p3Q6t5R0x2W9n4D7b8L1'
    (tmp_path / '.env').write_text('SERVICE_SECRET=' + credential)
    (tmp_path / 'index.html').write_text('<html>app</html>')
    async def handler(request):
        if request.path == '/app.js':
            return web.Response(text='window.config=' + json.dumps(credential), content_type='application/javascript')
        return web.Response(text='<html><script src="/app.js"></script></html>', content_type='text/html', status=200 if request.path in ('/', '/account') else 404)
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'source_scan', 'vuln_scan', source_path=str(tmp_path), paths=['/account']))
    finding = next(item for item in report.findings if item.rule_id.startswith('web.secret:'))
    assert set(finding.affected_pages) == {url, url + '/account'}
    assert {item.page_url for item in finding.evidence} == {url, url + '/account'}


def test_common_password_word_does_not_change_default_login_selectors():
    from backend.utils.redaction import private_values, redact_data
    with private_values(['password']):
        result = redact_data({'profile': {'login': {'password_selector': 'input[type="password"]'}}, 'description': 'Reflected credential: password'})
    assert result['profile']['login']['password_selector'] == 'input[type="password"]'
    assert 'password' not in result['description']


async def test_recheck_will_not_overwrite_the_original_export(tmp_path):
    from backend.cli import parser, run
    path = tmp_path / 'original.json'
    path.write_text('{"original":true}')
    args = parser().parse_args(['recheck', str(path), 'finding', '--output', str(path), '--no-save'])
    with pytest.raises(ValueError, match='preserve original evidence'):
        await run(args)
    assert path.read_text() == '{"original":true}'


async def test_session_lost_during_browser_checks_blocks_anonymous_server_audits(local_server):
    async def handler(request):
        if request.path == '/private':
            return web.Response(text='Private', status=200 if request.cookies.get('sid') == 'active' else 401)
        if request.path == '/signout':
            return web.Response(text='Signed out', headers={'Set-Cookie': 'sid=; Max-Age=0; Path=/'})
        return web.Response(text="<html><script>fetch('/signout')</script></html>", content_type='text/html')
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'browser_check', 'cookie_scan', session=ScanSession(cookie='sid=active', check_path='/private')))
    assert report.authentication['status'] == 'error'
    assert report.authentication['checked_after_pages'] is True
    assert report.module_status['cookie_scan'] == 'error'
    assert not report.route_results


async def test_new_response_cookie_is_redacted_if_also_reflected_in_the_body(local_server):
    token = 'new-cookie-4Q8w1V7m2T9b'
    async def handler(request):
        return web.Response(text=f'<html>Current user reference: {token}</html>' if request.path == '/' else '', content_type='text/html',
                            status=200 if request.path == '/' else 404, headers={'Set-Cookie': f'sid={token}; Path=/; HttpOnly'})
    async with local_server(handler) as url:
        report = await execute_scan(config(url, 'vuln_scan', 'cookie_scan'))
    assert token not in json.dumps(report.model_dump())


def test_quoted_cookie_values_are_omitted_without_losing_flags():
    from backend.utils.evidence import safe_headers
    with private_values():
        headers = safe_headers({'Set-Cookie': 'sid="private;value"; Path=/; HttpOnly; SameSite=Lax'})
    assert 'private' not in headers['Set-Cookie'] and 'value' not in headers['Set-Cookie']
    assert 'HttpOnly' in headers['Set-Cookie'] and 'SameSite=Lax' in headers['Set-Cookie']
