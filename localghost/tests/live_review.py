"""Test real HTTP servers through Localghost's API and desktop UI.

Run the Localghost API first, then:
uv run --with playwright python tests/live_review.py --api-url http://127.0.0.1:13669 \
  --juice-url http://127.0.0.1:3000 --dvwa-url http://127.0.0.1:8080 \
  --next-url http://127.0.0.1:4173 --static-url http://127.0.0.1:5500 \
  --output /workspace/artifacts/backend-frontend-review

External target arguments are optional. Only use disposable local test apps.
The helper servers contain real intentional flaws and synthetic data.
"""

import argparse
import asyncio
import json
import re
from pathlib import Path
from urllib.parse import quote, urlsplit

import httpx
from lab_servers import start_servers
from playwright.async_api import async_playwright, expect

MODULES = ('port_scan', 'vuln_scan', 'ssl_scan', 'cors_scan', 'cookie_scan', 'tech_detect', 'dns_scan',
           'load_test', 'ddos_test', 'rate_limit_test', 'xss_scan')
CORE = MODULES[:7]


async def scan(client, api, name, target, output, modules=CORE):
    response = await client.post(api + '/api/scan', json={
        'target_url': target, 'ports_to_scan': [1],
        'modules': {module: module in modules for module in MODULES},
        'benchmark_config': {'concurrency': 5, 'duration_seconds': 1},
    })
    response.raise_for_status()
    report = response.json()
    (output / f'{name}-after.json').write_text(json.dumps(report, indent=2))
    if report.get('cookie_scan'):
        assert all(cookie['value'] == '[redacted]' for cookie in report['cookie_scan']['cookies'])
    if report.get('port_scan') and urlsplit(target).port != 13666:
        assert urlsplit(target).port in [item['port'] for item in report['port_scan']['open_ports']]
    print(f"{name}: {report['status']}, {report['summary']}", flush=True)
    return report


async def check_dvwa(client, target):
    # DVWA's disposable database is initialized through its own setup page.
    async with httpx.AsyncClient(follow_redirects=True, timeout=30) as session:
        setup = await session.get(target + '/setup.php')
        token = re.search(r'name=[\'\"]user_token[\'\"][^>]*value=[\'\"]([^\'\"]+)', setup.text)
        data = {'create_db': 'Create / Reset Database'}
        if token:
            data['user_token'] = token[1]
        await session.post(target + '/setup.php', data=data)
        login = await session.get(target + '/login.php')
        token = re.search(r'name=[\'\"]user_token[\'\"][^>]*value=[\'\"]([^\'\"]+)', login.text)
        data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
        if token:
            data['user_token'] = token[1]
        response = await session.post(target + '/login.php', data=data)
        logged_in = 'Logout' in response.text
        response = await session.get(target + '/vulnerabilities/sqli/', params={'id': "1' OR '1'='1", 'Submit': 'Submit'})
        rows = response.text.count('First name:')
        reflected = await session.get(target + '/vulnerabilities/xss_r/', params={'name': '<script>window.__dvwa_review_xss=1</script>'})
        assert logged_in and rows > 1 and '<script>window.__dvwa_review_xss=1</script>' in reflected.text
        return {'login': True, 'sql_injection_returned_multiple_records': rows > 1,
                'authenticated_reflected_script': True, 'control_session_created_outside_scanner': True}


async def browser_checks(api, urls, report, output, axe_path, juice_url=None):
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(executable_path='/usr/bin/chromium' if Path('/usr/bin/chromium').exists() else None, args=['--no-sandbox'])
        page = await browser.new_page(viewport={'width': 1440, 'height': 1100}, reduced_motion='reduce')
        errors = []
        page.on('pageerror', lambda error: errors.append(str(error)))
        accessibility = {}

        async def inspect(name):
            if axe_path:
                await page.evaluate(axe_path.read_text())
                result = await page.evaluate("axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21aa','best-practice']}})")
                accessibility[name] = [{'id': item['id'], 'impact': item['impact'], 'description': item['description'],
                                        'nodes': [{'target': node['target'], 'summary': node['failureSummary']} for node in item['nodes']]} for item in result['violations']]

        await page.goto(api)
        await expect(page.locator('#workspace-project-count')).not_to_have_text('0')
        await inspect('projects')
        await page.screenshot(path=str(output / 'projects.png'))
        await page.locator('#configure-btn').click()
        await page.locator('#target-url').fill(urls['weak'])
        await inspect('scan-setup')
        await page.screenshot(path=str(output / 'scan-setup.png'))
        await page.goto(f"{api}/#report/{report['scan_id']}")
        await expect(page.locator('#report-target')).to_have_text(urls['weak'])
        await expect(page.locator('#findings-list')).to_contain_text('Sensitive File Exposed: /.env')
        await inspect('report')
        await page.screenshot(path=str(output / 'vulnerable-report.png'))
        await page.locator('#tab-headers').click()
        await expect(page.locator('#panel-headers')).to_contain_text('nosniff')
        await page.locator('#tab-cors').click()
        await expect(page.locator('#panel-cors')).to_contain_text('https://trusted.example')
        await expect(page.locator('#panel-cors')).to_contain_text('https://evil-attacker.com')
        await inspect('cors-details')
        for tab in ('headers', 'ssl', 'cookies', 'tech', 'dns', 'benchmark', 'ddos', 'ratelimit'):
            await page.locator(f'#tab-{tab}').click()
            await inspect(tab)
        await page.locator('#tab-xss').click()
        await expect(page.locator('#panel-xss')).to_contain_text('do not run browser scripts')
        await inspect('xss')
        await page.locator('#theme-toggle').click()
        await inspect('xss-dark')
        await page.locator('#tab-all-findings').click()
        await inspect('report-dark')
        await page.locator('.primary-nav [data-view="reports"]').click()
        await inspect('reports-dark')
        await page.locator('.primary-nav [data-view="home"]').click()
        await inspect('projects-dark')
        await page.locator('#theme-toggle').click()
        # Evidence in a report must stay inert, including real reflected payloads.
        assert await page.evaluate('window.__lab_review_xss') is None
        assert not errors, errors

        target_page = await browser.new_page()
        payload = '<script>window.__lab_review_xss=1</script>'
        await target_page.goto(urls['weak'] + '/?q=' + quote(payload, safe=''))
        await target_page.wait_for_function('window.__lab_review_xss === 1')
        await target_page.goto(urls['fixed'] + '/?q=' + quote(payload, safe=''))
        assert await target_page.evaluate('window.__lab_review_xss') is None
        await target_page.goto(urls['attacker'])
        cors = await target_page.evaluate("async url => (await fetch(url, {credentials: 'include'})).json()", urls['weak'] + '/api/private')
        assert cors['example_private_record'] == 'lab-only'
        response = await target_page.evaluate("async url => { try { return (await fetch(url, {method: 'POST'})).status; } catch { return 'blocked'; } }", api + '/api/projects/discover')
        assert response in (403, 'blocked')
        if juice_url:
            payload = '<iframe src="javascript:window.parent.__juice_review_xss=1">'
            await target_page.goto(juice_url + '/#/search?q=' + quote(payload, safe=''))
            await target_page.wait_for_function('window.__juice_review_xss === 1', timeout=15000)
        await target_page.close()
        await browser.close()
    (output / 'accessibility.json').write_text(json.dumps(accessibility, indent=2))
    return {'reflected_script_executed_on_weak_app': True, 'script_did_not_execute_on_fixed_app': True,
            'foreign_page_read_weak_cors_response': True, 'report_payloads_remained_inert': True,
            'foreign_page_could_not_trigger_discovery': True, 'page_errors': errors,
            'juice_shop_browser_only_xss_executed': True if juice_url else None,
            'accessibility_violations': {name: len(items) for name, items in accessibility.items()}}


async def main(args):
    args.output.mkdir(parents=True, exist_ok=True)
    urls, runners = await start_servers(args.output / 'run-lab')
    reports, evidence = {}, {}
    try:
        async with httpx.AsyncClient(timeout=240) as client:
            reports['weak'] = await scan(client, args.api_url, 'weak', urls['weak'], args.output, MODULES)
            reports['fixed'] = await scan(client, args.api_url, 'fixed', urls['fixed'], args.output, (*CORE, 'xss_scan'))
            reports['dynamic'] = await scan(client, args.api_url, 'dynamic', urls['dynamic-fallback'], args.output)
            reports['unavailable'] = await scan(client, args.api_url, 'unavailable', urls['unavailable'], args.output)
            reports['tls'] = await scan(client, args.api_url, 'self-signed', urls['self-signed'], args.output, ('ssl_scan',))
            reports['limited'] = await scan(client, args.api_url, 'limited', urls['limited'], args.output, ('rate_limit_test',))
            reports['json-api'] = await scan(client, args.api_url, 'json-api', urls['api'], args.output)
            assert not any(finding['title'].startswith('Missing ') for finding in reports['json-api']['vuln_scan']['findings'])
            assert reports['weak']['vuln_scan']['sensitive_files']['/.env'] is True
            assert reports['weak']['cors_scan']['allow_credentials']
            metrics = reports['weak']['benchmark']
            assert metrics['requests_attempted'] == metrics['requests_successful'] + metrics['requests_failed'] + metrics['requests_incomplete']
            assert reports['weak']['xss_scan']['vulnerable'] is True
            assert reports['fixed']['xss_scan']['vulnerable'] is not True
            assert all(value is False for value in reports['dynamic']['vuln_scan']['sensitive_files'].values())
            assert all(reports['unavailable'][module]['status'] == 'error' for module in ('cors_scan', 'cookie_scan', 'tech_detect'))
            assert reports['unavailable']['score'] is None
            assert reports['tls']['ssl_scan']['has_ssl'] and not reports['tls']['ssl_scan']['cert_valid']
            assert reports['limited']['rate_limit_test']['evidence'] == 'responses'
            assert reports['limited']['rate_limit_test']['has_rate_limiting']
            for name, target in (('juice-shop', args.juice_url), ('dvwa', args.dvwa_url), ('nextjs', args.next_url), ('static-html-js', args.static_url)):
                if not target:
                    continue
                scanned_target = target + '/login.php' if name == 'dvwa' else target
                reports[name] = await scan(client, args.api_url, name, scanned_target, args.output, (*CORE, 'xss_scan'))
            if args.juice_url:
                response = await client.post(args.juice_url + '/rest/user/login', json={'email': "' OR 1=1--", 'password': 'example'})
                evidence['juice-shop'] = {'sql_injection_login_bypass': response.status_code == 200 and 'authentication' in response.json(),
                                         'sql_injection_checked_by_scanner': False}
                assert evidence['juice-shop']['sql_injection_login_bypass']
            if args.dvwa_url:
                evidence['dvwa'] = await check_dvwa(client, args.dvwa_url)
            if args.next_url:
                assert any(tech['name'] == 'Next.js' for tech in reports['nextjs']['tech_detect']['technologies'])
                assert reports['nextjs']['xss_scan']['vulnerable'] is not True
                assert not any(reports['nextjs']['vuln_scan']['sensitive_files'].values())
            if args.static_url:
                assert reports['static-html-js']['vuln_scan']['sensitive_files']['/.env'] is True
        evidence['browser'] = await browser_checks(args.api_url, urls, reports['weak'], args.output, args.axe_path, args.juice_url)
        summary = {'targets': {name: {'target': report['target'], 'status': report['status'], 'summary': report['summary'], 'module_status': report['module_status']} for name, report in reports.items()},
                   'evidence': evidence}
        (args.output / 'live-results.json').write_text(json.dumps(summary, indent=2))
        print(json.dumps(evidence, indent=2), flush=True)
        if args.axe_path:
            assert not any(evidence['browser']['accessibility_violations'].values()), 'Accessibility checks found violations; see accessibility.json'
    finally:
        for runner in runners:
            await runner.cleanup()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api-url', required=True)
    parser.add_argument('--juice-url')
    parser.add_argument('--dvwa-url')
    parser.add_argument('--next-url')
    parser.add_argument('--static-url')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--axe-path', type=Path)
    asyncio.run(main(parser.parse_args()))
