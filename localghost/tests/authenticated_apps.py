"""Verify sessions on disposable, unmodified local Juice Shop and DVWA servers.

Start your own disposable containers first. This script uses their documented
training credentials; it does not initialize/reset a DVWA database.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.models.scan import ScanModules, ScanRequest, ScanSession  # noqa: E402
from backend.services.rechecks import perform_recheck  # noqa: E402
from backend.services.scanner import execute_scan  # noqa: E402


async def audit(target, paths, session):
    return await execute_scan(ScanRequest(target_url=target + '/', paths=paths, session=session, environment='production',
                                         modules=ScanModules(**{key: key in ('vuln_scan', 'cookie_scan', 'cors_scan', 'browser_check') for key in ScanModules.model_fields})), persist=False)


async def run(args):
    args.output.mkdir(parents=True, exist_ok=True)
    results = {}
    if args.juice_url:
        target = args.juice_url.rstrip('/')
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(target + '/rest/user/login', json={'email': 'admin@juice-sh.op', 'password': 'admin123'})
            response.raise_for_status()
            auth = response.json()['authentication']
        token = auth['token']
        state = {'cookies': [], 'origins': [{'origin': target, 'localStorage': [{'name': 'token', 'value': token}]}]}
        report = await audit(target, ['/#/basket', '/#/search'], ScanSession(authorization='Bearer ' + token, storage_state=json.dumps(state),
                                                                         authorization_storage_key='token', check_path=f"/rest/basket/{auth['bid']}"))
        assert report.authentication['status'] == 'verified' and report.authentication['checked_after_pages']
        assert len(report.browser_check['pages']) == 3, report.browser_check.get('error')
        assert all(page['status'] == 200 for page in report.browser_check['pages'])
        assert token not in json.dumps(report.model_dump())
        (args.output / 'juice-shop-authenticated.json').write_text(json.dumps(report.model_dump(), indent=2))
        results['juice_shop'] = {'session': 'verified before and after browser pages', 'pages': len(report.browser_check['pages']),
                                  'status': report.status, 'summary': report.summary, 'credential_redacted': True}
    if args.dvwa_url:
        target = args.dvwa_url.rstrip('/')

        def session():
            return ScanSession(login={'path': '/login.php', 'username': 'admin', 'password': 'password',
                                      'submit_selector': 'input[name="Login"]', 'success_selector': 'a[href="logout.php"]'})
        report = await audit(target, ['/vulnerabilities/xss_r/'], session())
        assert report.authentication['status'] == 'verified' and report.authentication['checked_after_pages']
        assert len(report.browser_check['pages']) == 2, report.browser_check.get('error')
        assert all(page['status'] == 200 for page in report.browser_check['pages'])
        finding = next(item for item in report.findings if "Cookie 'PHPSESSID' Missing HttpOnly" in item.title)
        recheck = await perform_recheck(report.model_dump(), finding.id, session(), persist=False)
        assert recheck['state'] == 'still_present'
        (args.output / 'dvwa-authenticated.json').write_text(json.dumps(report.model_dump(), indent=2))
        (args.output / 'dvwa-cookie-recheck.json').write_text(json.dumps(recheck, indent=2))
        results['dvwa'] = {'session': 'form login and signed-in element verified before and after pages',
                            'pages': len(report.browser_check['pages']), 'status': report.status, 'summary': report.summary,
                            'login_cookie_evidence': 'captured Set-Cookie', 'cookie_recheck': recheck['state']}
    assert results, 'Supply a disposable --juice-url and/or --dvwa-url'
    (args.output / 'authenticated-apps-results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--juice-url')
    parser.add_argument('--dvwa-url')
    parser.add_argument('--output', type=Path, required=True)
    asyncio.run(run(parser.parse_args()))
