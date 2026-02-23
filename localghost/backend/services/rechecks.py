"""Shared API/CLI rechecks with unchanged evidence and explicit scope."""

from backend.database.db import save_recheck
from backend.models.scan import ScanModules, ScanRequest, ScanResponse, ScanSession
from backend.services.scanner import execute_scan


def recheck_state(original, fresh):
    if original.get('verification') == 'not_checked':
        return 'resolved' if fresh.module_status.get(original['module']) == 'success' else 'not_checked'
    if any(finding.id == original['id'] for finding in fresh.findings):
        return 'still_present'
    module = original['module']
    if original['rule_id'].startswith('web.secret:configured-secret') and (fresh.source_scan or {}).get('status') != 'success':
        return 'not_checked'
    if module == 'vuln_scan' and original['rule_id'].startswith('file:'):
        path = original['rule_id'][5:]
        result = fresh.vuln_scan
        if fresh.authentication_used and (not result or not result.http_status or not 200 <= result.http_status < 300):
            return 'not_checked'
        return 'resolved' if result and result.sensitive_files.get(path) is False else 'not_checked'
    if module == 'ssl_scan' and (not fresh.ssl_scan or not fresh.ssl_scan.has_ssl):
        return 'not_checked'
    if module == 'cookie_scan':
        name = original['title'].split("'")[1] if "'" in original['title'] else ''
        route = fresh.route_results.get(original['location'], {}).get(module)
        cookies = route.get('cookies', []) if route else fresh.cookie_scan.cookies if fresh.cookie_scan else []
        if not any(cookie['name'] == name for cookie in cookies):
            return 'not_checked'
    if module == 'browser_check':
        result = fresh.browser_check or {}
        if original['rule_id'].startswith('browser.http'):
            observations = [item for page in result.get('pages', []) for item in page.get('responses', [])
                            if item['url'] == original['location']]
            return 'resolved' if observations and all(200 <= item['status'] < 300 for item in observations) else 'not_checked'
        pages = [page for page in result.get('pages', []) if page['url'] == original['location']]
        if not pages or any(page['state'] != 'success' or not page['status'] or not 200 <= page['status'] < 300 for page in pages):
            return 'not_checked'
    if module in ('xss_scan', 'ddos_test', 'rate_limit_test') and any(finding.module == module and finding.severity.value in ('critical', 'high', 'medium', 'low') for finding in fresh.findings):
        return 'not_checked'
    if fresh.module_status.get(module) == 'success':
        return 'resolved'
    return 'not_checked'



def has_credentials(session):
    return bool(session and (session.headers() or session.login or session.storage_state))


async def perform_recheck(original, finding_id, session=None, *, persist=True):
    finding = next((item for item in original.get('findings', []) if item['id'] == finding_id), None)
    if not finding or not finding.get('recheckable') or not original.get('request'):
        raise ValueError('This finding has no reproducible check. Run a new scan instead.')
    if original.get('scanner_version') != ScanResponse.model_fields['scanner_version'].default:
        raise ValueError('The scanner rules have changed. Run a new scan first.')
    if original.get('authentication_used') and not has_credentials(session):
        raise ValueError('This report used a session. Supply the session again to check the same scope.')
    if session:
        profile = (original.get('authentication') or {}).get('profile') or {}
        supplied = session.model_dump(exclude_unset=True)
        for key in ('check_path', 'check_selector'):
            if supplied.get(key) and profile.get(key) and supplied[key] != profile[key]:
                raise ValueError('The session assertion differs from the original scan. Run a new scan for the changed scope.')
        profile = dict(profile)
        login_profile = profile.pop('login', None)
        if supplied.get('login') and login_profile:
            supplied['login'] = {**login_profile, **supplied['login']}
        session = ScanSession.model_validate({**profile, **supplied})
    modules = {key: key == finding['module'] for key in ScanModules.model_fields}
    if original.get('source_scan') and original['request'].get('source_path'):
        modules['source_scan'] = True
    config = {**original['request'], 'modules': modules, 'session': session}
    request = ScanRequest.model_validate(config)
    fresh = await execute_scan(request, persist=persist,
                               recheck_of={'scan_id': original['scan_id'], 'finding_id': finding_id,
                                           'project_name': (original.get('source_scan') or {}).get('name')})
    state = recheck_state(finding, fresh)
    if fresh.saved:
        await save_recheck(original['scan_id'], finding_id, fresh.scan_id, state, fresh.timestamp)
    return {'finding_id': finding_id, 'state': state, 'scan_id': fresh.scan_id,
            'timestamp': fresh.timestamp, 'saved': fresh.saved,
            'finding': next((item.model_dump() for item in fresh.findings if item.id == finding_id), None),
            'errors': fresh.errors, 'unsaved_report': fresh.model_dump() if not fresh.saved else None,
            'report': fresh.model_dump()}
