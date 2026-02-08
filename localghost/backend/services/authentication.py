"""Prepare an explicit local login/session without storing its private state."""

import json
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import SecretStr

from backend.models.scan import Evidence
from backend.services.projects import project_origin
from backend.utils.evidence import safe_headers, safe_url
from backend.utils.network import target_addresses
from backend.utils.redaction import register_secret
from backend.utils.runtime import scan_options


async def launch_browser(playwright, target):
    import os
    import shutil
    executable = os.getenv('LOCALGHOST_CHROMIUM_PATH')
    if not executable and not Path(playwright.chromium.executable_path).exists():
        executable = shutil.which('chromium') or shutil.which('chromium-browser')
    hostname = urlsplit(target).hostname
    addresses = target_addresses(hostname)
    address = addresses[0] if addresses else ''
    if ':' in address:
        address = f'[{address}]'
    args = [f'--host-resolver-rules=MAP {hostname} {address}'] if addresses else []
    if sys_platform_linux():
        # Avoid orphaned zygote processes when a container's PID 1 has no reaper.
        args.append('--no-zygote')
    return await playwright.chromium.launch(headless=True, args=args, **({'executable_path': executable} if executable else {}))


def sys_platform_linux():
    import sys
    return sys.platform.startswith('linux')


def restricted_state(encoded, origin):
    state = json.loads(encoded)
    if not isinstance(state, dict) or set(state) - {'cookies', 'origins'}:
        raise ValueError('Invalid browser session state')
    host = urlsplit(origin).hostname
    cookies = []
    for cookie in state.get('cookies', []):
        domain = cookie.get('domain', '').lstrip('.')
        if domain != host:
            raise ValueError('Browser session contains a cookie for another host')
        register_secret(cookie.get('value', ''))
        cookies.append(cookie)
    origins = []
    for item in state.get('origins', []):
        if item.get('origin') != origin:
            raise ValueError('Browser session contains another origin')
        for value in item.get('localStorage', []):
            register_secret(value.get('value', ''))
        origins.append(item)
    return {'cookies': cookies, 'origins': origins}


async def update_session(context, session, headers):
    state = await context.storage_state()
    origin = scan_options().get('origin')
    # Export no private state: retain it only in the current scan's context.
    state['origins'] = [item for item in state.get('origins', []) if item['origin'] == origin]
    scan_options()['browser_state'] = state
    cookies = await context.cookies(origin)
    headers.pop('Cookie', None)
    session.cookie = SecretStr('')
    if cookies:
        value = '; '.join(f"{cookie['name']}={cookie['value']}" for cookie in cookies)
        headers['Cookie'] = value
        session.cookie = SecretStr(value)
        for cookie in cookies:
            register_secret(cookie['value'])
    if session.authorization_storage_key:
        headers.pop('Authorization', None)
        session.authorization = SecretStr('')
        for item in state['origins']:
            for value in item.get('localStorage', []):
                if value['name'] == session.authorization_storage_key:
                    token = value['value']
                    register_secret(token)
                    headers['Authorization'] = token if token.startswith('Bearer ') else 'Bearer ' + token
                    session.authorization = SecretStr(headers['Authorization'])


async def prepare_session(target, session, headers):
    if session is None:
        return {'status': 'not_supplied', 'evidence': []}
    origin = project_origin(target)
    options = scan_options()
    options['origin'] = origin
    options['session'] = session
    options['session_headers'] = headers
    profile = {key: getattr(session, key) for key in ('check_path', 'check_selector', 'refresh_path', 'authorization_storage_key') if getattr(session, key)}
    if session.login:
        profile['login'] = session.login.model_dump(exclude={'username', 'password'})
    needs_browser = bool(session.login or session.storage_state or session.check_selector)
    if not needs_browser and not session.check_path:
        return {'status': 'supplied', 'method': 'headers', 'profile': profile, 'evidence': [], 'note': 'Credentials supplied; login validity was not asserted.'}
    if not needs_browser:
        import aiohttp

        from backend.utils.evidence import record_evidence
        from backend.utils.network import scanner_session
        with record_evidence(origin + session.check_path) as recorder:
            try:
                async with scanner_session(timeout=aiohttp.ClientTimeout(total=8)) as client:
                    async with client.get(origin + session.check_path, allow_redirects=False) as response:
                        verified = 200 <= response.status < 300
            except (aiohttp.ClientError, OSError, TimeoutError):
                verified = False
        return {'status': 'verified' if verified else 'error', 'method': 'headers', 'check_path': session.check_path,
                'profile': profile,
                'error': None if verified else 'The session check did not return a successful response.',
                'evidence': [item.model_dump() for item in recorder.items]}
    evidence = []
    try:
        from playwright.async_api import async_playwright
        state = restricted_state(session.storage_state.get_secret_value(), origin) if session.storage_state else None
        if session.login:
            register_secret(session.login.password.get_secret_value())
        evidence = []
        async with async_playwright() as playwright:
            browser = await launch_browser(playwright, target)
            try:
                context = await browser.new_context(service_workers='block', accept_downloads=False,
                                                    **({'storage_state': state} if state else {}))
                await context.set_extra_http_headers({key: value for key, value in headers.items() if key != 'Cookie'})
                if headers.get('Cookie'):
                    from http.cookies import SimpleCookie
                    cookie = SimpleCookie()
                    cookie.load(headers['Cookie'])
                    await context.add_cookies([{'name': name, 'value': value.value, 'url': origin + '/'} for name, value in cookie.items()])
                allowed_posts = {origin + path for path in session.login.allowed_post_paths} if session.login else set()
                if session.login:
                    allowed_posts.add(origin + session.login.path)
                if session.refresh_path:
                    allowed_posts.add(origin + session.refresh_path)

                async def gate(route):
                    request = route.request
                    allowed = project_origin(request.url) == origin and (request.method in ('GET', 'HEAD', 'OPTIONS') or request.method == 'POST' and request.url.split('?', 1)[0] in allowed_posts)
                    await route.continue_() if allowed else await route.abort('blockedbyclient')

                await context.route('**/*', gate)
                await context.route_web_socket('**/*', lambda socket: socket.close())
                page = await context.new_page()
                pending = set()

                async def captured(response):
                    cookies = [header['value'] for header in await response.headers_array() if header['name'].lower() == 'set-cookie']
                    if not cookies and response.request.method != 'POST' and response.url != origin + (session.check_path or ''):
                        return
                    item = Evidence(method=response.request.method, url=safe_url(response.url), status=response.status, captured=True,
                                             request_headers=safe_headers(await response.request.all_headers()), request_body='[sign-in body omitted]' if response.request.method == 'POST' else None,
                                             response_headers=safe_headers(await response.all_headers()), page_url=safe_url(page.url),
                                             observation='Explicit session preparation request. Credentials are omitted.')
                    evidence.append(item.model_dump())
                    if cookies:
                        options.setdefault('cookie_exchanges', []).append({'cookies': cookies, 'evidence': item})

                def captured_done(task):
                    pending.discard(task)
                    if not task.cancelled() and task.exception():
                        options['session_capture_incomplete'] = True

                def response_received(response):
                    import asyncio
                    task = asyncio.create_task(captured(response))
                    pending.add(task)
                    task.add_done_callback(captured_done)
                page.on('response', response_received)
                if session.login:
                    await page.goto(origin + session.login.path, wait_until='domcontentloaded', timeout=12000)
                    await page.locator(session.login.username_selector).fill(session.login.username.get_secret_value())
                    await page.locator(session.login.password_selector).fill(session.login.password.get_secret_value())
                    await page.locator(session.login.submit_selector).click(timeout=10000)
                    await page.locator(session.login.success_selector).wait_for(state='visible', timeout=12000)
                    signed_in = urlsplit(page.url)
                    if not session.check_path:
                        profile['check_path'] = signed_in.path + ('?' + signed_in.query if signed_in.query else '') + ('#' + signed_in.fragment if signed_in.fragment else '')
                    if not session.check_selector:
                        profile['check_selector'] = session.login.success_selector
                if session.check_path:
                    response = await page.goto(origin + session.check_path, wait_until='domcontentloaded', timeout=12000)
                    if not response or not 200 <= response.status < 300 or response.request.redirected_from and not session.check_selector:
                        raise ValueError('Session check failed')
                if session.check_selector:
                    if not session.login and not session.check_path:
                        await page.goto(target, wait_until='domcontentloaded', timeout=12000)
                    await page.locator(session.check_selector).wait_for(state='visible', timeout=10000)
                await update_session(context, session, headers)
                if pending:
                    import asyncio
                    await asyncio.gather(*pending, return_exceptions=True)
                await context.close()
            finally:
                await browser.close()
        verified = bool(session.login or session.check_path or session.check_selector)
        return {'status': 'verified' if verified else 'supplied', 'method': 'browser_login' if session.login else 'browser_state',
                'check_path': profile.get('check_path'), 'profile': profile, 'evidence': evidence,
                'evidence_complete': not options.get('session_capture_incomplete', False),
                'note': 'The configured login/session assertion passed. Other users and permissions were not tested.' if verified else 'Browser state supplied; login validity was not asserted.'}
    except Exception:
        return {'status': 'error', 'method': 'browser_login' if session.login else 'browser_state',
                'profile': profile,
                'error': 'The login/session assertion could not complete. Check the browser setup, allowed sign-in paths, selectors, and credentials.', 'evidence': evidence}


async def verify_current_session(target, session, headers, authentication):
    """Reassert refreshed state without signing in a second time."""
    profile = authentication.get('profile') or {}
    if not profile.get('check_path') and not profile.get('check_selector'):
        return authentication
    state = scan_options().get('browser_state')
    current = session.model_copy(update={'login': None,
                                        'storage_state': SecretStr(json.dumps(state)) if state and profile.get('check_selector') else None,
                                        'check_path': profile.get('check_path'), 'check_selector': profile.get('check_selector')})
    fresh = await prepare_session(target, current, headers)
    scan_options()['session'] = current
    return {**authentication, 'status': fresh['status'], 'error': fresh.get('error'),
            'checked_after_pages': True, 'evidence': [*authentication.get('evidence', []), *fresh.get('evidence', [])]}
