"""Visit selected pages in Chromium and report observed page failures."""

from http.cookies import SimpleCookie
from urllib.parse import urlsplit

from backend.models.scan import Evidence, Finding, Severity
from backend.services.authentication import launch_browser, update_session
from backend.services.projects import project_origin
from backend.services.web_content import development_script
from backend.utils.evidence import safe_headers, safe_url
from backend.utils.runtime import scan_options


async def check_pages(target: str, paths: list[str], headers: dict | None = None) -> dict:
    try:
        from playwright.async_api import Error, async_playwright
    except ImportError:
        return {'status': 'error', 'error': 'Browser checks need Playwright. Install with uv sync --extra browser, then uv run playwright install chromium.', 'pages': [], 'findings': []}
    origin = project_origin(target)
    urls = list(dict.fromkeys([target, *(origin + path for path in paths)]))
    findings, pages = [], []
    api_requests = []
    secrets = list((headers or {}).values())

    def clean(text):
        for value in secrets:
            text = text.replace(value, '[redacted]')
            if value.startswith(('Bearer ', 'Basic ')):
                text = text.replace(value.split(' ', 1)[1], '[redacted]')
            # Cookie values may appear separately in a browser error message.
            for cookie in value.split(';'):
                _, separator, token = cookie.strip().partition('=')
                if separator and len(token) > 3:
                    text = text.replace(token, '[redacted]')
        return text[:500]

    stage = 'browser startup'
    try:
        async with async_playwright() as playwright:
            browser = await launch_browser(playwright, target)
            stage = 'session setup'
            try:
                state = scan_options().get('browser_state')
                context = await browser.new_context(service_workers='block', accept_downloads=False, **({'storage_state': state} if state else {}))
                if headers:
                    # Headers go on same-origin requests only; the route gate runs before network access.
                    await context.set_extra_http_headers({key: value for key, value in headers.items() if key != 'Cookie'})
                    cookies = SimpleCookie()
                    cookies.load(headers.get('Cookie', ''))
                    await context.add_cookies([{'name': name, 'value': value.value, 'url': origin + '/'} for name, value in cookies.items()])
                blocked = {'external': 0, 'writes': 0, 'websockets': 0}

                async def gate(route):
                    request = route.request
                    parsed = urlsplit(request.url)
                    if parsed.scheme in ('data', 'blob', 'about'):
                        await route.continue_()
                    elif project_origin(request.url) != origin:
                        blocked['external'] += 1
                        await route.abort('blockedbyclient')
                    elif request.method not in ('GET', 'HEAD', 'OPTIONS') and not (
                            scan_options().get('session') and scan_options()['session'].refresh_path
                            and request.method == 'POST' and request.url.split('?', 1)[0] == origin + scan_options()['session'].refresh_path):
                        blocked['writes'] += 1
                        await route.abort('blockedbyclient')
                    else:
                        await route.continue_()

                await context.route('**/*', gate)
                # WebSockets can bypass HTTP routing. Block them during page checks.
                async def block_socket(socket):
                    blocked['websockets'] += 1
                    await socket.close()

                await context.route_web_socket('**/*', block_socket)
                for url in urls:
                    stage = 'page load'
                    page = await context.new_page()
                    errors, failures, responses = [], [], []
                    response_objects = {}
                    before_blocked = dict(blocked)
                    page.on('pageerror', lambda error: errors.append(clean(error.stack or str(error))) if len(errors) < 20 else None)

                    def failed_response(response):
                        if (response.request.resource_type in ('fetch', 'xhr') and response.request.method == 'GET'
                                and project_origin(response.url) == origin and response.url not in api_requests and len(api_requests) < 20):
                            api_requests.append(response.url)
                        if project_origin(response.url) == origin and len(responses) < 200:
                            responses.append({'url': safe_url(response.url), 'status': response.status})
                            response_objects[safe_url(response.url)] = response
                        if response.status >= 400 and project_origin(response.url) == origin and len(failures) < 30:
                            failures.append({'url': safe_url(response.url), 'status': response.status, 'method': response.request.method,
                                             'resource': response.request.resource_type})

                    page.on('response', failed_response)

                    def failed_request(request):
                        reason = request.failure or 'No response'
                        if (len(failures) < 30 and project_origin(request.url) == origin
                                and request.method in ('GET', 'HEAD', 'OPTIONS') and 'BLOCKED_BY_CLIENT' not in reason):
                            failures.append({'url': safe_url(request.url), 'status': None, 'method': request.method,
                                             'resource': request.resource_type, 'error': clean(reason)})

                    page.on('requestfailed', failed_request)
                    state = {'url': url, 'status': None, 'state': 'success', 'errors': [], 'failed_requests': []}
                    response = None
                    try:
                        response = await page.goto(url, wait_until='domcontentloaded', timeout=10000)
                        state['status'] = response.status if response else None
                        await page.wait_for_timeout(500)
                        state['title'] = clean(await page.title())
                        scripts = await page.locator('script[src]').evaluate_all("scripts => scripts.map(script => script.getAttribute('src')).slice(0, 100)")
                        state['development_markers'] = [script for script in scripts if development_script(script)][:10]
                    except Error:
                        state.update(state='error', error='This page could not be loaded. Check redirects, TLS, and the connection.')
                    document_evidence = Evidence(url=safe_url(url), status=state['status'], captured=True,
                                                 page_url=safe_url(url), observation='Browser document request.')
                    stage = 'response evidence capture'
                    if response:
                        document_evidence.request_headers = safe_headers(await response.request.all_headers())
                        document_evidence.response_headers = safe_headers(await response.all_headers())
                    state['document_evidence'] = document_evidence.model_dump()
                    if scan_options().get('session'):
                        for resource in response_objects.values():
                            cookies = [item['value'] for item in await resource.headers_array() if item['name'].lower() == 'set-cookie']
                            if cookies:
                                cookie_evidence = Evidence(method=resource.request.method, url=safe_url(resource.url), status=resource.status, captured=True,
                                                           request_headers=safe_headers(await resource.request.all_headers()), response_headers=safe_headers(await resource.all_headers()),
                                                           page_url=safe_url(url), observation='Cookie set during the authenticated page load.')
                                scan_options().setdefault('cookie_exchanges', []).append({'cookies': cookies, 'evidence': cookie_evidence})
                    state.update(errors=errors[:20], failed_requests=failures[:30], responses=responses)
                    pages.append(state)
                    for error in dict.fromkeys(errors[:20]):
                        restricted = blocked['external'] > before_blocked['external'] or (
                            blocked['writes'] > before_blocked['writes'] and ('Failed to fetch' in error or 'NetworkError' in error))
                        script_evidence = []
                        for resource_url, resource in response_objects.items():
                            if resource_url in error:
                                script_evidence.append(Evidence(url=safe_url(resource_url), status=resource.status, captured=True, page_url=safe_url(url),
                                                                request_headers=safe_headers(await resource.request.all_headers()), response_headers=safe_headers(await resource.all_headers()),
                                                                observation='Script referenced by the captured JavaScript exception.'))
                        findings.append(Finding(rule_id='browser.javascript', title='JavaScript error on page', severity=Severity.MEDIUM,
                                                verification='review' if restricted else 'confirmed', location=url, description=error,
                                                recommendation='Open this page in your browser, inspect the stack trace, and fix the failing script.',
                                                evidence=[document_evidence.model_copy(update={'observation': error}), *script_evidence]).model_dump())
                    for failure in failures[:30]:
                        # Authentication boundaries are useful context, not proof of a broken app.
                        review = failure['status'] in (401, 403, 429)
                        title = f"HTTP {failure['status']} during page load" if failure['status'] else 'Request failed during page load'
                        detail = f"HTTP {failure['status']}" if failure['status'] else failure['error']
                        captured = Evidence(url=safe_url(failure['url']), method=failure['method'], status=failure['status'], captured=True,
                                            page_url=safe_url(url), error=failure.get('error'), observation=f"Observed while loading {url}")
                        resource = response_objects.get(failure['url'])
                        if resource:
                            captured.request_headers = safe_headers(await resource.request.all_headers())
                            captured.response_headers = safe_headers(await resource.all_headers())
                        findings.append(Finding(rule_id='browser.http', title=title, severity=Severity.MEDIUM,
                                                verification='review' if review else 'confirmed', location=failure['url'],
                                                description=f"The {failure['resource']} request failed with {detail} while loading {url}.",
                                                recommendation='Check the route, server logs, and required login session. Recheck after correcting the failure.',
                                                evidence=[captured]).model_dump())
                    await page.close()
                if scan_options().get('session'):
                    stage = 'session update'
                    await update_session(context, scan_options()['session'], scan_options()['session_headers'])
                await context.close()
            finally:
                await browser.close()
        incomplete = any(page['state'] != 'success' for page in pages) or any(blocked.values())
        error = 'Some pages could not be loaded, or page requests were blocked by the read-only browser checks.' if incomplete else None
        return {'status': 'partial' if incomplete else 'success', 'error': error,
                'pages': pages, 'findings': findings, 'blocked_requests': blocked, 'api_requests': api_requests,
                'limitations': ['Only the selected pages were visited. An explicitly configured sign-in is handled separately; other forms were not submitted.',
                                'External requests, WebSockets, and requests that change data were blocked.',
                                'Errors appearing after the initial page load may not be observed.']}
    except Exception as exc:
        message = 'Chromium could not start. Run uv run playwright install chromium, or set LOCALGHOST_CHROMIUM_PATH to an installed Chromium.' if stage == 'browser startup' else f'Browser checks stopped during {stage} ({type(exc).__name__}). Some pages or response details could not be checked.'
        return {'status': 'error', 'error': message,
                'pages': pages, 'findings': findings}
