"""Inspect observed page and script content for exposed credentials and debug details."""

import hashlib
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import aiohttp

from backend.models.scan import Evidence, Finding, Severity
from backend.services.projects import project_origin
from backend.services.secrets import scan_text
from backend.utils.evidence import safe_headers, safe_url
from backend.utils.http import decode_body, read_limited
from backend.utils.redaction import redact_text
from backend.utils.runtime import scan_options


def development_script(url):
    path = urlsplit(url).path
    return (path in ('/@vite/client', '/@react-refresh') or path.startswith('/_next/static/') and
            any(marker in path for marker in ('/development/', 'next-devtools', 'next-dev_', 'browser_dev_hmr-client')))


class Scripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == 'script' and attributes.get('src'):
            self.urls.append(attributes['src'])


def evidence_for(response, text, start=0, end=0, observation='Observed response content.'):
    captured = getattr(response, '_localghost_evidence', None)
    if not captured:
        captured = Evidence(method=response.request_info.method, url=safe_url(response.url), status=response.status,
                            request_headers=safe_headers(response.request_info.headers), response_headers=safe_headers(response.headers),
                            captured=True, observation=observation)
    excerpt = text[max(0, start - 160):min(len(text), max(end, start + 300) + 160)]
    return captured.model_copy(update={'response_body_excerpt': redact_text(excerpt),
                                       'response_body_truncated': len(excerpt) < len(text), 'observation': observation})


def inspect_content(response, body, *, page_url, script=False):
    text = decode_body(body, response.charset)
    findings = []
    source = scan_options().get('source', {})
    for match in scan_text(text, include_assignments=script):
        description = ('A configured secret value' if match['kind'] == 'configured-secret' else f"A value matching the {match['kind']} credential format") + ' appeared in this browser response. Its validity was not tested. The value is redacted.'
        evidence = evidence_for(response, text, match['start'], match['end'], description)
        evidence.page_url = page_url
        linked = next((item for item in source.get('secret_sources', []) if item['fingerprint'] == match['fingerprint']), None)
        findings.append(Finding(rule_id=f"web.secret:{match['kind']}:{linked['name'] if linked else match['name']}", title='Credential material in a browser response', severity=Severity.HIGH,
                                verification='confirmed', location=str(response.url), affected_pages=[page_url],
                                description=description, evidence=[evidence],
                                fix_file=linked['file'] if linked else '', fix_line=linked['line'] if linked else None,
                                recommendation='Remove the credential from the response and client build. Use it only in server-side code, rebuild, and rotate it if it has been shared.'))
    debug_rules = [
        ('werkzeug', r'(?:Werkzeug Debugger|__debugger__=yes)', 'Interactive Python debugger is exposed', 'Disable Flask/Werkzeug debug mode and run a production WSGI server.'),
        ('django', r'Django Version[\s\S]{0,5000}Traceback|You.re seeing this error because you have DEBUG = True', 'Django debug page is exposed', 'Set DEBUG=False in the production settings and configure an ordinary error page.'),
        ('php', r'<(?:b|br)[^>]*>[\s\S]{0,120}(?:Fatal error|Warning):[\s\S]{0,500} on line ', 'PHP error details are exposed', 'Set display_errors=Off in production and send errors to the server log.'),
        ('node-stack', r'(?:Error|TypeError|ReferenceError):[^<\n]{1,200}(?:\n|<br[^>]*>)[ \t]*at [^<\n]{1,200}:[0-9]+:[0-9]+', 'Server stack trace is returned to the browser', 'Use a production error handler that logs the stack on the server and returns a short error response.'),
    ]
    if not script:
        for rule, pattern, title, recommendation in debug_rules:
            found = re.search(pattern, text, re.I)
            if found:
                evidence = evidence_for(response, text, found.start(), found.end(), 'Debug-only content was observed in the response.')
                evidence.page_url = page_url
                findings.append(Finding(rule_id=f'web.debug:{rule}', title=title, severity=Severity.HIGH, verification='confirmed',
                                        location=str(response.url), affected_pages=[page_url], description='The response contains framework debug details. See the captured excerpt.',
                                        recommendation=recommendation, evidence=[evidence]))
    return findings


async def inspect_page(response, body, session):
    url = str(response.url)
    findings = inspect_content(response, body, page_url=url)
    observed = {'url': url, 'development_markers': [], 'production_assets_matched': [], 'assets': [], 'limited': False}
    if response.content_type not in ('text/html', 'application/xhtml+xml'):
        return findings, observed
    scripts = Scripts()
    scripts.feed(decode_body(body, response.charset))
    script_urls = list(dict.fromkeys(urljoin(url, value) for value in scripts.urls))
    for value in script_urls:
        if development_script(value):
            observed['development_markers'].append(value)
    same_origin = [value for value in script_urls if project_origin(value) == project_origin(url)]
    observed['limited'] = len(same_origin) > 20
    source_assets = {item['url_path']: item for item in scan_options().get('source', {}).get('production_assets', [])}
    for asset in same_origin[:20]:
        try:
            async with session.get(asset, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as script:
                script_body, complete = await read_limited(script, 2 * 1024 * 1024)
                observed['assets'].append({'url': asset, 'status': script.status, 'complete': complete})
                if 200 <= script.status < 300:
                    findings.extend(inspect_content(script, script_body, page_url=url, script=True))
                    artifact = source_assets.get(urlsplit(asset).path)
                    if complete and artifact and artifact['sha256'] == hashlib.sha256(script_body).hexdigest():
                        observed['production_assets_matched'].append(artifact['file'])
                if not complete:
                    observed['limited'] = True
        except (aiohttp.ClientError, OSError, TimeoutError):
            observed['assets'].append({'url': asset, 'status': None, 'complete': False})
            observed['limited'] = True
    return findings, observed
