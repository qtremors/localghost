"""Capture the exchange that produced an observation without retaining credentials."""

import re
from contextlib import contextmanager
from contextvars import ContextVar
from http.cookies import CookieError, SimpleCookie
from urllib.parse import unquote_plus, urlsplit, urlunsplit

import aiohttp

from backend.models.scan import Evidence
from backend.utils.redaction import redact_text, register_secret

MAX_EXCHANGES = 768
MAX_EXCERPT = 1800
_current: ContextVar['EvidenceRecorder | None'] = ContextVar('localghost_evidence', default=None)


def safe_url(value):
    parts = urlsplit(str(value))
    query = []
    for part in parts.query.split('&'):
        key, separator, value = part.partition('=')
        private = any(word in unquote_plus(key).lower() for word in ('token', 'password', 'secret', 'api_key', 'apikey', 'session'))
        query.append(key + separator + ('[redacted]' if private else redact_text(value)))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, '&'.join(query), parts.fragment))


def safe_headers(headers):
    output = {}
    for key, value in headers.items():
        lowered = key.lower()
        if lowered in ('authorization', 'proxy-authorization', 'x-api-key', 'x-auth-token') or 'token' in lowered or 'secret' in lowered:
            value = '[redacted]'
        elif lowered == 'cookie':
            parsed = SimpleCookie()
            try:
                parsed.load(value)
            except CookieError:
                parsed.clear()
            for cookie in parsed.values():
                register_secret(cookie.value)
            value = '; '.join(part.split('=', 1)[0].strip() + '=[redacted]' for part in value.split(';') if '=' in part)
        elif lowered == 'set-cookie':
            cookies = []
            for cookie in value.splitlines():
                parsed = SimpleCookie()
                try:
                    parsed.load(cookie)
                except CookieError:
                    parsed.clear()
                if parsed:
                    for morsel in parsed.values():
                        register_secret(morsel.value)
                        cookie = re.sub(re.escape(morsel.key) + r'\s*=\s*' + re.escape(morsel.coded_value), morsel.key + '=[redacted]', cookie, count=1)
                    cookies.append(cookie)
                else:
                    cookies.append(cookie.partition('=')[0] + '=[redacted; unparsed attributes omitted]')
            value = '\n'.join(cookies)
        elif lowered == 'location':
            value = safe_url(value)
        value = redact_text(value)[:2048]
        output[key] = (output.get(key, '') + ('\n' if key in output else '') + value)[:4096]
        if len(output) >= 40:
            break
    return output


class EvidenceRecorder:
    def __init__(self, page_url=''):
        self.page_url = page_url
        self.items: list[Evidence] = []
        self.limited = False

    def response(self, response):
        if len(self.items) >= MAX_EXCHANGES:
            self.limited = True
            return
        info = response.request_info
        item = Evidence(method=info.method, url=safe_url(info.real_url), status=response.status,
                        observation='Captured response headers.', captured=True,
                        request_headers=safe_headers(info.headers), response_headers=safe_headers(response.headers),
                        page_url=safe_url(self.page_url or info.real_url))
        self.items.append(item)
        response._localghost_evidence = item

    def failure(self, method, url, headers, error):
        if len(self.items) < MAX_EXCHANGES:
            self.items.append(Evidence(method=method, url=safe_url(url), captured=True,
                                      request_headers=safe_headers(headers), page_url=safe_url(self.page_url or url),
                                      observation='The request did not produce a response.', error=type(error).__name__))


@contextmanager
def record_evidence(page_url=''):
    recorder = EvidenceRecorder(page_url)
    token = _current.set(recorder)
    try:
        yield recorder
    finally:
        _current.reset(token)


def capture_trace():
    recorder = _current.get()
    if recorder is None:
        return None
    trace = aiohttp.TraceConfig()

    async def ended(session, context, params):
        recorder.response(params.response)

    async def failed(session, context, params):
        recorder.failure(params.method, params.url, params.headers, params.exception)

    trace.on_request_end.append(ended)
    trace.on_request_exception.append(failed)
    return trace


def capture_body(response, body, complete):
    item = getattr(response, '_localghost_evidence', None)
    if item is not None:
        text = body.decode('utf-8', errors='replace')
        # Never retain a complete private key, cookie, or configured secret in an excerpt.
        item.response_body_excerpt = redact_text(text)[:MAX_EXCERPT]
        item.response_body_truncated = not complete or len(text) > MAX_EXCERPT
        item.observation = 'Captured response headers and a redacted body excerpt.'


def source_evidence(file, line, excerpt, observation):
    return Evidence(method='FILE', url=file, observation=observation, captured=True,
                    source_file=file, source_line=line, source_excerpt=redact_text(excerpt)[:MAX_EXCERPT])


def record_observation(method, url, request, response, observation, error=None):
    """Record non-HTTP observations without representing them as HTTP exchanges."""
    recorder = _current.get()
    if recorder is not None and len(recorder.items) < MAX_EXCHANGES:
        recorder.items.append(Evidence(method=method, url=safe_url(url), captured=True,
                                       request_details=request, response_details=response, error=error,
                                       page_url=safe_url(recorder.page_url), observation=observation))
