"""Limit browser access to the local UI and its own API origin."""

import os
from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse

from backend.utils.validators import is_private_address

MAX_API_BODY = 65536
UI_POLICY = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)


def _origin(value):
    parsed = urlsplit(value)
    if parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username or parsed.password or parsed.path not in ('', '/') or parsed.query or parsed.fragment:
        raise ValueError('Invalid origin')
    return parsed.scheme, parsed.hostname.lower().rstrip('.'), parsed.port or (443 if parsed.scheme == 'https' else 80)


class LocalAccessMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        headers = Headers(scope=scope)
        host = headers.get('host', '')
        try:
            if any(char in host for char in ('/', '\\', '@', '?', '#')):
                raise ValueError('Invalid host')
            scheme, hostname, port = _origin(f"{scope.get('scheme', 'http')}://{host}")
        except ValueError:
            return await JSONResponse({'detail': 'Invalid Host header'}, status_code=400)(scope, receive, send)
        extra_hosts = {name.strip().lower().rstrip('.') for name in os.getenv('LOCALGHOST_ALLOWED_HOSTS', '').split(',') if name.strip()}
        if hostname != 'localhost' and not is_private_address(hostname) and hostname not in extra_hosts:
            return await JSONResponse({'detail': 'Host is not allowed. Use a local address or configure LOCALGHOST_ALLOWED_HOSTS.'}, status_code=400)(scope, receive, send)
        if scope['path'].startswith('/api/') and scope['method'] in ('POST', 'PUT', 'PATCH', 'DELETE'):
            origin = headers.get('origin')
            try:
                permitted_origin = origin is None or _origin(origin) == (scheme, hostname, port)
            except ValueError:
                permitted_origin = False
            if not permitted_origin or headers.get('sec-fetch-site') == 'cross-site':
                return await JSONResponse({'detail': 'Requests must come from the Localghost page.'}, status_code=403)(scope, receive, send)
            try:
                too_large = int(headers.get('content-length', '0')) > MAX_API_BODY
            except ValueError:
                too_large = True
            if too_large:
                return await JSONResponse({'detail': 'Request body is too large'}, status_code=413)(scope, receive, send)
        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            received += len(message.get('body', b''))
            if scope['path'].startswith('/api/') and received > MAX_API_BODY:
                raise HTTPException(413, 'Request body is too large')
            return message

        async def protected_send(message):
            if message['type'] == 'http.response.start':
                response_headers = MutableHeaders(scope=message)
                response_headers['X-Content-Type-Options'] = 'nosniff'
                response_headers['X-Frame-Options'] = 'DENY'
                response_headers['Referrer-Policy'] = 'no-referrer'
                response_headers['Cross-Origin-Opener-Policy'] = 'same-origin'
                response_headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
                if scope['path'] == '/' or scope['path'].startswith('/static/'):
                    response_headers['Content-Security-Policy'] = UI_POLICY
                if scope['path'].startswith('/api/'):
                    response_headers['Cache-Control'] = 'no-store'
            await send(message)

        await self.app(scope, limited_receive, protected_send)
