"""Loopback-only servers with real, deliberate flaws and a fixed comparison app.

These return synthetic test data, never files or credentials from the host.
Run with ``uv run python tests/lab_servers.py --output /tmp/localghost-lab``.
"""

import argparse
import asyncio
import json
import ssl
import time
import uuid
from datetime import UTC, datetime, timedelta
from html import escape
from pathlib import Path

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

VALID_HEADERS = {
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
    'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', 'Permissions-Policy': 'camera=(), microphone=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
}


def handler_for(mode):
    timestamps = []

    async def handler(request):
        if mode == 'api':
            return web.json_response({'status': 'ok'}, headers={'X-Content-Type-Options': 'nosniff'}) if request.path == '/' else web.Response(status=404)
        if mode == 'limited':
            now = time.monotonic()
            timestamps[:] = [value for value in timestamps if now - value < 1]
            if len(timestamps) >= 10:
                return web.Response(status=429, text='Too many requests', headers={'Retry-After': '1'})
            timestamps.append(now)
        if mode == 'unavailable':
            return web.Response(status=503, text='Maintenance')
        if mode == 'dynamic-fallback':
            return web.Response(text=f'<html><title>Not found</title><p>{escape(request.path)}</p><p>Request {uuid.uuid4().hex}</p></html>', content_type='text/html')
        if mode == 'weak' and request.path == '/.env':
            return web.Response(text='DATABASE_PASSWORD=synthetic-lab-password\nDEBUG=true\n')
        if request.path == '/api/private':
            response = web.json_response({'example_private_record': 'lab-only'})
        elif request.path in ('/', '/search'):
            value = request.query.get('q', 'Localghost test server')
            body = value if mode == 'weak' else escape(value)
            response = web.Response(text=f'<html><title>Localghost {mode}</title><body>{body}</body></html>', content_type='text/html')
            if mode == 'weak':
                response.headers['Set-Cookie'] = 'session=synthetic-lab-cookie; Secure; HttpOnly; SameSite=invalid'
                response.headers.update({'X-Frame-Options': 'ALLOWALL', 'X-Content-Type-Options': 'incorrect',
                                         'Strict-Transport-Security': 'max-age=0', 'Content-Security-Policy': "default-src * 'unsafe-inline'"})
        else:
            response = web.Response(status=404, text='Not found')
        if mode == 'weak':
            # A safe OPTIONS response must not hide an unsafe simple GET policy.
            origin = 'https://trusted.example' if request.method == 'OPTIONS' else request.headers.get('Origin', '')
            if origin:
                response.headers['Access-Control-Allow-Origin'] = origin
                response.headers['Access-Control-Allow-Credentials'] = 'true'
        elif mode == 'fixed':
            response.headers.update(VALID_HEADERS)
        return response
    return handler


async def start_servers(output):
    output.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(UTC)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=10))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
                   .sign(key, hashes.SHA256()))
    cert_path, key_path = output / 'certificate.pem', output / 'private-key.pem'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    runners, urls = [], {}
    for mode in ('weak', 'fixed', 'dynamic-fallback', 'unavailable', 'self-signed', 'limited', 'attacker', 'api'):
        app = web.Application()
        app.router.add_route('*', '/{path:.*}', handler_for('fixed' if mode == 'self-signed' else mode))
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0, ssl_context=context if mode == 'self-signed' else None)
        await site.start()
        urls[mode] = f"{'https' if mode == 'self-signed' else 'http'}://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        runners.append(runner)
    (output / 'urls.json').write_text(json.dumps(urls, indent=2))
    return urls, runners


async def main(output):
    urls, runners = await start_servers(output)
    print(json.dumps(urls), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        for runner in runners:
            await runner.cleanup()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    asyncio.run(main(parser.parse_args().output))
