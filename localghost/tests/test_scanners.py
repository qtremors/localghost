import ssl
from datetime import datetime, timedelta, timezone

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.scanners.cookie_scan import scan_cookies
from backend.scanners.cors_scan import scan_cors
from backend.scanners.port_scan import scan_ports
from backend.scanners.ssl_scan import scan_ssl
from backend.scanners.vuln_scan import check_vulnerabilities


async def test_spa_fallback_does_not_report_every_sensitive_file(local_server):
    async def handler(request):
        return web.Response(text='<html>Application shell</html>', content_type='text/html')
    async with local_server(handler) as url:
        result = await check_vulnerabilities(url + '/nested?query=1')
    assert not any(result.sensitive_files.values())
    assert not any('Exposed' in finding.title for finding in result.findings)


async def test_real_sensitive_file_uses_origin_root(local_server):
    paths = []
    async def handler(request):
        paths.append(request.path)
        if request.path == '/.env':
            return web.Response(text='DATABASE_PASSWORD=example')
        return web.Response(status=404)
    async with local_server(handler) as url:
        result = await check_vulnerabilities(url + '/nested?query=1')
    assert result.sensitive_files['/.env'] is True
    assert '/.env' in paths
    assert not any(path.startswith('/nested/') for path in paths)


async def test_redirects_do_not_scan_another_target(local_server):
    calls = []
    async def destination(request):
        calls.append(request.path)
        return web.Response(text='destination')
    async with local_server(destination) as other:
        async def redirect(request):
            raise web.HTTPFound(other)
        async with local_server(redirect) as url:
            await check_vulnerabilities(url)
            await scan_cookies(url)
            await scan_cors(url)
    assert calls == []


async def test_port_scan_includes_custom_target_port(local_server):
    async def handler(request):
        return web.Response(text='ok')
    async with local_server(handler) as url:
        result = await scan_ports(url)
    assert int(url.rsplit(':', 1)[1]) in [port['port'] for port in result.open_ports]


async def test_self_signed_certificate_is_inspected_but_not_trusted(tmp_path, local_server):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=60))
            .sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    async def handler(request):
        return web.Response(text='ok')
    async with local_server(handler, context) as url:
        result = await scan_ssl(url)
    assert result.has_ssl
    assert result.certificate['subject'] == 'localhost'
    assert result.protocol_version in ('TLSv1.2', 'TLSv1.3')
    assert not result.cert_valid
    assert 58 <= result.days_until_expiry <= 60
    assert any(finding.title == 'SSL Certificate Not Trusted' for finding in result.findings)
