"""Inspect TLS certificates independently from certificate trust verification."""

import asyncio
import ssl
from contextlib import suppress
from datetime import datetime, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.x509.oid import NameOID

from backend.models.scan import Finding, Severity, SSLScanResult
from backend.utils.evidence import record_observation
from backend.utils.network import open_target_connection


async def _tls_connection(host: str, port: int, context: ssl.SSLContext):
    writer = None
    try:
        async with asyncio.timeout(5):
            _, writer = await open_target_connection(
                host, port, ssl=context, server_hostname=host, ssl_handshake_timeout=5,
            )
            connection = writer.get_extra_info("ssl_object")
            record_observation('TLS', f'https://{host}:{port}',
                               {'hostname': host, 'port': port, 'verify_certificate': context.verify_mode != ssl.CERT_NONE},
                               {'protocol': connection.version(), 'cipher': connection.cipher(),
                                'certificate_der_sha256': __import__('hashlib').sha256(connection.getpeercert(binary_form=True)).hexdigest()},
                               'Observed TLS handshake; this is transport evidence, not an HTTP response.')
            return connection.getpeercert(binary_form=True), connection.cipher(), connection.version()
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        record_observation('TLS', f'https://{host}:{port}',
                           {'hostname': host, 'port': port, 'verify_certificate': context.verify_mode != ssl.CERT_NONE},
                           {}, 'TLS handshake did not complete.', type(exc).__name__)
        raise
    finally:
        if writer is not None:
            writer.close()
            with suppress(OSError, TimeoutError):
                async with asyncio.timeout(1):
                    await writer.wait_closed()


async def _inspect_tls(host: str, port: int):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    binary, cipher, version = await _tls_connection(host, port, context)
    certificate = x509.load_der_x509_certificate(binary)
    trusted = False
    trust_error = ""
    try:
        await _tls_connection(host, port, ssl.create_default_context())
        trusted = True
    except ssl.SSLCertVerificationError as exc:
        trust_error = exc.verify_message
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        trust_error = type(exc).__name__
    return certificate, cipher, version, trusted, trust_error


async def scan_ssl(target_url: str) -> SSLScanResult:
    parsed = urlsplit(target_url)
    host = parsed.hostname
    port = parsed.port or 443
    result = SSLScanResult()
    try:
        certificate, cipher, version, trusted, trust_error = await _inspect_tls(host, port)
        result.has_ssl = True
        result.protocol_version = version or ""
        result.cipher_suite = cipher[0] if cipher else ""
        now = datetime.now(timezone.utc)
        expiry = certificate.not_valid_after_utc
        result.days_until_expiry = (expiry - now).days
        result.cert_expired = expiry <= now
        result.cert_valid = trusted and certificate.not_valid_before_utc <= now < expiry
        names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        issuers = certificate.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        try:
            sans = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            san = [str(name.value) for name in sans]
        except x509.ExtensionNotFound:
            san = []
        result.certificate = {
            "subject": names[0].value if names else certificate.subject.rfc4514_string(),
            "issuer": issuers[0].value if issuers else certificate.issuer.rfc4514_string(),
            "not_before": certificate.not_valid_before_utc.isoformat(),
            "not_after": expiry.isoformat(), "serial_number": str(certificate.serial_number),
            "san": san,
        }
        if result.cert_expired:
            result.findings.append(Finding(title="SSL Certificate Expired", severity=Severity.CRITICAL,
                description=f"Certificate expired on {expiry.isoformat()}.", recommendation="Renew the certificate."))
        elif result.days_until_expiry < 30:
            result.findings.append(Finding(title="SSL Certificate Expiring Soon", severity=Severity.HIGH,
                description=f"Certificate expires in {result.days_until_expiry} days.", recommendation="Renew the certificate before it expires."))
        if not trusted:
            result.findings.append(Finding(title="SSL Certificate Not Trusted", severity=Severity.HIGH,
                description=f"Certificate inspection succeeded, but trust verification failed: {trust_error}.",
                recommendation="Use a trusted certificate matching the target hostname, or trust your local development CA."))
        elif result.cert_valid:
            result.findings.append(Finding(title="SSL Certificate Valid", severity=Severity.PASS,
                description=f"Trusted certificate valid for {result.days_until_expiry} more days."))
        modern = version in ("TLSv1.2", "TLSv1.3")
        result.findings.append(Finding(title="TLS Protocol Version", severity=Severity.PASS if modern else Severity.HIGH,
            description=f"Using {version or 'Unknown'} with cipher {result.cipher_suite}.",
            recommendation="" if modern else "Upgrade to TLS 1.2 or 1.3."))
    except (OSError, ssl.SSLError, ValueError, TimeoutError) as exc:
        if parsed.scheme == "https":
            result.status = "error"
            result.error = "Could not establish a TLS connection to the HTTPS target"
        result.findings.append(Finding(title="No SSL/TLS Connection", severity=Severity.INFO,
            description=f"Could not establish TLS to {host}:{port}: {type(exc).__name__}.",
            recommendation="Check that HTTPS is configured on the selected port."))
    return result
