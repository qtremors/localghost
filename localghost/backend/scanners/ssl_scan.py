"""SSL/TLS certificate and protocol analysis scanner."""

import ssl
import socket
import asyncio
from datetime import datetime, timezone
from urllib.parse import urlparse
from backend.models.scan import SSLScanResult, Finding, Severity


async def scan_ssl(target_url: str) -> SSLScanResult:
    """Analyze SSL/TLS configuration of the target."""
    result = SSLScanResult()
    findings = []

    parsed = urlparse(target_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 443)

    # Try SSL connection
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # We want to inspect even invalid certs

        loop = asyncio.get_event_loop()

        def _check_ssl():
            conn = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
            conn.settimeout(5)
            try:
                conn.connect((host, port))
                cert = conn.getpeercert(binary_form=False)
                cipher = conn.cipher()
                version = conn.version()
                return cert, cipher, version
            except ssl.SSLError:
                # Try to get cert even if validation fails
                try:
                    conn2 = ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
                    conn2.settimeout(5)
                    conn2.connect((host, port))
                    return conn2.getpeercert(binary_form=False), conn2.cipher(), conn2.version()
                except Exception:
                    return None, None, None
            finally:
                conn.close()

        cert, cipher, version = await loop.run_in_executor(None, _check_ssl)

        if cert:
            result.has_ssl = True

            # Parse certificate details
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            not_after = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")

            result.certificate = {
                "subject": subject.get("commonName", "Unknown"),
                "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
                "not_before": not_before,
                "not_after": not_after,
                "serial_number": cert.get("serialNumber", ""),
                "san": [entry[1] for entry in cert.get("subjectAltName", ())]
            }

            # Check expiry
            if not_after:
                try:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_left = (expiry - now).days
                    result.days_until_expiry = days_left
                    result.cert_expired = days_left < 0
                    result.cert_valid = days_left >= 0

                    if days_left < 0:
                        findings.append(Finding(
                            title="SSL Certificate Expired",
                            severity=Severity.CRITICAL,
                            description=f"Certificate expired {abs(days_left)} days ago.",
                            recommendation="Renew the SSL certificate immediately."
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            title="SSL Certificate Expiring Soon",
                            severity=Severity.HIGH,
                            description=f"Certificate expires in {days_left} days.",
                            recommendation="Renew the SSL certificate before it expires."
                        ))
                    else:
                        findings.append(Finding(
                            title="SSL Certificate Valid",
                            severity=Severity.PASS,
                            description=f"Certificate is valid for {days_left} more days.",
                        ))
                except (ValueError, TypeError):
                    pass

            # Cipher info
            if cipher:
                result.cipher_suite = cipher[0] if cipher else ""
                result.protocol_version = version or ""

                findings.append(Finding(
                    title="TLS Protocol Version",
                    severity=Severity.PASS if version in ("TLSv1.2", "TLSv1.3") else Severity.HIGH,
                    description=f"Using {version or 'Unknown'} with cipher {cipher[0] if cipher else 'Unknown'}.",
                    recommendation="" if version in ("TLSv1.2", "TLSv1.3") else "Upgrade to TLS 1.2 or 1.3."
                ))
        else:
            result.has_ssl = False
            findings.append(Finding(
                title="No SSL/TLS Detected",
                severity=Severity.INFO,
                description=f"Could not establish SSL connection to {host}:{port}.",
                recommendation="Consider enabling HTTPS even for local development."
            ))

    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        result.has_ssl = False
        findings.append(Finding(
            title="SSL Connection Failed",
            severity=Severity.INFO,
            description=f"Could not connect to {host}:{port} for SSL check: {type(e).__name__}",
            recommendation="SSL/TLS may not be configured on this port."
        ))
    except Exception as e:
        findings.append(Finding(
            title="SSL Check Error",
            severity=Severity.INFO,
            description=f"Unexpected error during SSL check: {str(e)}",
        ))

    result.findings = findings
    return result
