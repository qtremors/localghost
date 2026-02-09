"""Security headers and sensitive file vulnerability scanner."""

import asyncio
import uuid
from urllib.parse import urljoin, urlsplit

import aiohttp

from backend.models.scan import Finding, HeaderCheckResult, Severity, VulnScanResult
from backend.services.file_checks import classify_file
from backend.services.header_checks import check_header_value, has_frame_policy
from backend.services.web_content import inspect_page
from backend.utils.http import read_limited
from backend.utils.network import scanner_session

# Headers to check and their severity when missing
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": Severity.HIGH,
        "description": "HSTS prevents protocol downgrade attacks and cookie hijacking.",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header."
    },
    "Content-Security-Policy": {
        "severity": Severity.HIGH,
        "description": "CSP prevents XSS attacks by controlling resource loading.",
        "recommendation": "Define a Content-Security-Policy that restricts script and resource origins."
    },
    "X-Frame-Options": {
        "severity": Severity.MEDIUM,
        "description": "Prevents clickjacking by controlling iframe embedding.",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header."
    },
    "X-Content-Type-Options": {
        "severity": Severity.MEDIUM,
        "description": "Prevents MIME type sniffing attacks.",
        "recommendation": "Add 'X-Content-Type-Options: nosniff' header."
    },
    "Referrer-Policy": {
        "severity": Severity.LOW,
        "description": "Controls how much referrer information is sent with requests.",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin' header."
    },
    "Permissions-Policy": {
        "severity": Severity.LOW,
        "description": "Controls which browser features the page can use.",
        "recommendation": "Add a Permissions-Policy header to restrict unnecessary browser APIs."
    },
    "Cross-Origin-Opener-Policy": {
        "severity": Severity.LOW,
        "description": "COOP isolates the browsing context from cross-origin windows.",
        "recommendation": "Consider 'Cross-Origin-Opener-Policy: same-origin' where compatible with your login and popup flows."
    },
}

# Sensitive paths to probe — files that should NOT be publicly accessible
# Note: robots.txt, sitemap.xml, .well-known/security.txt are intentionally
# public files and are NOT included here. They are NOT security issues.
SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/package.json",
    "/.npmrc",
    "/.htaccess",
    "/wp-config.php",
    "/server-status",
    "/phpinfo.php",
    "/.DS_Store",
    "/backup.sql",
    "/dump.sql",
    "/.env.local",
    "/.env.production",
    "/config.yml",
    "/config.json",
]

# Critical files — exposure of these is a severe security risk
CRITICAL_PATHS = {"/.env", "/.git/config", "/.git/HEAD", "/backup.sql", "/dump.sql",
                  "/.env.local", "/.env.production", "/wp-config.php"}


async def check_vulnerabilities(target_url: str, *, include_files=True) -> VulnScanResult:
    """Check target URL for security misconfigurations."""

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    result = VulnScanResult()
    findings = []

    # 1. Check Security Headers
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with scanner_session(timeout=timeout) as session:
            async with session.get(target_url, allow_redirects=False) as response:
                result.http_status = response.status
                body, complete = await read_limited(response)
                content_findings, observations = await inspect_page(response, body, session)
                findings.extend(content_findings)
                result.runtime_observations.append(observations)
                if not complete or observations['limited']:
                    result.status = 'partial'
                    result.error = 'Some page or script content exceeded the inspection limit.'
                if not 200 <= response.status < 300:
                    raise ValueError(f'Target returned HTTP {response.status}; header checks were not completed')
                headers = response.headers
                document = response.content_type in ('text/html', 'application/xhtml+xml', 'image/svg+xml')
                for header_name, meta in SECURITY_HEADERS.items():
                    present = header_name in headers
                    value = headers.get(header_name) if present else None
                    applicable = not (header_name == 'Strict-Transport-Security' and urlsplit(target_url).scheme != 'https')
                    note = '' if applicable else 'HSTS is only used over HTTPS.'
                    if not document and header_name not in ('Strict-Transport-Security', 'X-Content-Type-Options'):
                        applicable = False
                        note = f'Not used for this {response.content_type} response.'
                    if header_name == 'X-Frame-Options' and has_frame_policy(headers.get('Content-Security-Policy', '')):
                        applicable = False
                        note = 'CSP frame-ancestors controls framing instead.'
                    valid, reason = check_header_value(header_name, value or '') if present else (False, '')
                    severity = Severity.INFO if not applicable else Severity.PASS if present and valid else meta['severity']
                    result.security_headers[header_name] = HeaderCheckResult(
                        present=present, value=value, valid=valid if applicable else None,
                        applicable=applicable, note=note or reason, severity=severity,
                    )
                    if applicable and (not present or not valid):
                        findings.append(Finding(
                            title=f'Missing {header_name}' if not present else f'{header_name} needs review',
                            severity=severity, description=reason if present else meta['description'],
                            recommendation=meta['recommendation'],
                        ))

                # Server fingerprint
                server = headers.get("Server", "Not Disclosed")
                result.server_fingerprint = server
                if server and server != "Not Disclosed":
                    findings.append(Finding(
                        title="Server Header Disclosed",
                        severity=Severity.INFO,
                        description=f"Server identifies as: {server}",
                        recommendation="Consider removing or obfuscating the Server header."
                    ))

                # X-Powered-By disclosure
                powered_by = headers.get("X-Powered-By")
                if powered_by:
                    findings.append(Finding(
                        title="X-Powered-By Header Disclosed",
                        severity=Severity.LOW,
                        description=f"Technology disclosed: {powered_by}",
                        recommendation="Remove the X-Powered-By header to reduce fingerprinting surface."
                    ))

    except Exception as e:
        result.status = "partial"
        result.error = "Security headers could not be retrieved"
        findings.append(Finding(
            title="Header Check Failed",
            severity=Severity.INFO,
            description=f"Could not retrieve headers: {str(e)}",
            recommendation="Ensure the target is reachable."
        ))

    if not include_files:
        result.findings = findings
        return result

    # 2. Check Sensitive Files
    async def check_path(session, path, fallbacks):
        try:
            async with session.get(urljoin(target_url, path), allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3)) as response:
                if response.status in (401, 403, 404, 410):
                    return path, False
                if response.status != 200:
                    return path, None
                body, complete = await read_limited(response)
                return path, classify_file(path, body, response.content_type, fallbacks, complete)
        except Exception:
            return path, None

    try:
        async with scanner_session(timeout=aiohttp.ClientTimeout(total=15)) as session:
            fallbacks = []
            for _ in range(2):
                missing_path = f'/.localghost-missing-{uuid.uuid4().hex}'
                try:
                    async with session.get(urljoin(target_url, missing_path), allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3)) as response:
                        if response.status == 200:
                            body, complete = await read_limited(response)
                            if complete:
                                fallbacks.append((missing_path, body))
                except (aiohttp.ClientError, TimeoutError):
                    pass
            path_results = await asyncio.gather(*(check_path(session, path, fallbacks) for path in SENSITIVE_PATHS))

            for path, found in path_results:
                result.sensitive_files[path] = found
                if found:
                    severity = Severity.CRITICAL if path in CRITICAL_PATHS else Severity.HIGH

                    # Build context-aware description and recommendation
                    if path.startswith("/.git"):
                        description = (
                            f"The path {path} is accessible (HTTP 200). "
                            f"An attacker could reconstruct your entire source code and commit history from exposed .git files."
                        )
                        recommendation = (
                            f"Block public access to {path}. "
                            f"NOTE: Local dev servers (VS Code Live Server, Python http.server) serve the entire "
                            f"project directory including .git/. Production hosts like GitHub Pages, Vercel, and "
                            f"Netlify do NOT expose .git/ by default — this finding is most relevant for local/self-hosted servers."
                        )
                    elif path.startswith("/.env"):
                        description = (
                            f"The path {path} is accessible (HTTP 200). "
                            f"Environment files often contain API keys, database passwords, and other secrets."
                        )
                        recommendation = "Never serve .env files publicly. Block access via server configuration."
                    else:
                        description = f"The path {path} is accessible (HTTP 200). This file may expose configuration details or sensitive data."
                        recommendation = f"Block public access to {path} via server configuration or .htaccess rules."

                    findings.append(Finding(
                        title=f"Sensitive File Exposed: {path}",
                        severity=severity,
                        description=description,
                        recommendation=recommendation,
                    ))
            if any(found is None for _, found in path_results):
                result.status = "partial"
                result.error = "Some sensitive file paths could not be checked"
    except Exception as e:
        result.status = "partial"
        result.error = "Sensitive file checks could not be completed"
        findings.append(Finding(
            title="Sensitive File Check Failed",
            severity=Severity.INFO,
            description=f"Could not probe paths: {str(e)}",
            recommendation="Ensure the target is reachable."
        ))

    if not result.security_headers and not any(value is not None for value in result.sensitive_files.values()):
        result.status = "error"
    result.findings = findings
    return result
