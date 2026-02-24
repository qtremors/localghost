"""Security headers and sensitive file vulnerability scanner."""

import aiohttp
import asyncio
from typing import Dict, Any
from backend.models.scan import VulnScanResult, HeaderCheckResult, Finding, Severity


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
    "X-XSS-Protection": {
        "severity": Severity.LOW,
        "description": "Legacy XSS filter (mostly replaced by CSP but still useful).",
        "recommendation": "Add 'X-XSS-Protection: 1; mode=block' header."
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


async def check_vulnerabilities(target_url: str) -> VulnScanResult:
    """Check target URL for security misconfigurations."""

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    result = VulnScanResult()
    findings = []

    # 1. Check Security Headers
    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(target_url) as response:
                headers = response.headers

                for header_name, meta in SECURITY_HEADERS.items():
                    present = header_name in headers
                    value = headers.get(header_name) if present else None

                    result.security_headers[header_name] = HeaderCheckResult(
                        present=present,
                        value=value,
                        severity=Severity.PASS if present else meta["severity"]
                    )

                    if not present:
                        findings.append(Finding(
                            title=f"Missing {header_name}",
                            severity=meta["severity"],
                            description=meta["description"],
                            recommendation=meta["recommendation"]
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
        findings.append(Finding(
            title="Header Check Failed",
            severity=Severity.INFO,
            description=f"Could not retrieve headers: {str(e)}",
            recommendation="Ensure the target is reachable."
        ))

    # 2. Check Sensitive Files
    async def check_path(session: aiohttp.ClientSession, base_url: str, path: str):
        full_url = f"{base_url.rstrip('/')}{path}"
        try:
            async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                found = resp.status == 200
                return path, found
        except Exception:
            return path, False

    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            tasks = [check_path(session, target_url, path) for path in SENSITIVE_PATHS]
            path_results = await asyncio.gather(*tasks)

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
                        recommendation = f"Never serve .env files publicly. Block access via server configuration."
                    else:
                        description = f"The path {path} is accessible (HTTP 200). This file may expose configuration details or sensitive data."
                        recommendation = f"Block public access to {path} via server configuration or .htaccess rules."

                    findings.append(Finding(
                        title=f"Sensitive File Exposed: {path}",
                        severity=severity,
                        description=description,
                        recommendation=recommendation,
                    ))
    except Exception as e:
        findings.append(Finding(
            title="Sensitive File Check Failed",
            severity=Severity.INFO,
            description=f"Could not probe paths: {str(e)}",
            recommendation="Ensure the target is reachable."
        ))

    result.findings = findings
    return result
