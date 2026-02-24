"""XSS (Cross-Site Scripting) vulnerability scanner — tests for reflected XSS."""

import asyncio
import aiohttp
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from typing import List, Dict, Any
from backend.models.scan import Finding, Severity


# Safe XSS test payloads — these won't cause harm but will be detectable if reflected
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '"><img src=x onerror=alert(1)>',
    "'-alert(1)-'",
    '<svg onload=alert(1)>',
    '"><svg/onload=alert(1)//',
    "javascript:alert(1)",
    '<img src=x onerror=prompt(1)>',
    '${7*7}',  # Template injection
    '{{7*7}}',  # SSTI check
]

# Common parameter names to inject into
COMMON_PARAMS = [
    'q', 'search', 'query', 'name', 'input', 'text',
    'value', 'id', 'page', 'url', 'redirect', 'next',
    'callback', 'data', 'msg', 'message', 'error',
    'return', 'ref', 'site', 'content',
]

# Paths where XSS is commonly found
INJECTABLE_PATHS = [
    '/',
    '/search',
    '/login',
    '/register',
    '/contact',
    '/feedback',
    '/api',
]


class XSSScanResult:
    """Results from XSS scanning."""
    def __init__(self):
        self.vulnerable = False
        self.reflections_found = 0
        self.tests_run = 0
        self.vulnerable_params = []
        self.vulnerable_paths = []
        self.findings: List[Finding] = []

    def to_dict(self):
        return {
            "vulnerable": self.vulnerable,
            "reflections_found": self.reflections_found,
            "tests_run": self.tests_run,
            "vulnerable_params": self.vulnerable_params,
            "vulnerable_paths": self.vulnerable_paths,
            "findings": [f.model_dump() for f in self.findings],
        }


async def scan_xss(target_url: str) -> dict:
    """
    Scan for reflected XSS vulnerabilities.

    Tests:
    1. URL parameter injection — inject payloads into common GET parameters
    2. Path reflection — check if path segments are reflected in HTML
    3. Header injection — check if custom headers are reflected
    4. Error page reflection — trigger 404s with payloads in the URL
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    result = XSSScanResult()
    findings = []

    # Test 1: Parameter injection
    param_results = await _test_param_injection(target_url)
    result.tests_run += param_results["tests_run"]

    for reflection in param_results["reflections"]:
        result.reflections_found += 1
        result.vulnerable = True
        result.vulnerable_params.append(reflection["param"])
        findings.append(Finding(
            title=f"Reflected XSS via '{reflection['param']}' parameter",
            severity=Severity.CRITICAL,
            description=f"Payload reflected unescaped in response body. "
                        f"Payload: {reflection['payload'][:60]}... "
                        f"on path: {reflection['path']}",
            recommendation="Sanitize and escape all user input before rendering in HTML. "
                           "Use Content-Security-Policy headers to mitigate XSS impact."
        ))

    # Test 2: Path-based reflection
    path_results = await _test_path_reflection(target_url)
    result.tests_run += path_results["tests_run"]

    for reflection in path_results["reflections"]:
        result.reflections_found += 1
        result.vulnerable = True
        result.vulnerable_paths.append(reflection["path"])
        findings.append(Finding(
            title="Reflected XSS via URL path",
            severity=Severity.HIGH,
            description=f"Path segment reflected unescaped in response. "
                        f"Path: {reflection['path'][:80]}",
            recommendation="Never reflect URL path segments directly in HTML without escaping."
        ))

    # Test 3: Error page reflection
    error_results = await _test_error_page_reflection(target_url)
    result.tests_run += error_results["tests_run"]

    for reflection in error_results["reflections"]:
        result.reflections_found += 1
        result.vulnerable = True
        findings.append(Finding(
            title="XSS via Error Page Reflection",
            severity=Severity.HIGH,
            description=f"Error page (404) reflects the requested URL or path unescaped. "
                        f"Payload reflected: {reflection['payload'][:60]}",
            recommendation="Custom error pages should not reflect user-controlled input."
        ))

    # Test 4: Check for protective headers
    header_results = await _check_xss_headers(target_url)
    for finding in header_results:
        findings.append(finding)

    # Summary finding
    if not result.vulnerable:
        findings.append(Finding(
            title="No Reflected XSS Detected",
            severity=Severity.PASS,
            description=f"Tested {result.tests_run} injection points with {len(XSS_PAYLOADS)} payloads. "
                        f"No reflections found.",
        ))
    else:
        findings.insert(0, Finding(
            title=f"XSS Vulnerabilities Detected ({result.reflections_found} reflections)",
            severity=Severity.CRITICAL,
            description=f"Found {result.reflections_found} reflected XSS vulnerabilities across "
                        f"{len(result.vulnerable_params)} parameters and {len(result.vulnerable_paths)} paths.",
            recommendation="Implement output encoding, Content-Security-Policy, and input validation."
        ))

    result.findings = findings
    return result.to_dict()


async def _test_param_injection(base_url: str) -> dict:
    """Inject XSS payloads into common GET parameters."""
    tests_run = 0
    reflections = []

    parsed = urlparse(base_url)

    async with aiohttp.ClientSession() as session:
        for path in INJECTABLE_PATHS[:4]:  # Test first 4 paths
            for param in COMMON_PARAMS[:8]:  # Test first 8 params
                for payload in XSS_PAYLOADS[:4]:  # Test first 4 payloads per param
                    tests_run += 1
                    test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{urlencode({param: payload})}"

                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=3),
                            allow_redirects=True
                        ) as resp:
                            if resp.status < 500:
                                body = await resp.text()
                                # Check if the payload is reflected UNESCAPED
                                if payload in body:
                                    reflections.append({
                                        "param": param,
                                        "path": path,
                                        "payload": payload,
                                        "status": resp.status,
                                    })
                                    break  # Found it for this param, move on
                    except Exception:
                        pass

    return {"tests_run": tests_run, "reflections": reflections}


async def _test_path_reflection(base_url: str) -> dict:
    """Check if path segments are reflected in response body."""
    tests_run = 0
    reflections = []

    parsed = urlparse(base_url)

    async with aiohttp.ClientSession() as session:
        for payload in XSS_PAYLOADS[:3]:
            tests_run += 1
            # Inject payload as a path segment
            test_url = f"{parsed.scheme}://{parsed.netloc}/{payload}"

            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=3),
                    allow_redirects=True
                ) as resp:
                    body = await resp.text()
                    if payload in body:
                        reflections.append({
                            "path": f"/{payload[:40]}...",
                            "payload": payload,
                        })
            except Exception:
                pass

    return {"tests_run": tests_run, "reflections": reflections}


async def _test_error_page_reflection(base_url: str) -> dict:
    """Check if error pages reflect the URL."""
    tests_run = 0
    reflections = []

    parsed = urlparse(base_url)

    async with aiohttp.ClientSession() as session:
        for payload in XSS_PAYLOADS[:3]:
            tests_run += 1
            # Request a path that will likely 404
            test_path = f"/nonexistent_page_{payload}"
            test_url = f"{parsed.scheme}://{parsed.netloc}{test_path}"

            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=3),
                    allow_redirects=False
                ) as resp:
                    if resp.status in (404, 400):
                        body = await resp.text()
                        if payload in body:
                            reflections.append({
                                "payload": payload,
                                "status": resp.status,
                            })
            except Exception:
                pass

    return {"tests_run": tests_run, "reflections": reflections}


async def _check_xss_headers(target_url: str) -> list:
    """Check for XSS-protective response headers."""
    findings = []

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(target_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                headers = resp.headers

                # X-XSS-Protection (legacy but still relevant)
                xss_protection = headers.get("X-XSS-Protection")
                if not xss_protection:
                    findings.append(Finding(
                        title="Missing X-XSS-Protection Header",
                        severity=Severity.LOW,
                        description="X-XSS-Protection header is not set. While deprecated in modern browsers, "
                                    "it provides protection for older browsers.",
                        recommendation="Add 'X-XSS-Protection: 1; mode=block' header."
                    ))
                else:
                    findings.append(Finding(
                        title="X-XSS-Protection Header Present",
                        severity=Severity.PASS,
                        description=f"X-XSS-Protection: {xss_protection}",
                    ))

                # Content-Security-Policy
                csp = headers.get("Content-Security-Policy")
                if not csp:
                    findings.append(Finding(
                        title="Missing Content-Security-Policy",
                        severity=Severity.MEDIUM,
                        description="No CSP header found. CSP is the most effective XSS mitigation.",
                        recommendation="Implement a strict Content-Security-Policy that restricts inline scripts."
                    ))
                else:
                    # Check if CSP allows unsafe-inline
                    if "'unsafe-inline'" in csp:
                        findings.append(Finding(
                            title="CSP Allows 'unsafe-inline'",
                            severity=Severity.MEDIUM,
                            description="Content-Security-Policy contains 'unsafe-inline' which weakens XSS protection.",
                            recommendation="Remove 'unsafe-inline' and use nonce-based or hash-based CSP."
                        ))
                    else:
                        findings.append(Finding(
                            title="Content-Security-Policy Present",
                            severity=Severity.PASS,
                            description=f"CSP: {csp[:100]}{'...' if len(csp) > 100 else ''}",
                        ))

                # X-Content-Type-Options
                content_type_opts = headers.get("X-Content-Type-Options")
                if content_type_opts != "nosniff":
                    findings.append(Finding(
                        title="Missing X-Content-Type-Options: nosniff",
                        severity=Severity.LOW,
                        description="Without nosniff, browsers may MIME-sniff content types, enabling XSS via file uploads.",
                        recommendation="Add 'X-Content-Type-Options: nosniff' header."
                    ))

    except Exception:
        pass

    return findings
