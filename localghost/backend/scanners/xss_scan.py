"""XSS (Cross-Site Scripting) vulnerability scanner — tests for reflected XSS."""

from typing import List
from urllib.parse import parse_qsl, urlencode, urlparse, urlunsplit

import aiohttp

from backend.models.scan import Finding, Severity
from backend.services.header_checks import check_header_value
from backend.services.web_content import evidence_for
from backend.utils.html import has_active_html_reflection
from backend.utils.http import decode_body, read_limited
from backend.utils.network import scanner_session
from backend.utils.probes import ProbeCoverage

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


def _assessable(status):
    return 200 <= status < 500 and not 300 <= status < 400 and status not in (401, 403, 429)


async def _read_body(response):
    body, complete = await read_limited(response, 1024 * 1024)
    return decode_body(body, response.charset), complete


def _reflection(response, body, payload):
    return not 300 <= response.status < 400 and response.content_type in ('text/html', 'application/xhtml+xml') and has_active_html_reflection(body, payload)


class XSSScanResult:
    """Results from XSS scanning."""
    def __init__(self):
        self.vulnerable = False
        self.coverage = ProbeCoverage()
        self.status = 'success'
        self.error = None
        self.reflections_found = 0
        self.tests_run = 0
        self.vulnerable_params = []
        self.vulnerable_paths = []
        self.findings: List[Finding] = []

    def to_dict(self):
        return {
            "status": self.status, "error": self.error,
            "probe_coverage": self.coverage.to_dict(),
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
    parsed = urlparse(target_url)
    findings = []

    # Test 1: Parameter injection
    param_results = await _test_param_injection(target_url)
    result.tests_run += param_results["tests_run"]
    result.coverage.merge(param_results["tests_run"], param_results["completed"])

    for reflection in param_results["reflections"]:
        result.reflections_found += 1
        result.vulnerable = True
        if reflection['param'] not in result.vulnerable_params:
            result.vulnerable_params.append(reflection["param"])
        findings.append(Finding(
            title=f"Potential reflected XSS via '{reflection['param']}' parameter",
            severity=Severity.HIGH,
            description=f"Payload reflected unescaped in response body. "
                        f"Payload: {reflection['payload'][:60]}... "
                        f"on path: {reflection['path']}",
            evidence=reflection.get('evidence', []), location=f'{parsed.scheme}://{parsed.netloc}' + reflection['path'],
            recommendation="Sanitize and escape all user input before rendering in HTML. "
                           "Use Content-Security-Policy headers to mitigate XSS impact."
        ))

    # Test 2: Path-based reflection
    path_results = await _test_path_reflection(target_url)
    result.tests_run += path_results["tests_run"]
    result.coverage.merge(path_results["tests_run"], path_results["completed"])

    for reflection in path_results["reflections"]:
        result.reflections_found += 1
        result.vulnerable = True
        result.vulnerable_paths.append(reflection["path"])
        findings.append(Finding(
            title="Potential reflected XSS via URL path",
            severity=Severity.HIGH,
            description=f"Path segment reflected unescaped in response. "
                        f"Path: {reflection['path'][:80]}",
            evidence=reflection.get('evidence', []),
            recommendation="Never reflect URL path segments directly in HTML without escaping."
        ))

    # Test 3: Error page reflection
    error_results = await _test_error_page_reflection(target_url)
    result.tests_run += error_results["tests_run"]
    result.coverage.merge(error_results["tests_run"], error_results["completed"])

    for reflection in error_results["reflections"]:
        result.reflections_found += 1
        result.vulnerable = True
        findings.append(Finding(
            title="Potential XSS via Error Page Reflection",
            severity=Severity.HIGH,
            description=f"Error page (404) reflects the requested URL or path unescaped. "
                        f"Payload reflected: {reflection['payload'][:60]}",
            evidence=reflection.get('evidence', []),
            recommendation="Custom error pages should not reflect user-controlled input."
        ))

    # Test 4: Check for protective headers
    header_results = await _check_xss_headers(target_url)
    findings.extend(header_results["findings"])
    result.coverage.record(header_results["completed"])
    result.status = result.coverage.status
    if result.status != 'success':
        result.error = f"{result.coverage.inconclusive} probes could not be assessed (connection errors, redirects, blocked responses, or server errors)"

    # Summary finding
    if not result.vulnerable and result.status != 'success':
        result.vulnerable = None
        findings.append(Finding(
            title="XSS Assessment Incomplete", severity=Severity.INFO,
            description=f"{result.coverage.completed} of {result.coverage.attempted} probes completed. Failed or blocked probes do not establish protection.",
            recommendation="Check the target connection and access requirements, then retry the scan.",
        ))
    elif not result.vulnerable:
        findings.append(Finding(
            title="No Reflected XSS Detected",
            severity=Severity.PASS,
            description=f"Completed {result.tests_run} injection probes. "
                        f"No reflections found.",
        ))
    else:
        findings.insert(0, Finding(
            title=f"Potential XSS Detected ({result.reflections_found} reflections)",
            severity=Severity.INFO,
            description=f"Found {result.reflections_found} unescaped HTML reflections across "
                        f"{len(result.vulnerable_params)} parameters and {len(result.vulnerable_paths)} paths.",
            recommendation="Implement output encoding, Content-Security-Policy, and input validation."
        ))

    result.findings = findings
    return result.to_dict()


async def _test_param_injection(base_url: str) -> dict:
    """Inject XSS payloads into common GET parameters."""
    tests_run = 0
    completed = 0
    reflections = []

    parsed = urlparse(base_url)

    async with scanner_session() as session:
        for path in list(dict.fromkeys([parsed.path or '/', *INJECTABLE_PATHS]))[:4]:
            for param in COMMON_PARAMS[:8]:  # Test first 8 params
                for payload in XSS_PAYLOADS[:4]:  # Test first 4 payloads per param
                    tests_run += 1
                    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True) if key != param]
                    test_url = urlunsplit((parsed.scheme, parsed.netloc, path, urlencode([*query, (param, payload)]), ''))

                    try:
                        async with session.get(
                            test_url,
                            timeout=aiohttp.ClientTimeout(total=3),
                            allow_redirects=False
                        ) as resp:
                            body, complete_body = await _read_body(resp)
                            if complete_body and _assessable(resp.status):
                                completed += 1
                            if _reflection(resp, body, payload):
                                reflections.append({"param": param, "path": path, "payload": payload, "status": resp.status,
                                                    "evidence": [evidence_for(resp, body, body.find(payload), body.find(payload) + len(payload), 'Injected HTML appeared unescaped in this response. Browser execution was not tested.').model_dump()]})
                                break  # Keep known reflections even when response inspection was truncated.
                    except Exception:
                        pass

    return {"tests_run": tests_run, "completed": completed, "reflections": reflections}


async def _test_path_reflection(base_url: str) -> dict:
    """Check if path segments are reflected in response body."""
    tests_run = 0
    completed = 0
    reflections = []

    parsed = urlparse(base_url)

    async with scanner_session() as session:
        for payload in XSS_PAYLOADS[:3]:
            tests_run += 1
            # Inject payload as a path segment
            test_url = f"{parsed.scheme}://{parsed.netloc}/{payload}"

            try:
                async with session.get(
                    test_url,
                    timeout=aiohttp.ClientTimeout(total=3),
                    allow_redirects=False
                ) as resp:
                    body, complete_body = await _read_body(resp)
                    if complete_body and _assessable(resp.status):
                        completed += 1
                    if _reflection(resp, body, payload):
                        reflections.append({
                            "path": f"/{payload[:40]}...",
                            "payload": payload,
                            "evidence": [evidence_for(resp, body, body.find(payload), body.find(payload) + len(payload), 'Injected path HTML appeared in the response.').model_dump()],
                        })
            except Exception:
                pass

    return {"tests_run": tests_run, "completed": completed, "reflections": reflections}


async def _test_error_page_reflection(base_url: str) -> dict:
    """Check if error pages reflect the URL."""
    tests_run = 0
    completed = 0
    reflections = []

    parsed = urlparse(base_url)

    async with scanner_session() as session:
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
                    body, complete_body = await _read_body(resp)
                    if complete_body and _assessable(resp.status):
                        completed += 1
                    if resp.status in (404, 400):
                        if _reflection(resp, body, payload):
                            reflections.append({
                                "payload": payload,
                                "status": resp.status,
                                "evidence": [evidence_for(resp, body, body.find(payload), body.find(payload) + len(payload), 'Injected HTML appeared in an error response.').model_dump()],
                            })
            except Exception:
                pass

    return {"tests_run": tests_run, "completed": completed, "reflections": reflections}


async def _check_xss_headers(target_url: str) -> list:
    """Check for XSS-protective response headers."""
    findings = []
    completed = False

    try:
        async with scanner_session() as session:
            async with session.get(target_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if not 200 <= resp.status < 300:
                    return {"findings": [], "completed": False}
                headers = resp.headers
                completed = True

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
                    valid, reason = check_header_value('Content-Security-Policy', csp)
                    if not valid:
                        findings.append(Finding(
                            title="Content-Security-Policy needs review",
                            severity=Severity.MEDIUM,
                            description=reason,
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

    return {"findings": findings, "completed": completed}
