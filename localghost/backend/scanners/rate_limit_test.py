"""API rate limit detection scanner — checks if the target enforces rate limiting."""

import time
import asyncio
import aiohttp
from typing import List, Dict, Any
from backend.models.scan import Finding, Severity


class RateLimitResult:
    """Results from rate limit detection."""
    def __init__(self):
        self.has_rate_limiting = False
        self.rate_limit_headers = {}
        self.trigger_threshold = 0    # Request count that triggered 429
        self.burst_test = {}
        self.sustained_test = {}
        self.endpoint_tests = []
        self.findings: List[Finding] = []

    def to_dict(self):
        return {
            "has_rate_limiting": self.has_rate_limiting,
            "rate_limit_headers": self.rate_limit_headers,
            "trigger_threshold": self.trigger_threshold,
            "burst_test": self.burst_test,
            "sustained_test": self.sustained_test,
            "endpoint_tests": self.endpoint_tests,
            "findings": [f.model_dump() for f in self.findings],
        }


# Common rate limit response headers
RATE_LIMIT_HEADERS = [
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "X-Rate-Limit-Limit",
    "X-Rate-Limit-Remaining",
    "X-Rate-Limit-Reset",
    "RateLimit-Limit",
    "RateLimit-Remaining",
    "RateLimit-Reset",
    "RateLimit-Policy",
    "Retry-After",
]


async def test_rate_limits(target_url: str) -> dict:
    """
    Detect and test rate limiting on the target.
    
    Tests:
    1. Header detection — check for rate limit headers in normal responses
    2. Burst test — rapid burst of 50 requests to trigger limits
    3. Sustained test — steady stream over 10 seconds
    4. Multi-endpoint — test different paths for per-route limits
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    result = RateLimitResult()
    findings = []

    # Test 1: Check for rate limit headers in a normal response
    header_result = await _check_rate_limit_headers(target_url)
    result.rate_limit_headers = header_result["headers"]
    
    if header_result["headers"]:
        result.has_rate_limiting = True
        header_list = ", ".join(f"{k}: {v}" for k, v in header_result["headers"].items())
        findings.append(Finding(
            title="Rate Limit Headers Detected",
            severity=Severity.PASS,
            description=f"Server responds with rate limiting headers: {header_list}",
        ))
    else:
        findings.append(Finding(
            title="No Rate Limit Headers in Normal Response",
            severity=Severity.INFO,
            description="No standard rate limiting headers found in the initial response.",
            recommendation="Consider adding X-RateLimit-* headers to inform clients of limits."
        ))

    # Test 2: Burst test — send 50 requests as fast as possible
    burst_result = await _burst_test(target_url, num_requests=50)
    result.burst_test = burst_result

    if burst_result["rate_limited_count"] > 0:
        result.has_rate_limiting = True
        result.trigger_threshold = burst_result["first_429_at"]
        findings.append(Finding(
            title="Burst Rate Limiting Active",
            severity=Severity.PASS,
            description=f"Rate limiting triggered after {burst_result['first_429_at']} requests. {burst_result['rate_limited_count']} of {burst_result['total_requests']} were rejected (HTTP 429).",
        ))
    else:
        findings.append(Finding(
            title="No Burst Rate Limiting Detected",
            severity=Severity.MEDIUM,
            description=f"All {burst_result['total_requests']} rapid burst requests were accepted (no HTTP 429 responses).",
            recommendation="Implement rate limiting to prevent burst abuse. Common limits: 100 req/min per IP."
        ))

    # Test 3: Sustained test — steady requests over 10 seconds
    sustained_result = await _sustained_test(target_url, duration_sec=8, rps=10)
    result.sustained_test = sustained_result

    if sustained_result["rate_limited_count"] > 0:
        result.has_rate_limiting = True
        findings.append(Finding(
            title="Sustained Rate Limiting Active",
            severity=Severity.PASS,
            description=f"Rate limiting triggered during sustained traffic ({sustained_result['rps_target']} req/s for {sustained_result['duration_sec']}s). {sustained_result['rate_limited_count']} requests rejected.",
        ))
    else:
        if not result.has_rate_limiting:
            findings.append(Finding(
                title="No Sustained Rate Limiting Detected",
                severity=Severity.MEDIUM,
                description=f"Server accepted all {sustained_result['total_requests']} requests over {sustained_result['duration_sec']}s at {sustained_result['rps_target']} req/s.",
                recommendation="Add sliding window or token bucket rate limiting for sustained traffic protection."
            ))

    # Test 4: Endpoint-specific limits
    endpoint_result = await _test_endpoint_limits(target_url)
    result.endpoint_tests = endpoint_result

    per_route_limiting = any(e["rate_limited"] for e in endpoint_result)
    if per_route_limiting:
        limited_paths = [e["path"] for e in endpoint_result if e["rate_limited"]]
        findings.append(Finding(
            title="Per-Endpoint Rate Limiting Detected",
            severity=Severity.PASS,
            description=f"Some endpoints have individual rate limits: {', '.join(limited_paths)}",
        ))

    # Overall assessment
    if not result.has_rate_limiting:
        findings.append(Finding(
            title="No Rate Limiting Detected",
            severity=Severity.HIGH,
            description="The target has no detectable rate limiting across any test. It is vulnerable to abuse, scraping, and brute-force attacks.",
            recommendation="Implement rate limiting at the application level (e.g., slowapi for FastAPI) or at the reverse proxy level (Nginx limit_req, Cloudflare rate rules)."
        ))
    else:
        findings.append(Finding(
            title="Rate Limiting Summary",
            severity=Severity.PASS,
            description=f"Rate limiting is active. Threshold: ~{result.trigger_threshold} requests before rejection." if result.trigger_threshold else "Rate limiting is active via response headers.",
        ))

    result.findings = findings
    return result.to_dict()


async def _check_rate_limit_headers(url: str) -> dict:
    """Check if normal responses contain rate limit headers."""
    found_headers = {}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                for header in RATE_LIMIT_HEADERS:
                    value = resp.headers.get(header)
                    if value:
                        found_headers[header] = value
    except Exception:
        pass
    return {"headers": found_headers}


async def _burst_test(url: str, num_requests: int = 50) -> dict:
    """Send a burst of requests and detect 429 responses."""
    results = {"total_requests": num_requests, "accepted": 0, "rate_limited_count": 0, "errors": 0, "first_429_at": 0}
    request_num = 0

    connector = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        async def single(i):
            nonlocal request_num
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    request_num += 1
                    if resp.status == 429:
                        results["rate_limited_count"] += 1
                        if results["first_429_at"] == 0:
                            results["first_429_at"] = i + 1
                        # Check for Retry-After
                        retry = resp.headers.get("Retry-After")
                        if retry:
                            results["retry_after"] = retry
                    elif resp.status < 500:
                        results["accepted"] += 1
                    else:
                        results["errors"] += 1
            except Exception:
                results["errors"] += 1

        tasks = [single(i) for i in range(num_requests)]
        await asyncio.gather(*tasks)

    return results


async def _sustained_test(url: str, duration_sec: int = 8, rps: int = 10) -> dict:
    """Send requests at a steady rate and detect rate limiting."""
    results = {
        "duration_sec": duration_sec,
        "rps_target": rps,
        "total_requests": 0,
        "accepted": 0,
        "rate_limited_count": 0,
        "errors": 0,
    }

    end_time = time.monotonic() + duration_sec
    interval = 1.0 / rps

    async with aiohttp.ClientSession() as session:
        while time.monotonic() < end_time:
            start = time.monotonic()
            results["total_requests"] += 1
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status == 429:
                        results["rate_limited_count"] += 1
                    elif resp.status < 500:
                        results["accepted"] += 1
                    else:
                        results["errors"] += 1
            except Exception:
                results["errors"] += 1

            # Maintain target RPS
            elapsed = time.monotonic() - start
            sleep_time = max(0, interval - elapsed)
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

    return results


async def _test_endpoint_limits(url: str) -> list:
    """Test rate limiting on different endpoint paths."""
    base = url.rstrip("/")
    paths = ["/", "/health", "/api/scan", "/api/history", "/static/style.css"]
    results = []

    for path in paths:
        test_url = f"{base}{path}"
        rate_limited = False
        accepted = 0
        rejected = 0

        try:
            async with aiohttp.ClientSession() as session:
                for _ in range(20):
                    try:
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=2)) as resp:
                            if resp.status == 429:
                                rejected += 1
                                rate_limited = True
                            else:
                                accepted += 1
                    except Exception:
                        break
        except Exception:
            pass

        results.append({
            "path": path,
            "requests_sent": accepted + rejected,
            "accepted": accepted,
            "rejected": rejected,
            "rate_limited": rate_limited,
        })

    return results
