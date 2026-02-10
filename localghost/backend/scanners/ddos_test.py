"""DDoS resilience testing scanner — tests how the target handles connection flooding."""

import asyncio
import time
from typing import List

import aiohttp

from backend.models.scan import Finding, Severity
from backend.utils.network import open_target_connection, scanner_connector, scanner_session
from backend.utils.probes import ProbeCoverage


class DDoSTestResult:
    """Results from DDoS resilience testing."""
    def __init__(self):
        self.connection_flood = {}
        self.slowloris = {}
        self.rapid_fire = {}
        self.findings: List[Finding] = []
        self.resilience_score = None
        self.status = 'success'
        self.error = None
        self.coverage = ProbeCoverage()
        self.availability_before = {}
        self.availability_after = {}

    def to_dict(self):
        return {
            "status": self.status, "error": self.error,
            "probe_coverage": self.coverage.to_dict(),
            "availability_before": self.availability_before,
            "availability_after": self.availability_after,
            "connection_flood": self.connection_flood,
            "slowloris": self.slowloris,
            "rapid_fire": self.rapid_fire,
            "findings": [f.model_dump() for f in self.findings],
            "resilience_score": self.resilience_score,
        }


async def test_ddos_resilience(target_url: str) -> dict:
    """
    Test the target's resilience to various DDoS-like attack patterns.

    This is a LOCAL-ONLY tool — these tests simulate attack patterns
    at a safe scale to measure how well the server handles them.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    result = DDoSTestResult()
    findings = []

    baseline = await _test_availability(target_url)
    result.availability_before = baseline
    result.coverage.record(baseline['testable'])
    if not baseline['testable']:
        result.status = 'error'
        result.error = 'The target did not return a successful baseline response; resilience was not assessed'
        result.findings = [Finding(title='Resilience Assessment Unavailable', severity=Severity.INFO,
            description='The target could not be assessed before the test. This is not evidence of either resilience or a crash.',
            recommendation='Use a reachable target URL that returns a successful response, then retry.')]
        return result.to_dict()

    # Test 1: Connection Flood — open many concurrent connections rapidly
    flood_result = await _test_connection_flood(target_url)
    result.connection_flood = flood_result
    result.coverage.merge(flood_result['total_connections'], flood_result['successful'])

    if not flood_result['successful']:
        findings.append(Finding(title='Concurrent Request Test Incomplete', severity=Severity.INFO,
            description='No concurrent requests completed. Connection errors do not identify their cause.'))
    elif flood_result["success_rate"] < 50:
        findings.append(Finding(
            title="Concurrent Request Failures Observed",
            severity=Severity.HIGH,
            description=f"Only {flood_result['success_rate']}% of {flood_result['total_connections']} concurrent connections succeeded. Server may exhaust file descriptors or connection pools.",
            recommendation="Configure connection limits, implement connection queuing, or add a reverse proxy with connection rate limiting."
        ))
    elif flood_result["success_rate"] < 80:
        findings.append(Finding(
            title="Partially Resilient to Connection Flood",
            severity=Severity.MEDIUM,
            description=f"{flood_result['success_rate']}% of connections succeeded under flood. Some degradation detected.",
            recommendation="Consider increasing connection pool limits or adding load balancing."
        ))
    else:
        findings.append(Finding(
            title="Resilient to Connection Flood",
            severity=Severity.PASS,
            description=f"{flood_result['success_rate']}% of connections succeeded under concurrent flood test.",
        ))

    # Test 2: Slowloris — hold connections open with slow headers
    slowloris_result = await _test_slowloris(target_url)
    result.slowloris = slowloris_result
    result.coverage.merge(slowloris_result['attempted'], slowloris_result['attempted'] - slowloris_result['errors'])
    retained = slowloris_result['still_alive_after_hold']

    if retained > 15:
        findings.append(Finding(
            title="Slow Connections Remained Open",
            severity=Severity.HIGH,
            description=f"{retained} partial-request connections remained open after {slowloris_result['hold_duration_sec']} seconds in this bounded test.",
            recommendation="Set aggressive request timeouts, limit concurrent connections per IP, or use a reverse proxy like Nginx with timeout protection."
        ))
    elif retained > 5:
        findings.append(Finding(
            title="Some Slow Connections Remained Open",
            severity=Severity.MEDIUM,
            description=f"{retained} partial-request connections remained open at the end of the hold period.",
            recommendation="Reduce keepalive timeout and limit concurrent connections."
        ))
    elif slowloris_result['errors']:
        findings.append(Finding(title='Slow Connection Check Incomplete', severity=Severity.INFO,
            description='Some connections could not be established. This does not establish timeout protection.'))
    else:
        findings.append(Finding(
            title="Slow Requests Closed Within Test Period",
            severity=Severity.PASS,
            description=f"{retained} of {slowloris_result['connections_held']} established connections remained open after the hold period.",
        ))

    # Test 3: Rapid Fire — burst of sequential requests in tight loop
    rapid_result = await _test_rapid_fire(target_url)
    result.rapid_fire = rapid_result
    result.coverage.merge(rapid_result['total_requests'], rapid_result['accepted'] + rapid_result['rejected_count'])

    if rapid_result["rejected_count"] > 0:
        findings.append(Finding(
            title="Server Applies Rate Limiting Under Burst",
            severity=Severity.PASS,
            description=f"Server rejected {rapid_result['rejected_count']} of {rapid_result['total_requests']} rapid requests. Rate limiting is active.",
        ))
    elif rapid_result['errors']:
        findings.append(Finding(title='Rapid Request Check Incomplete', severity=Severity.INFO,
            description=f"{rapid_result['errors']} requests failed or returned unavailable responses. These do not count as rate-limit rejections."))
    elif rapid_result["avg_response_ms"] > 2000:
        findings.append(Finding(
            title="Server Degrades Under Rapid Fire",
            severity=Severity.MEDIUM,
            description=f"Average response time rose to {rapid_result['avg_response_ms']}ms under rapid burst ({rapid_result['total_requests']} requests).",
            recommendation="Implement rate limiting to prevent resource exhaustion."
        ))
    else:
        findings.append(Finding(
            title="No Rate Limiting Detected Under Burst",
            severity=Severity.LOW,
            description=f"All {rapid_result['total_requests']} rapid requests accepted with {rapid_result['avg_response_ms']}ms avg latency. No rate limiting observed.",
            recommendation="Consider adding rate limiting to prevent abuse."
        ))

    # Test 4: Service availability after attacks
    post_attack = await _test_availability(target_url)
    result.availability_after = post_attack
    result.coverage.record(post_attack['available'])
    if post_attack["available"]:
        findings.append(Finding(
            title="Service Responded After Tests",
            severity=Severity.PASS,
            description=f"The target returned HTTP {post_attack['status_code']} after testing ({post_attack['response_ms']}ms).",
        ))
    else:
        findings.append(Finding(
            title="Service Unavailable After Tests",
            severity=Severity.CRITICAL,
            description="The target was reachable before testing but did not return an available response afterward. The cause cannot be determined from this check alone.",
            recommendation="Improve server stability, add process managers (e.g. supervisor/systemd), or use auto-restart mechanisms."
        ))

    # Compute resilience score
    result.status = result.coverage.status
    if result.status == 'success':
        result.resilience_score = _compute_resilience_score(flood_result, slowloris_result, rapid_result, post_attack)
    else:
        result.error = f'{result.coverage.inconclusive} probes were inconclusive; the resilience score is unavailable'
    result.findings = findings

    return result.to_dict()


async def _test_connection_flood(url: str, num_connections: int = 100) -> dict:
    """Attempt to open many concurrent connections."""
    successes = 0
    failures = 0
    latencies = []

    async def single_request(session):
        nonlocal successes, failures
        start = time.monotonic()
        try:
            async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                elapsed = (time.monotonic() - start) * 1000
                if resp.status < 500:
                    successes += 1
                else:
                    failures += 1
                latencies.append(elapsed)
        except Exception:
            failures += 1
            latencies.append((time.monotonic() - start) * 1000)

    start_time = time.monotonic()
    connector = scanner_connector(limit=100, force_close=True)
    async with scanner_session(connector=connector) as session:
        tasks = [single_request(session) for _ in range(num_connections)]
        await asyncio.gather(*tasks)
    total_time = (time.monotonic() - start_time) * 1000

    return {
        "total_connections": num_connections,
        "successful": successes,
        "failed": failures,
        "success_rate": round((successes / num_connections) * 100, 1) if num_connections > 0 else 0,
        "total_time_ms": round(total_time, 2),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
    }


async def _test_slowloris(url: str, num_connections: int = 20, hold_seconds: int = 5) -> dict:
    """Hold partial requests open, closing every connection on cancellation."""
    from contextlib import suppress
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    tls = parsed.scheme == "https"
    port = parsed.port or (443 if tls else 80)
    connections = []
    still_alive = 0
    attempted, errors = 0, 0
    try:
        for _ in range(num_connections):
            attempted += 1
            try:
                reader, writer = await asyncio.wait_for(
                    open_target_connection(host, port, ssl=True if tls else None), timeout=5,
                )
                connections.append((reader, writer))
                writer.write(f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode())
                await writer.drain()
            except (OSError, TimeoutError):
                errors += 1
                break
        await asyncio.sleep(hold_seconds)
        for reader, writer in connections:
            if not reader.at_eof() and not writer.is_closing():
                try:
                    # A response or EOF means the partial request was handled or
                    # closed. A buffered error response must not count as alive.
                    try:
                        await asyncio.wait_for(reader.read(1), timeout=.01)
                    except TimeoutError:
                        writer.write(b"X-Slow: a\r\n")
                        await writer.drain()
                        still_alive += 1
                except OSError:
                    pass
        return {
            "attempted": attempted, "errors": errors,
            "connections_held": len(connections),
            "still_alive_after_hold": still_alive,
            "hold_duration_sec": hold_seconds,
        }
    finally:
        for _, writer in connections:
            writer.close()
        for _, writer in connections:
            with suppress(OSError, TimeoutError):
                async with asyncio.timeout(1):
                    await writer.wait_closed()


async def _test_rapid_fire(url: str, num_requests: int = 200) -> dict:
    """Send a burst of rapid sequential requests to test rate limiting."""
    accepted = 0
    rejected = 0  # Explicit HTTP 429 responses only.
    errors = 0
    latencies = []

    connector = scanner_connector(limit=10)
    async with scanner_session(connector=connector) as session:
        for _ in range(num_requests):
            start = time.monotonic()
            try:
                async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    elapsed = (time.monotonic() - start) * 1000
                    latencies.append(elapsed)
                    if resp.status == 429:
                        rejected += 1
                    elif 200 <= resp.status < 300:
                        accepted += 1
                    else:
                        errors += 1
            except Exception:
                errors += 1
                latencies.append((time.monotonic() - start) * 1000)

    return {
        "total_requests": num_requests,
        "accepted": accepted,
        "rejected_count": rejected, "errors": errors,
        "avg_response_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
        "min_response_ms": round(min(latencies), 2) if latencies else 0,
        "max_response_ms": round(max(latencies), 2) if latencies else 0,
    }


async def _test_availability(url: str) -> dict:
    """Check if the server is still responding after tests."""
    try:
        async with scanner_session() as session:
            start = time.monotonic()
            async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                elapsed = (time.monotonic() - start) * 1000
                return {
                    "available": 200 <= resp.status < 500 and not 300 <= resp.status < 400,
                    "testable": 200 <= resp.status < 300,
                    "status_code": resp.status,
                    "response_ms": round(elapsed, 2),
                }
    except Exception:
        return {"available": False, "testable": False, "status_code": 0, "response_ms": 0}


def _compute_resilience_score(flood, slowloris, rapid, post_attack) -> int:
    """Compute a 0-100 resilience score."""
    score = 0

    # Flood resilience (40 pts)
    score += min(40, int(flood["success_rate"] * 0.4))

    # Slowloris resilience (25 pts)
    held = slowloris["still_alive_after_hold"]
    if held <= 3:
        score += 25
    elif held <= 10:
        score += 15
    elif held <= 15:
        score += 8
    else:
        score += 0

    # Rate limiting / rapid fire (20 pts)
    if rapid["rejected_count"] > 0:
        score += 20  # Has rate limiting
    elif rapid["avg_response_ms"] < 500:
        score += 10  # No rate limiting but handles it well
    else:
        score += 5   # No rate limiting and degraded

    # Post-attack availability (15 pts)
    if post_attack["available"]:
        score += 15

    return min(100, score)
