"""DDoS resilience testing scanner — tests how the target handles connection flooding."""

import time
import asyncio
import aiohttp
from typing import List
from backend.models.scan import Finding, Severity


class DDoSTestResult:
    """Results from DDoS resilience testing."""
    def __init__(self):
        self.connection_flood = {}
        self.slowloris = {}
        self.rapid_fire = {}
        self.findings: List[Finding] = []
        self.resilience_score = 0  # 0-100, higher = more resilient

    def to_dict(self):
        return {
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

    # Test 1: Connection Flood — open many concurrent connections rapidly
    flood_result = await _test_connection_flood(target_url)
    result.connection_flood = flood_result
    
    if flood_result["success_rate"] < 50:
        findings.append(Finding(
            title="Vulnerable to Connection Flood",
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

    if slowloris_result["connections_held"] > 15:
        findings.append(Finding(
            title="Vulnerable to Slowloris Attack",
            severity=Severity.HIGH,
            description=f"Server allowed {slowloris_result['connections_held']} slow connections to be held open simultaneously for {slowloris_result['hold_duration_sec']}s.",
            recommendation="Set aggressive request timeouts, limit concurrent connections per IP, or use a reverse proxy like Nginx with timeout protection."
        ))
    elif slowloris_result["connections_held"] > 5:
        findings.append(Finding(
            title="Partially Vulnerable to Slowloris",
            severity=Severity.MEDIUM,
            description=f"{slowloris_result['connections_held']} slow connections held open.",
            recommendation="Reduce keepalive timeout and limit concurrent connections."
        ))
    else:
        findings.append(Finding(
            title="Protected Against Slowloris",
            severity=Severity.PASS,
            description=f"Server limited slow connections to {slowloris_result['connections_held']}.",
        ))

    # Test 3: Rapid Fire — burst of sequential requests in tight loop
    rapid_result = await _test_rapid_fire(target_url)
    result.rapid_fire = rapid_result

    if rapid_result["rejected_count"] > 0:
        findings.append(Finding(
            title="Server Applies Rate Limiting Under Burst",
            severity=Severity.PASS,
            description=f"Server rejected {rapid_result['rejected_count']} of {rapid_result['total_requests']} rapid requests. Rate limiting is active.",
        ))
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
    if post_attack["available"]:
        findings.append(Finding(
            title="Service Available After Tests",
            severity=Severity.PASS,
            description=f"Server responded normally after all resilience tests ({post_attack['response_ms']}ms).",
        ))
    else:
        findings.append(Finding(
            title="Service Unavailable After Tests",
            severity=Severity.CRITICAL,
            description="Server did not respond after resilience testing. It may have crashed or become unresponsive.",
            recommendation="Improve server stability, add process managers (e.g. supervisor/systemd), or use auto-restart mechanisms."
        ))

    # Compute resilience score
    score = _compute_resilience_score(flood_result, slowloris_result, rapid_result, post_attack)
    result.resilience_score = score
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
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
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
    connector = aiohttp.TCPConnector(limit=0, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
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
    """Hold connections open by sending headers very slowly."""
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 80

    connections_held = 0
    sockets = []
    
    loop = asyncio.get_event_loop()

    def _create_slow_connections():
        nonlocal connections_held
        for _ in range(num_connections):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((host, port))
                # Send partial HTTP request (just the first line)
                s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode())
                sockets.append(s)
                connections_held += 1
            except Exception:
                break

    await loop.run_in_executor(None, _create_slow_connections)

    # Hold them open
    await asyncio.sleep(hold_seconds)

    # Check how many are still alive
    still_alive = 0

    def _check_alive():
        nonlocal still_alive
        for s in sockets:
            try:
                # Send another partial header to keep alive
                s.send(b"X-Slow: a\r\n")
                still_alive += 1
            except Exception:
                pass

    await loop.run_in_executor(None, _check_alive)

    # Cleanup
    def _cleanup():
        for s in sockets:
            try:
                s.close()
            except Exception:
                pass

    await loop.run_in_executor(None, _cleanup)

    return {
        "attempted": num_connections,
        "connections_held": connections_held,
        "still_alive_after_hold": still_alive,
        "hold_duration_sec": hold_seconds,
    }


async def _test_rapid_fire(url: str, num_requests: int = 200) -> dict:
    """Send a burst of rapid sequential requests to test rate limiting."""
    accepted = 0
    rejected = 0  # 429 or connection refused
    latencies = []

    connector = aiohttp.TCPConnector(limit=10)
    async with aiohttp.ClientSession(connector=connector) as session:
        for _ in range(num_requests):
            start = time.monotonic()
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    elapsed = (time.monotonic() - start) * 1000
                    latencies.append(elapsed)
                    if resp.status == 429:
                        rejected += 1
                    else:
                        accepted += 1
            except Exception:
                rejected += 1
                latencies.append((time.monotonic() - start) * 1000)

    return {
        "total_requests": num_requests,
        "accepted": accepted,
        "rejected_count": rejected,
        "avg_response_ms": round(sum(latencies) / len(latencies), 2) if latencies else 0,
        "min_response_ms": round(min(latencies), 2) if latencies else 0,
        "max_response_ms": round(max(latencies), 2) if latencies else 0,
    }


async def _test_availability(url: str) -> dict:
    """Check if the server is still responding after tests."""
    try:
        async with aiohttp.ClientSession() as session:
            start = time.monotonic()
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                elapsed = (time.monotonic() - start) * 1000
                return {
                    "available": resp.status < 500,
                    "status_code": resp.status,
                    "response_ms": round(elapsed, 2),
                }
    except Exception:
        return {"available": False, "status_code": 0, "response_ms": 0}


def _compute_resilience_score(flood, slowloris, rapid, post_attack) -> int:
    """Compute a 0-100 resilience score."""
    score = 0

    # Flood resilience (40 pts)
    score += min(40, int(flood["success_rate"] * 0.4))

    # Slowloris resilience (25 pts)
    held = slowloris["connections_held"]
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
