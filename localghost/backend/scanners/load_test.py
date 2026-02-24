"""HTTP load testing with detailed latency metrics."""

import time
import asyncio
import aiohttp
from typing import Dict, Any, List
from backend.models.scan import BenchmarkResult


async def send_request(session: aiohttp.ClientSession, url: str) -> tuple[bool, float]:
    """Send a single request. Returns (success, latency_ms)."""
    start = time.monotonic()
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as response:
            elapsed = (time.monotonic() - start) * 1000
            return response.status < 400, elapsed
    except Exception:
        elapsed = (time.monotonic() - start) * 1000
        return False, elapsed


async def run_load_test(target_url: str, concurrency: int = 50, duration_seconds: int = 5) -> BenchmarkResult:
    """
    Run a load test against the target with detailed latency metrics.

    Args:
        target_url: The URL to test.
        concurrency: Number of concurrent tasks sending requests.
        duration_seconds: How long to run the load test.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    latencies: List[float] = []
    successful = 0
    attempted = 0
    failed = 0
    lock = asyncio.Lock()

    async def worker(session: aiohttp.ClientSession, end_time: float):
        nonlocal successful, attempted, failed
        while time.monotonic() < end_time:
            success, latency = await send_request(session, target_url)
            async with lock:
                attempted += 1
                latencies.append(latency)
                if success:
                    successful += 1
                else:
                    failed += 1

    start_time = time.monotonic()
    timeout_end = start_time + duration_seconds

    connector = aiohttp.TCPConnector(limit=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [worker(session, timeout_end) for _ in range(concurrency)]
        await asyncio.gather(*tasks)

    actual_duration = time.monotonic() - start_time

    # Calculate percentiles
    sorted_latencies = sorted(latencies) if latencies else [0]

    def percentile(data: List[float], p: float) -> float:
        idx = int(len(data) * p / 100)
        return data[min(idx, len(data) - 1)]

    result = BenchmarkResult(
        requests_attempted=attempted,
        requests_successful=successful,
        requests_failed=failed,
        duration=round(actual_duration, 2),
        req_per_sec=round(successful / actual_duration, 2) if actual_duration > 0 else 0,
        avg_latency_ms=round(sum(sorted_latencies) / len(sorted_latencies), 2),
        min_latency_ms=round(sorted_latencies[0], 2),
        max_latency_ms=round(sorted_latencies[-1], 2),
        p50_latency_ms=round(percentile(sorted_latencies, 50), 2),
        p95_latency_ms=round(percentile(sorted_latencies, 95), 2),
        p99_latency_ms=round(percentile(sorted_latencies, 99), 2),
        error_rate=round((failed / attempted * 100), 2) if attempted > 0 else 0
    )

    return result
