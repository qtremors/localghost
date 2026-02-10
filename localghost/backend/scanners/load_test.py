"""HTTP load testing with detailed latency metrics."""

import asyncio
import math
import random
import time
from typing import List

import aiohttp

from backend.models.scan import BenchmarkResult
from backend.utils.network import scanner_connector, scanner_session

MAX_LATENCY_SAMPLES = 50000


async def send_request(session: aiohttp.ClientSession, url: str, timeout_seconds=5) -> tuple[bool | None, float]:
    """Send a single request. Returns (success, latency_ms)."""
    start = time.monotonic()
    try:
        async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=timeout_seconds)) as response:
            # Measure complete responses and permit connection reuse without
            # retaining potentially large response bodies in memory.
            async for _ in response.content.iter_chunked(65536):
                pass
            elapsed = (time.monotonic() - start) * 1000
            return response.status < 400, elapsed
    except TimeoutError:
        # A request stopped by the test deadline is not a server failure or a
        # completed-response latency sample.
        return (None if timeout_seconds < 5 else False), (time.monotonic() - start) * 1000
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
    incomplete = 0
    latency_sum, latency_min, latency_max = 0.0, float('inf'), 0.0
    sampling = random.Random(0)

    async def worker(session: aiohttp.ClientSession, end_time: float):
        nonlocal successful, attempted, failed, incomplete, latency_sum, latency_min, latency_max
        while time.monotonic() < end_time:
            remaining = end_time - time.monotonic()
            if remaining <= 0:
                break
            success, latency = await send_request(session, target_url, min(5, remaining))
            attempted += 1
            if success is None:
                incomplete += 1
                continue
            measured = successful + failed + 1
            latency_sum += latency
            latency_min = min(latency_min, latency)
            latency_max = max(latency_max, latency)
            if len(latencies) < MAX_LATENCY_SAMPLES:
                latencies.append(latency)
            else:
                replacement = sampling.randrange(measured)
                if replacement < MAX_LATENCY_SAMPLES:
                    latencies[replacement] = latency
            if success:
                successful += 1
            else:
                failed += 1

    start_time = time.monotonic()
    timeout_end = start_time + duration_seconds

    connector = scanner_connector(limit=concurrency)
    async with scanner_session(connector=connector) as session:
        tasks = [worker(session, timeout_end) for _ in range(concurrency)]
        await asyncio.gather(*tasks)

    actual_duration = time.monotonic() - start_time

    # Calculate percentiles
    sorted_latencies = sorted(latencies) if latencies else [0]

    def percentile(data: List[float], p: float) -> float:
        idx = max(0, math.ceil(len(data) * p / 100) - 1)
        return data[min(idx, len(data) - 1)]

    result = BenchmarkResult(
        status='partial' if successful + failed == 0 else 'success',
        error='No requests finished before the test deadline' if successful + failed == 0 else None,
        requests_attempted=attempted,
        requests_successful=successful,
        requests_failed=failed,
        requests_incomplete=incomplete,
        duration=round(actual_duration, 2),
        req_per_sec=round(successful / actual_duration, 2) if actual_duration > 0 else 0,
        avg_latency_ms=round(latency_sum / (successful + failed), 2) if successful + failed else None,
        min_latency_ms=round(latency_min, 2) if latencies else None,
        max_latency_ms=round(latency_max, 2) if latencies else None,
        p50_latency_ms=round(percentile(sorted_latencies, 50), 2) if latencies else None,
        p95_latency_ms=round(percentile(sorted_latencies, 95), 2) if latencies else None,
        p99_latency_ms=round(percentile(sorted_latencies, 99), 2) if latencies else None,
        error_rate=round((failed / (successful + failed) * 100), 2) if successful + failed else None,
        latency_samples=len(latencies), latency_sampled=successful + failed > len(latencies),
    )

    return result
