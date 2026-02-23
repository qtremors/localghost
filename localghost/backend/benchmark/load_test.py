import time
import asyncio
import aiohttp
from typing import Dict, Any

async def send_request(session: aiohttp.ClientSession, url: str) -> bool:
    """Send a single request and return True if successful."""
    try:
        async with session.get(url, timeout=2) as response:
            return response.status < 400
    except Exception:
        return False

async def run_load_test(target_url: str, concurrency: int = 50, duration_seconds: int = 5) -> Dict[str, Any]:
    """
    Run a simple, pure Python load test against the target.
    
    Args:
        target_url: The URL to test.
        concurrency: Number of concurrent tasks sending requests.
        duration_seconds: How long to run the load test.
    """
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    stats = {
        "requests_attempted": 0,
        "requests_successful": 0,
        "start_time": time.time(),
        "end_time": 0,
        "duration": duration_seconds,
        "req_per_sec": 0
    }

    async def worker(session: aiohttp.ClientSession, end_time: float):
        """Worker task that continuously sends requests until end_time is reached."""
        while time.time() < end_time:
            stats["requests_attempted"] += 1
            success = await send_request(session, target_url)
            if success:
                stats["requests_successful"] += 1

    timeout_end = time.time() + duration_seconds
    
    connector = aiohttp.TCPConnector(limit=concurrency)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [worker(session, timeout_end) for _ in range(concurrency)]
        await asyncio.gather(*tasks)

    stats["end_time"] = time.time()
    actual_duration = stats["end_time"] - stats["start_time"]
    
    if actual_duration > 0:
        stats["req_per_sec"] = round(stats["requests_successful"] / actual_duration, 2)
        
    # Clean up floats for JSON serialization
    stats["start_time"] = round(stats["start_time"], 2)
    stats["end_time"] = round(stats["end_time"], 2)
    stats["duration"] = round(actual_duration, 2)
    
    return stats
