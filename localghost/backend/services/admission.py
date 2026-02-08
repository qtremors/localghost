"""Keep app discovery and traffic-generating scans from overlapping."""

import asyncio

workload_lock = asyncio.Lock()
