"""Find HTTP development servers on this machine without running an audit."""

import asyncio
import re
from datetime import UTC, datetime
from html import unescape

import aiohttp
from fastapi import APIRouter, HTTPException, Query, Request

from backend.database.db import get_project_history
from backend.services.admission import workload_lock
from backend.services.docker import discover_containers
from backend.services.source import inspect_source
from backend.utils.http import read_limited

router = APIRouter(prefix="/api/projects", tags=["projects"])
COMMON_PORTS = (3000, 3001, 3002, 4000, 4173, 4200, 4321, 5000, 5001, 5173,
                5174, 5500, 6006, 7000, 8000, 8001, 8080, 8081, 8888, 9000)
_discovery_lock = workload_lock


@router.post('/docker')
async def docker_projects():
    if workload_lock.locked():
        raise HTTPException(429, 'A scan or app search is running. Try again shortly.')
    async with workload_lock:
        try:
            return await discover_containers()
        except (ValueError, OSError):
            raise HTTPException(422, 'Local Docker discovery could not complete. Start Docker and check local socket access.') from None


@router.post('/inspect')
async def inspect_project(request: dict):
    path = request.get('source_path')
    if not isinstance(path, str) or len(path) > 4096:
        raise HTTPException(422, 'Enter an absolute source-folder path')
    if workload_lock.locked():
        raise HTTPException(429, 'A scan or app search is already running. Try again shortly.')
    async with workload_lock:
        try:
            return await asyncio.to_thread(inspect_source, path)
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc


@router.get('')
async def list_projects(limit: int = Query(default=24, ge=1, le=100), offset: int = Query(default=0, ge=0)):
    return await get_project_history(limit, offset)


async def discover_projects(excluded_port: int | None = None):
    """Make one bounded HTTP request per common port and loopback address."""
    ports = [port for port in COMMON_PORTS if port not in (excluded_port, 13666)]
    semaphore = asyncio.Semaphore(12)
    timeout = aiohttp.ClientTimeout(total=1.2)
    async with aiohttp.ClientSession(timeout=timeout, trust_env=False) as session:
        async def probe(host, port):
            async with semaphore:
                url = f"http://{host}:{port}"
                try:
                    async with session.get(url, allow_redirects=False) as response:
                        body = b''
                        try:
                            async with asyncio.timeout(.25):
                                body, _ = await read_limited(response, 32768)
                        except (aiohttp.ClientError, TimeoutError):
                            pass  # A slow body does not undo a confirmed HTTP response.
                        text = body.decode("utf-8", errors="replace")
                        title = re.search(r"<title\b[^>]*>(.*?)</title\s*>", text, re.I | re.S)
                        name = unescape(re.sub(r"<[^>]*>", "", title[1])) if title else ""
                        return {"target": url, "port": port, "name": " ".join(name.split())[:120],
                                "http_status": response.status,
                                "server": response.headers.get("X-Powered-By", response.headers.get("Server", ""))[:100]}
                except (aiohttp.ClientError, TimeoutError, OSError):
                    return None

        results = await asyncio.gather(*(probe(host, port) for port in ports for host in ("127.0.0.1", "[::1]")))
    # Different apps can share a port on separate IPv4/IPv6 listeners. Keep both
    # responding addresses rather than silently dropping one based on port alone.
    return {"projects": [result for result in results if result], "checked_ports": len(ports),
            "checked_at": datetime.now(UTC).isoformat()}


@router.post("/discover")
async def discover(request: Request):
    """Discovery is explicit, loopback-only, and limited to one run at a time."""
    if _discovery_lock.locked():
        raise HTTPException(429, "A scan or app search is already running. Try again shortly.")
    async with _discovery_lock:
        return await discover_projects(request.url.port)
