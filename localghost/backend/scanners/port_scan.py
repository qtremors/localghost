"""TCP port scanner with service detection."""

import asyncio
import time
from contextlib import suppress
from typing import List, Optional
from urllib.parse import urlparse

from backend.models.scan import PortScanResult
from backend.utils.network import open_target_connection

# Localghost's own port — will be excluded from results
LOCALGHOST_PORT = 13666

# Common ports and their associated services
PORT_SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3000: "Dev Server (Node/Rails)",
    3306: "MySQL",
    3389: "RDP",
    5000: "Dev Server (Flask)",
    5173: "Vite Dev Server",
    5432: "PostgreSQL",
    5500: "Live Server",
    5672: "RabbitMQ",
    6379: "Redis",
    8000: "Dev Server (Uvicorn/Django)",
    8080: "HTTP Proxy / Alt HTTP",
    8443: "HTTPS Alt",
    8888: "Jupyter Notebook",
    9000: "PHP-FPM / SonarQube",
    9090: "Prometheus",
    9200: "Elasticsearch",
    13666: "Localghost (self)",
    27017: "MongoDB",
}

COMMON_PORTS = list(PORT_SERVICE_MAP.keys())


async def check_port(host: str, port: int, timeout: float = 0.5) -> Optional[dict]:
    """Check if a specific port is open on the host."""
    try:
        reader, writer = await asyncio.wait_for(
            open_target_connection(host, port),
            timeout=timeout
        )
        writer.close()
        # A reset during teardown does not undo a confirmed TCP connection.
        with suppress(OSError, TimeoutError):
            async with asyncio.timeout(timeout):
                await writer.wait_closed()
        return {
            "port": port,
            "service": PORT_SERVICE_MAP.get(port, "Unknown"),
            "state": "open"
        }
    except ConnectionRefusedError:
        return None
    except (TimeoutError, OSError):
        return {"port": port, "state": "inconclusive"}


async def scan_ports(target_url: str, ports: Optional[List[int]] = None) -> PortScanResult:
    """Scan ports on the target host and return enriched results."""
    parsed = urlparse(target_url)
    host = parsed.hostname or target_url.replace("http://", "").replace("https://", "").split(":")[0]
    if not host:
        host = "127.0.0.1"

    # Include the URL's port even when it is absent from the common service map.
    ports_to_check = sorted({*(ports if ports is not None else COMMON_PORTS), parsed.port or (443 if parsed.scheme == "https" else 80)})
    if host in ("127.0.0.1", "localhost", "::1"):
        ports_to_check = [port for port in ports_to_check if port != LOCALGHOST_PORT]

    start = time.monotonic()
    semaphore = asyncio.Semaphore(100)

    async def bounded_check(port):
        async with semaphore:
            return await check_port(host, port)

    tasks = [bounded_check(port) for port in ports_to_check]
    results = await asyncio.gather(*tasks)
    elapsed = (time.monotonic() - start) * 1000

    open_ports = [r for r in results if r is not None and r["state"] == "open"]
    inconclusive = [r["port"] for r in results if r is not None and r["state"] == "inconclusive"]
    completed = len(ports_to_check) - len(inconclusive)

    # Filter out localghost's own port when scanning localhost
    if host in ("127.0.0.1", "localhost", "::1"):
        open_ports = [p for p in open_ports if p["port"] != LOCALGHOST_PORT]

    return PortScanResult(
        status="error" if not completed else "partial" if inconclusive else "success",
        error="No eligible port checks completed" if not completed else f"{len(inconclusive)} ports were unreachable or timed out" if inconclusive else None,
        open_ports=open_ports,
        total_scanned=len(ports_to_check),
        ports_checked=ports_to_check,
        closed_count=sum(result is None for result in results),
        inconclusive_ports=inconclusive,
        scan_time_ms=round(elapsed, 2)
    )

