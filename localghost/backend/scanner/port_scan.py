import asyncio
import socket
from urllib.parse import urlparse
from typing import List, Optional

# Common ports to check if none specified
COMMON_PORTS = [80, 443, 3000, 5000, 5173, 8000, 8080, 8888, 9000]

async def check_port(host: str, port: int, timeout: float = 0.5) -> Optional[int]:
    """Check if a specific port is open on the host."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), 
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        return port
    except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
        return None

async def scan_ports(target_url: str, ports: Optional[List[int]] = None) -> List[int]:
    """Scan ports on the target host."""
    parsed_url = urlparse(target_url)
    
    # Extract host, fallback to localhost if it's not well-formed
    host = parsed_url.hostname or target_url.replace("http://", "").replace("https://", "").split(":")[0]
    if not host or host == "":
        host = "127.0.0.1"

    ports_to_check = ports if ports else COMMON_PORTS
    
    # Run port checks concurrently
    tasks = [check_port(host, port) for port in ports_to_check]
    results = await asyncio.gather(*tasks)
    
    # Filter out None values and return list of open ports
    open_ports = [port for port in results if port is not None]
    return sorted(open_ports)
