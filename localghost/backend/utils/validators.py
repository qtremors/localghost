"""Validation for HTTP targets on loopback and private networks."""

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlsplit, urlunsplit

PRIVATE_RANGES = tuple(map(ipaddress.ip_network, (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "::1/128", "fc00::/7",
)))


def is_private_address(host: str) -> bool:
    try:
        address = ipaddress.ip_address(host)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return any(address in network for network in PRIVATE_RANGES)
    except ValueError:
        return False


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("Enter a target URL")
    if "://" not in url and not re.match(r"^[a-z][a-z\d+.-]*:(?!\d)", url, re.I):
        url = f"http://{url}"
    return url


def extract_host(url: str) -> str:
    return urlsplit(url).hostname or ""


def extract_port(url: str) -> int | None:
    return urlsplit(url).port


def is_local_target(url: str) -> bool:
    host = extract_host(normalize_url(url))
    return host.lower() == "localhost" or is_private_address(host)


def validate_target_url(url: str) -> str:
    url = normalize_url(url)
    if len(url) > 2048:
        raise ValueError("URL must be at most 2048 characters")
    if re.search(r"[\s\x00-\x1f\x7f\\]", url):
        raise ValueError("URL must not contain spaces, control characters, or backslashes")
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid hostname and port (1–65535)") from exc
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS targets are supported")
    if not host:
        raise ValueError("Enter a valid target hostname")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Target URLs must not contain credentials")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not re.fullmatch(r"[a-z\d](?:[a-z\d.-]*[a-z\d])?\.?", host, re.I):
            raise ValueError("Enter a valid target hostname")
    else:
        if not is_private_address(host):
            raise ValueError("Targets must use a loopback or private network address")
    return urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, ""))


async def validate_target_address(url: str) -> tuple[str, ...]:
    """Resolve hostnames before launching modules; reject public/mixed DNS answers."""
    host = extract_host(url)
    if is_private_address(host):
        return (host,)
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, extract_port(url) or (443 if urlsplit(url).scheme == "https" else 80), type=socket.SOCK_STREAM),
            timeout=5,
        )
    except (OSError, TimeoutError) as exc:
        raise ValueError(f"Could not resolve {host}; check the target hostname") from exc
    if not infos or not all(is_private_address(info[4][0]) for info in infos):
        raise ValueError("Target hostname must resolve only to loopback or private network addresses")
    return tuple(dict.fromkeys(info[4][0] for info in infos))
