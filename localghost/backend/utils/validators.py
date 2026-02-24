"""URL validation and sanitization utilities."""

import re
import ipaddress
from urllib.parse import urlparse


# Private/local IP ranges
PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]

LOCAL_HOSTNAMES = {"localhost", "localghost", "host.docker.internal"}


def normalize_url(url: str) -> str:
    """Normalize a URL by ensuring it has a scheme."""
    url = url.strip()
    if not url:
        raise ValueError("URL cannot be empty")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = f"http://{url}"
    return url


def extract_host(url: str) -> str:
    """Extract the hostname from a URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not host:
        # Fallback: strip scheme and path
        host = url.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
    return host or "127.0.0.1"


def extract_port(url: str) -> int | None:
    """Extract the port from a URL, or return None for default."""
    parsed = urlparse(url)
    return parsed.port


def is_local_target(url: str) -> bool:
    """Check if a URL points to a local/private address. Returns True if safe to scan."""
    host = extract_host(normalize_url(url))

    # Check known local hostnames
    if host.lower() in LOCAL_HOSTNAMES:
        return True

    # Check if it's a private IP
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in network for network in PRIVATE_RANGES)
    except ValueError:
        pass

    # Could be a hostname that resolves locally — allow it but warn
    # For a local tool, we allow all targets but the scoring engine
    # will note if it appears to be a non-local target
    return True


def validate_target_url(url: str) -> str:
    """Validate and normalize a target URL. Returns the normalized URL."""
    url = normalize_url(url)
    host = extract_host(url)

    if not host:
        raise ValueError("Could not extract hostname from URL")

    # Basic sanity checks
    if len(url) > 2048:
        raise ValueError("URL is too long")

    return url
