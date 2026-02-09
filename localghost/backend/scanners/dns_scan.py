"""DNS record enumeration scanner."""

import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

from backend.models.scan import DNSScanResult, Finding, Severity
from backend.utils.evidence import record_observation
from backend.utils.network import target_addresses


async def scan_dns(target_url: str) -> DNSScanResult:
    """Enumerate DNS records for the target hostname."""

    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")
    host = parsed.hostname or "127.0.0.1"

    result = DNSScanResult()
    findings = []
    loop = asyncio.get_event_loop()

    # Resolve A / AAAA records
    try:
        def _resolve():
            records = {"A": [], "AAAA": []}
            infos = socket.getaddrinfo(host, None)
            for info in infos:
                family, _, _, _, addr = info
                ip = addr[0]
                if family == socket.AF_INET and ip not in records["A"]:
                    records["A"].append(ip)
                elif family == socket.AF_INET6 and ip not in records["AAAA"]:
                    records["AAAA"].append(ip)
            return records

        pinned = target_addresses(host)
        if pinned is not None:
            records = {"A": [], "AAAA": []}
            for address in pinned:
                records["AAAA" if ipaddress.ip_address(address).version == 6 else "A"].append(address)
        else:
            records = await asyncio.wait_for(loop.run_in_executor(None, _resolve), timeout=5)
        result.records = records
        record_observation('DNS', target_url, {'hostname': host, 'resolver': 'validated system address snapshot' if pinned is not None else 'system resolver'},
                           records, 'Addresses returned by system resolution. No authoritative DNS queries were performed.')

        if records.get("A"):
            findings.append(Finding(
                title="A Records Found",
                severity=Severity.INFO,
                description=f"IPv4 addresses: {', '.join(records['A'])}",
            ))

        if records.get("AAAA"):
            findings.append(Finding(
                title="AAAA Records Found",
                severity=Severity.INFO,
                description=f"IPv6 addresses: {', '.join(records['AAAA'])}",
            ))

        if not records.get("A") and not records.get("AAAA"):
            findings.append(Finding(
                title="No DNS Records Found",
                severity=Severity.INFO,
                description=f"Could not resolve any addresses for {host}.",
            ))

    except Exception as e:
        result.status = "error"
        result.error = "DNS resolution failed"
        findings.append(Finding(
            title="DNS Resolution Failed",
            severity=Severity.INFO,
            description=f"DNS lookup error: {str(e)}",
        ))

    result.findings = findings
    return result
