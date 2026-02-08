"""Keep scanner connections within one validated DNS snapshot per assessment."""

import asyncio
import ipaddress
import socket
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

from backend.utils.validators import is_private_address


@dataclass(frozen=True)
class TargetSnapshot:
    hostname: str
    addresses: tuple[str, ...]


_snapshot: ContextVar[TargetSnapshot | None] = ContextVar('localghost_target', default=None)
_session_headers: ContextVar[dict] = ContextVar('localghost_session', default={})


@contextmanager
def use_session(headers: dict):
    token = _session_headers.set(headers)
    try:
        yield
    finally:
        _session_headers.reset(token)


def _host_key(hostname: str) -> str:
    try:
        return str(ipaddress.ip_address(hostname)).lower()
    except ValueError:
        return hostname.lower().rstrip('.')


@contextmanager
def pin_target(url: str, addresses: tuple[str, ...]):
    """Child scanner tasks inherit the snapshot; reset it even on cancellation."""
    if not addresses or not all(is_private_address(address) for address in addresses):
        raise ValueError('A scan requires validated private target addresses')
    snapshot = TargetSnapshot(urlsplit(url).hostname, tuple(dict.fromkeys(addresses)))
    token = _snapshot.set(snapshot)
    try:
        yield snapshot
    finally:
        _snapshot.reset(token)


def target_addresses(hostname: str) -> tuple[str, ...] | None:
    snapshot = _snapshot.get()
    if snapshot is None:
        return None
    if _host_key(hostname) != _host_key(snapshot.hostname):
        raise ValueError('A scanner attempted to connect outside the selected target')
    return snapshot.addresses


class PinnedResolver(AbstractResolver):
    def __init__(self, snapshot: TargetSnapshot):
        self.snapshot = snapshot

    async def resolve(self, host, port=0, family=socket.AF_UNSPEC):
        if _host_key(host) != _host_key(self.snapshot.hostname):
            raise OSError('Hostname is outside the selected scan target')
        resolved = []
        for address in self.snapshot.addresses:
            address_family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
            if family in (socket.AF_UNSPEC, address_family):
                resolved.append({'hostname': host, 'host': address, 'port': port,
                                 'family': address_family, 'proto': socket.IPPROTO_TCP,
                                 'flags': socket.AI_NUMERICHOST})
        if not resolved:
            raise OSError('No validated target address for this address family')
        return resolved

    async def close(self):
        pass


def scanner_connector(**kwargs) -> aiohttp.TCPConnector:
    snapshot = _snapshot.get()
    if snapshot is not None:
        kwargs['resolver'] = PinnedResolver(snapshot)
    return aiohttp.TCPConnector(**kwargs)


def scanner_session(**kwargs) -> aiohttp.ClientSession:
    from backend.utils.evidence import capture_trace
    evidence_trace = capture_trace()
    if evidence_trace:
        kwargs['trace_configs'] = [*kwargs.get('trace_configs', []), evidence_trace]
    kwargs['headers'] = {**_session_headers.get(), **kwargs.get('headers', {})}
    if 'connector' not in kwargs:
        kwargs['connector'] = scanner_connector()
    snapshot = _snapshot.get()
    if snapshot is not None:
        trace = aiohttp.TraceConfig()

        async def check_target(session, context, params):
            if _host_key(params.url.host) != _host_key(snapshot.hostname):
                raise ValueError('HTTP request is outside the selected scan target')

        async def reject_redirect(session, context, params):
            raise ValueError('Scanner redirects are not followed; use the final target URL')

        trace.on_request_start.append(check_target)
        trace.on_request_redirect.append(reject_redirect)
        kwargs['trace_configs'] = [*kwargs.get('trace_configs', []), trace]
    return aiohttp.ClientSession(**kwargs)


async def open_target_connection(host: str, port: int, **kwargs):
    """Use numeric endpoints while retaining the original TLS SNI/verification name."""
    addresses = target_addresses(host)
    if addresses is None:
        return await asyncio.open_connection(host, port, **kwargs)
    if kwargs.get('ssl') and 'server_hostname' not in kwargs:
        kwargs['server_hostname'] = host
    last_error = None
    for address in addresses:
        try:
            return await asyncio.open_connection(address, port, **kwargs)
        except OSError as exc:
            last_error = exc
    raise last_error or OSError('No target address could be reached')
