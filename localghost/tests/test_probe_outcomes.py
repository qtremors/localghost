import asyncio
import socket

import pytest
from aiohttp import web

from backend.scanners import ddos_test, port_scan, rate_limit_test, xss_scan


@pytest.fixture
def small_xss_scan(monkeypatch):
    monkeypatch.setattr(xss_scan, 'XSS_PAYLOADS', ['<svg/onload=alert(1)>'])
    monkeypatch.setattr(xss_scan, 'COMMON_PARAMS', ['q'])
    monkeypatch.setattr(xss_scan, 'INJECTABLE_PATHS', ['/'])


@pytest.mark.parametrize('status', [302, 403, 429, 503])
async def test_unavailable_xss_probes_do_not_pass(local_server, small_xss_scan, status):
    async def handler(request):
        return web.Response(status=status, text='Unavailable', headers={'Location': '/login'} if status == 302 else {})
    async with local_server(handler) as url:
        result = await xss_scan.scan_xss(url)
    assert result['status'] == 'error'
    assert result['vulnerable'] is None
    assert result['probe_coverage'] == {'attempted': 4, 'completed': 0, 'inconclusive': 4}
    assert not any(finding['severity'] == 'pass' for finding in result['findings'])


async def test_reflection_is_preserved_when_other_xss_probes_fail(local_server, small_xss_scan):
    async def handler(request):
        if request.query.get('q'):
            return web.Response(text=request.query['q'], content_type='text/html')
        return web.Response(status=503, text='Unavailable')
    async with local_server(handler) as url:
        result = await xss_scan.scan_xss(url)
    assert result['status'] == 'partial'
    assert result['vulnerable'] is True
    assert result['reflections_found'] == 1
    assert any(finding['severity'] == 'high' for finding in result['findings'])


async def test_xss_reads_later_response_chunks(local_server, small_xss_scan):
    async def handler(request):
        response = web.StreamResponse(headers={'Content-Type': 'text/html'})
        await response.prepare(request)
        await response.write(b'<html>first chunk')
        await asyncio.sleep(.01)
        await response.write(request.query.get('q', 'safe').encode())
        await response.write_eof()
        return response
    async with local_server(handler) as url:
        result = await xss_scan._test_param_injection(url)
    assert result['completed'] == 1
    assert len(result['reflections']) == 1


async def test_oversize_xss_responses_are_inconclusive(local_server, small_xss_scan):
    async def handler(request):
        return web.Response(body=b'x' * (1024 * 1024 + 10), content_type='text/html')
    async with local_server(handler) as url:
        result = await xss_scan._test_param_injection(url)
    assert result['tests_run'] == 1
    assert result['completed'] == 0
    assert result['reflections'] == []


async def test_rate_limit_baseline_failure_stops_further_probes(local_server, monkeypatch):
    calls = []
    async def handler(request):
        calls.append(request.path)
        return web.Response(status=403)
    async def must_not_run(*args, **kwargs):
        pytest.fail('Active probes must not run after an unavailable baseline')
    monkeypatch.setattr(rate_limit_test, '_burst_test', must_not_run)
    async with local_server(handler) as url:
        result = await rate_limit_test.test_rate_limits(url)
    assert calls == ['/']
    assert result['status'] == 'error'
    assert result['has_rate_limiting'] is None
    assert not any(finding['severity'] in ('pass', 'high', 'critical') for finding in result['findings'])


async def test_rate_limit_burst_separates_rejections_errors_and_unavailable(local_server):
    statuses = iter([200, 429, 503, 403])
    async def handler(request):
        return web.Response(status=next(statuses))
    async with local_server(handler) as url:
        result = await rate_limit_test._burst_test(url, num_requests=4)
    assert result['accepted'] == 1
    assert result['rate_limited_count'] == 1
    assert result['errors'] == 1
    assert result['unavailable'] == 1


async def test_first_429_is_observed_response_order_not_dispatch_index(local_server):
    calls = 0
    async def handler(request):
        nonlocal calls
        calls += 1
        if calls == 1:
            await asyncio.sleep(.03)
            return web.Response()
        return web.Response(status=429)
    async with local_server(handler) as url:
        result = await rate_limit_test._burst_test(url, num_requests=2)
    assert result['first_429_at'] == 1


async def test_missing_rate_limit_endpoints_are_not_counted_as_accepted(local_server):
    calls = []
    async def handler(request):
        calls.append(request.path)
        return web.Response(status=404)
    async with local_server(handler) as url:
        endpoints = await rate_limit_test._test_endpoint_limits(url + '/nested?key=example')
    assert all(endpoint['requests_sent'] == 1 and endpoint['unavailable'] == 1 and endpoint['accepted'] == 0 for endpoint in endpoints)
    assert calls == ['/nested', '/', '/health', '/api']


async def test_connection_failures_are_not_counted_as_rate_limit_rejections():
    with socket.socket() as unused:
        unused.bind(('127.0.0.1', 0))
        port = unused.getsockname()[1]
    result = await ddos_test._test_rapid_fire(f'http://127.0.0.1:{port}', num_requests=2)
    assert result['errors'] == 2
    assert result['rejected_count'] == 0
    assert result['accepted'] == 0


async def test_resilience_cannot_be_assessed_when_baseline_is_down(local_server, monkeypatch):
    async def handler(request):
        return web.Response(status=503)
    async def must_not_run(*args, **kwargs):
        pytest.fail('No resilience traffic should be generated after a failed baseline')
    monkeypatch.setattr(ddos_test, '_test_connection_flood', must_not_run)
    async with local_server(handler) as url:
        result = await ddos_test.test_ddos_resilience(url)
    assert result['status'] == 'error'
    assert result['resilience_score'] is None
    assert result['probe_coverage']['completed'] == 0
    assert not any(finding['severity'] == 'pass' for finding in result['findings'])


async def test_completed_error_response_is_not_a_held_slow_connection():
    async def handler(reader, writer):
        try:
            await reader.read(4096)
            writer.write(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 3\r\nConnection: close\r\n\r\nBAD')
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()
    server = await asyncio.start_server(handler, '127.0.0.1', 0)
    try:
        port = server.sockets[0].getsockname()[1]
        result = await ddos_test._test_slowloris(f'http://127.0.0.1:{port}', num_connections=1, hold_seconds=.02)
        assert result['connections_held'] == 1
        assert result['still_alive_after_hold'] == 0
        assert result['errors'] == 0
    finally:
        server.close()
        await server.wait_closed()


async def test_port_timeouts_are_not_reported_as_closed(monkeypatch):
    async def unreachable(*args, **kwargs):
        raise TimeoutError()
    monkeypatch.setattr(port_scan, 'open_target_connection', unreachable)
    result = await port_scan.scan_ports('http://127.0.0.1:3000', ports=[3000])
    assert result.status == 'error'
    assert result.inconclusive_ports == [3000]
    assert result.closed_count == 0


async def test_incomplete_rate_limit_tests_do_not_claim_missing_limits(monkeypatch):
    async def header(*args, **kwargs):
        return {'completed': True, 'headers': {}}
    async def failed(*args, **kwargs):
        return {'total_requests': 3, 'accepted': 0, 'rate_limited_count': 0, 'errors': 3, 'unavailable': 0, 'first_429_at': 0}
    async def endpoints(*args, **kwargs):
        return []
    monkeypatch.setattr(rate_limit_test, '_check_rate_limit_headers', header)
    monkeypatch.setattr(rate_limit_test, '_burst_test', failed)
    monkeypatch.setattr(rate_limit_test, '_sustained_test', failed)
    monkeypatch.setattr(rate_limit_test, '_test_endpoint_limits', endpoints)
    result = await rate_limit_test.test_rate_limits('http://localhost')
    assert result['status'] == 'partial'
    assert result['has_rate_limiting'] is None
    assert result['probe_coverage'] == {'attempted': 7, 'completed': 1, 'inconclusive': 6}
    assert not any(finding['title'] == 'No Rate Limiting Observed' for finding in result['findings'])


async def test_closed_slow_connections_receive_credit_based_on_end_state(monkeypatch):
    async def available(*args, **kwargs):
        return {'available': True, 'testable': True, 'response_ms': 1, 'status_code': 200}
    async def flood(*args, **kwargs):
        return {'total_connections': 100, 'successful': 100, 'failed': 0, 'success_rate': 100}
    async def slow(*args, **kwargs):
        return {'attempted': 20, 'connections_held': 20, 'still_alive_after_hold': 0, 'errors': 0, 'hold_duration_sec': 5}
    async def rapid(*args, **kwargs):
        return {'total_requests': 200, 'accepted': 200, 'rejected_count': 0, 'errors': 0, 'avg_response_ms': 1}
    monkeypatch.setattr(ddos_test, '_test_availability', available)
    monkeypatch.setattr(ddos_test, '_test_connection_flood', flood)
    monkeypatch.setattr(ddos_test, '_test_slowloris', slow)
    monkeypatch.setattr(ddos_test, '_test_rapid_fire', rapid)
    result = await ddos_test.test_ddos_resilience('http://localhost')
    assert result['status'] == 'success'
    assert result['resilience_score'] == 90
    assert any(finding['title'] == 'Slow Requests Closed Within Test Period' for finding in result['findings'])
    rapid_errors = {'total_requests': 2, 'accepted': 0, 'rejected_count': 0, 'errors': 2, 'avg_response_ms': 1}
    async def failed_rapid(*args, **kwargs):
        return rapid_errors
    monkeypatch.setattr(ddos_test, '_test_rapid_fire', failed_rapid)
    result = await ddos_test.test_ddos_resilience('http://localhost')
    assert result['status'] == 'partial'
    assert result['resilience_score'] is None
    assert not any(finding['title'] == 'Server Applies Rate Limiting Under Burst' for finding in result['findings'])


async def test_port_scan_with_no_eligible_ports_has_no_score():
    from backend.services.scoring import compute_score
    result = await port_scan.scan_ports('http://127.0.0.1:13666', ports=[13666])
    assert result.status == 'error'
    assert result.total_scanned == 0
    assert compute_score(ports=result).coverage == 0


async def test_connection_reset_during_teardown_does_not_hide_open_port(monkeypatch):
    class Writer:
        def close(self):
            pass
        async def wait_closed(self):
            raise ConnectionResetError()
    async def connect(*args, **kwargs):
        return object(), Writer()
    monkeypatch.setattr(port_scan, 'open_target_connection', connect)
    result = await port_scan.scan_ports('http://127.0.0.1:3000', ports=[3000])
    assert result.status == 'success'
    assert result.open_ports[0]['port'] == 3000
    assert result.inconclusive_ports == []
