import asyncio
import json

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.requests import ClientDisconnect

from backend.database import db
from backend.main import app
from backend.models.scan import DNSScanResult, ScanModules, ScanRequest
from backend.routers import scan as scan_router
from backend.services import scanner


def request_for(*enabled):
    return ScanRequest(target_url='localhost:3000', modules=ScanModules(**{key: key in enabled for key in ScanModules.model_fields}))


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url='http://localhost') as client:
        yield client


async def test_module_failure_is_reported_without_losing_other_results(monkeypatch):
    async def failure(target):
        raise RuntimeError('internal detail')
    async def dns(target):
        return DNSScanResult(records={'A': ['127.0.0.1']})
    monkeypatch.setattr(scanner, 'scan_cors', failure)
    monkeypatch.setattr(scanner, 'scan_dns', dns)
    events = []
    async def emit(event):
        events.append(event)
    result = await scanner.execute_scan(request_for('cors_scan', 'dns_scan'), emit)
    assert result.status == 'partial'
    assert result.module_status['cors_scan'] == 'error'
    assert result.module_status['dns_scan'] == 'success'
    assert result.score is None
    assert 'internal detail' not in result.errors['cors_scan']
    assert events[0]['type'] == 'started'
    assert (await db.get_scan(result.scan_id))['results']['errors']


async def test_save_failure_keeps_report_and_warns(monkeypatch):
    async def dns(target):
        return DNSScanResult()
    async def fail_save(*args):
        raise OSError('disk full')
    monkeypatch.setattr(scanner, 'scan_dns', dns)
    monkeypatch.setattr(scanner, 'save_scan', fail_save)
    result = await scanner.execute_scan(request_for('dns_scan'))
    assert result.saved is False
    assert result.warnings
    assert result.dns_scan is not None


async def test_stream_completes_and_history_export_round_trip(client, monkeypatch):
    async def dns(target):
        return DNSScanResult(records={'A': ['127.0.0.1']})
    monkeypatch.setattr(scanner, 'scan_dns', dns)
    response = await client.post('/api/scan/stream', json=request_for('dns_scan').model_dump())
    assert response.status_code == 200
    events = [json.loads(line) for line in response.text.splitlines()]
    assert [event['type'] for event in events] == ['started', 'module', 'module', 'complete']
    result = events[-1]['result']
    scan_id = result['scan_id']
    assert not scan_router._scan_lock.locked()
    history = (await client.get('/api/history')).json()
    assert history['total'] == 1
    detail = (await client.get(f'/api/history/{scan_id}')).json()
    assert detail['results']['score'] is None
    export = await client.get(f'/api/report/{scan_id}')
    assert export.json() == result
    assert 'attachment' in export.headers['content-disposition']
    assert (await client.delete(f'/api/history/{scan_id}')).status_code == 200
    assert (await client.get(f'/api/history/{scan_id}')).status_code == 404


async def test_invalid_request_is_rejected_before_streaming(client):
    response = await client.post('/api/scan/stream', json={'target_url': 'http://localhost:99999'})
    assert response.status_code == 422
    assert not scan_router._scan_lock.locked()


async def test_concurrent_scan_returns_retry_after(client):
    await scan_router._scan_lock.acquire()
    try:
        for path in ('/api/scan', '/api/scan/stream'):
            response = await client.post(path, json=request_for('dns_scan').model_dump())
            assert response.status_code == 429
            assert response.headers['retry-after'] == '5'
    finally:
        scan_router._scan_lock.release()


async def test_stream_disconnect_cancels_modules_and_releases_slot(monkeypatch):
    running, cancelled = asyncio.Event(), asyncio.Event()
    async def slow_dns(target):
        running.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
    monkeypatch.setattr(scanner, 'scan_dns', slow_dns)
    response = await scan_router.stream_scan(request_for('dns_scan'))
    iterator = response.body_iterator
    assert json.loads(await anext(iterator))['type'] == 'started'
    await asyncio.wait_for(running.wait(), timeout=2)
    await iterator.aclose()
    await asyncio.wait_for(cancelled.wait(), timeout=2)
    assert not scan_router._scan_lock.locked()
    assert (await db.get_scan_history())['total'] == 0


async def test_stream_error_releases_slot(client, monkeypatch):
    async def invalid(target):
        raise ValueError('Could not resolve the target')
    monkeypatch.setattr(scanner, 'validate_target_address', invalid)
    response = await client.post('/api/scan/stream', json=request_for('dns_scan').model_dump())
    assert json.loads(response.text)['type'] == 'error'
    assert not scan_router._scan_lock.locked()


async def test_disconnect_before_stream_iteration_releases_slot():
    response = await scan_router.stream_scan(request_for('dns_scan'))
    async def send(message):
        raise OSError('connection closed before response started')
    async def receive():
        return {'type': 'http.disconnect'}
    with pytest.raises(ClientDisconnect):
        await response({'type': 'http', 'asgi': {'spec_version': '2.4'}}, receive, send)
    assert not scan_router._scan_lock.locked()


async def test_active_tests_run_after_audit_and_sequentially(monkeypatch, local_server):
    from aiohttp import web

    from backend.models.scan import BenchmarkResult
    order = []
    async def audit(target):
        order.append('audit')
        return DNSScanResult()
    async def benchmark(target, **kwargs):
        order.append('benchmark-start')
        await asyncio.sleep(0)
        order.append('benchmark-end')
        return BenchmarkResult()
    async def resilience(target):
        order.append('resilience')
        return {}
    async def target(request):
        return web.Response(text='ok')
    monkeypatch.setattr(scanner, 'scan_dns', audit)
    monkeypatch.setattr(scanner, 'run_load_test', benchmark)
    monkeypatch.setattr(scanner, 'test_ddos_resilience', resilience)
    async with local_server(target) as url:
        request = request_for('dns_scan', 'load_test', 'ddos_test').model_copy(update={'target_url': url})
        result = await scanner.execute_scan(request)
    assert result.status == 'success'
    assert order == ['audit', 'benchmark-start', 'benchmark-end', 'resilience']
