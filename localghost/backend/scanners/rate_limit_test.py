"""Observe rate-limit evidence while keeping errors separate from rejections."""

import asyncio
import time
from urllib.parse import urljoin, urlsplit

import aiohttp

from backend.models.scan import Finding, Severity
from backend.utils.network import scanner_connector, scanner_session
from backend.utils.probes import ProbeCoverage

RATE_LIMIT_HEADERS = [
    'X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset',
    'X-Rate-Limit-Limit', 'X-Rate-Limit-Remaining', 'X-Rate-Limit-Reset',
    'RateLimit-Limit', 'RateLimit-Remaining', 'RateLimit-Reset',
    'RateLimit-Policy', 'Retry-After',
]


def _counts(attempted=0):
    return {'total_requests': attempted, 'accepted': 0, 'rate_limited_count': 0,
            'errors': 0, 'unavailable': 0, 'responses_received': 0}


def _record_response(result, status):
    result['responses_received'] += 1
    if status == 429:
        result['rate_limited_count'] += 1
    elif 200 <= status < 300:
        result['accepted'] += 1
    elif status >= 500:
        result['errors'] += 1
    else:
        result['unavailable'] += 1


async def test_rate_limits(target_url: str) -> dict:
    if not target_url.startswith(('http://', 'https://')):
        target_url = f'http://{target_url}'
    coverage = ProbeCoverage()
    findings = []
    result = {'has_rate_limiting': None, 'evidence': 'inconclusive',
              'rate_limit_headers': {}, 'trigger_threshold': 0, 'first_429_response': 0,
              'burst_test': {}, 'sustained_test': {}, 'endpoint_tests': []}
    header = await _check_rate_limit_headers(target_url)
    result['rate_limit_headers'] = header['headers']
    coverage.record(header['completed'])
    if not header['completed']:
        findings.append(Finding(title='Rate Limit Assessment Unavailable', severity=Severity.INFO,
            description='The initial request failed, redirected, or returned an unavailable response. No absence of rate limiting can be inferred.',
            recommendation='Check target availability and access requirements before retrying.'))
    else:
        if header['headers']:
            findings.append(Finding(title='Rate Limit Headers Advertised', severity=Severity.INFO,
                description='The response advertises rate-limit metadata. Actual rejection evidence is recorded separately.'))
        burst = await _burst_test(target_url, num_requests=50)
        sustained = await _sustained_test(target_url, duration_sec=8, rps=10)
        endpoints = await _test_endpoint_limits(target_url)
        result.update(burst_test=burst, sustained_test=sustained, endpoint_tests=endpoints)
        for name, data in (('Burst', burst), ('Sustained', sustained)):
            coverage.merge(data['total_requests'], data['accepted'] + data['rate_limited_count'])
            if data['rate_limited_count']:
                findings.append(Finding(title=f'{name} Rate Limiting Observed', severity=Severity.PASS,
                    description=f"Observed {data['rate_limited_count']} HTTP 429 responses out of {data['total_requests']} attempted requests."))
            elif data['errors'] or data['unavailable']:
                findings.append(Finding(title=f'{name} Rate Limit Check Incomplete', severity=Severity.INFO,
                    description=f"{data['errors']} requests failed and {data['unavailable']} returned blocked, redirected, or unavailable responses. These are not rate-limit rejections."))
            else:
                findings.append(Finding(title=f'No {name} Rate Limiting Observed', severity=Severity.INFO,
                    description=f"No HTTP 429 responses among {data['accepted']} completed requests at this workload. Limits may be higher or scoped differently.",
                    recommendation='Review whether the configured limits match your application requirements.'))
        for endpoint in endpoints:
            coverage.merge(endpoint['requests_sent'], endpoint['accepted'] + endpoint['rejected'])
        observed_rejections = burst['rate_limited_count'] + sustained['rate_limited_count'] + sum(endpoint['rejected'] for endpoint in endpoints)
        first_rejection = burst['first_429_at']
        result['first_429_response'] = first_rejection
        result['trigger_threshold'] = first_rejection  # Compatibility; not a configured server threshold.
        if observed_rejections:
            result.update(has_rate_limiting=True, evidence='responses')
            findings.append(Finding(title='Rate Limiting Observed', severity=Severity.PASS,
                description=f'Observed {observed_rejections} HTTP 429 responses. This confirms rejection for the tested workload and endpoints.'))
        elif header['headers']:
            result.update(has_rate_limiting=True, evidence='headers')
        elif not coverage.inconclusive:
            result.update(has_rate_limiting=False, evidence='not_observed')
            findings.append(Finding(title='No Rate Limiting Observed', severity=Severity.INFO,
                description='No HTTP 429 responses or standard rate-limit headers were observed. This does not rule out higher, authenticated, or differently scoped limits.',
                recommendation='Review your intended limits and, when appropriate, test their documented thresholds.'))
    result['status'] = coverage.status
    result['probe_coverage'] = coverage.to_dict()
    result['error'] = None
    if coverage.status != 'success':
        result['error'] = f'{coverage.inconclusive} probes were inconclusive; connection errors and unavailable responses do not prove rate limiting is absent'
        findings.append(Finding(title='Rate Limit Assessment Incomplete', severity=Severity.INFO,
            description=f'{coverage.completed} of {coverage.attempted} probes completed. Review the failed and unavailable request counts.'))
    result['findings'] = [finding.model_dump() for finding in findings]
    return result


async def _check_rate_limit_headers(url: str) -> dict:
    found_headers = {}
    try:
        async with scanner_session() as session:
            async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as response:
                found_headers = {name: response.headers[name] for name in RATE_LIMIT_HEADERS if response.headers.get(name)}
                return {'headers': found_headers, 'completed': 200 <= response.status < 300 or response.status == 429}
    except (aiohttp.ClientError, OSError, TimeoutError):
        pass
    return {'headers': found_headers, 'completed': False}


async def _burst_test(url: str, num_requests: int = 50) -> dict:
    result = {**_counts(num_requests), 'first_429_at': 0}
    connector = scanner_connector(limit=20)
    async with scanner_session(connector=connector) as session:
        async def single():
            try:
                async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=5)) as response:
                    _record_response(result, response.status)
                    if response.status == 429:
                        if not result['first_429_at']:
                            result['first_429_at'] = result['responses_received']
                        if response.headers.get('Retry-After'):
                            result['retry_after'] = response.headers['Retry-After']
            except (aiohttp.ClientError, OSError, TimeoutError):
                result['errors'] += 1
        await asyncio.gather(*(single() for _ in range(num_requests)))
    return result


async def _sustained_test(url: str, duration_sec: int = 8, rps: int = 10) -> dict:
    result = {**_counts(), 'duration_sec': duration_sec, 'rps_target': rps}
    started = time.monotonic()
    deadline = started + duration_sec
    async with scanner_session() as session:
        while time.monotonic() < deadline:
            request_start = time.monotonic()
            result['total_requests'] += 1
            try:
                async with session.get(url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=3)) as response:
                    _record_response(result, response.status)
            except (aiohttp.ClientError, OSError, TimeoutError):
                result['errors'] += 1
            await asyncio.sleep(max(0, min(deadline - time.monotonic(), 1 / rps - (time.monotonic() - request_start))))
    result['actual_duration_sec'] = round(time.monotonic() - started, 2)
    return result


async def _test_endpoint_limits(url: str) -> list:
    parsed = urlsplit(url)
    paths = list(dict.fromkeys([parsed.path or '/', '/', '/health', '/api']))
    results = []
    async with scanner_session() as session:
        for path in paths:
            test_url = url if path == (parsed.path or '/') else urljoin(url, path)
            result = {'path': path, 'requests_sent': 0, 'accepted': 0, 'rejected': 0,
                      'rate_limited': False, 'errors': 0, 'unavailable': 0}
            for _ in range(20):
                result['requests_sent'] += 1
                try:
                    async with session.get(test_url, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=2)) as response:
                        if response.status == 429:
                            result['rejected'] += 1
                            result['rate_limited'] = True
                        elif 200 <= response.status < 300:
                            result['accepted'] += 1
                        else:
                            result['errors' if response.status >= 500 else 'unavailable'] += 1
                            break  # Do not repeatedly probe routes that cannot be assessed.
                except (aiohttp.ClientError, OSError, TimeoutError):
                    result['errors'] += 1
                    break
            results.append(result)
    return results
