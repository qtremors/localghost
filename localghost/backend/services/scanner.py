"""Run independent scan modules and report their actual lifecycle events."""

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urldefrag, urlsplit

import aiohttp

from backend.database.db import save_scan
from backend.models.scan import ScanRequest, ScanResponse
from backend.scanners.browser_check import check_pages
from backend.scanners.cookie_scan import scan_cookies
from backend.scanners.cors_scan import scan_cors
from backend.scanners.ddos_test import test_ddos_resilience
from backend.scanners.dns_scan import scan_dns
from backend.scanners.load_test import run_load_test
from backend.scanners.port_scan import scan_ports
from backend.scanners.rate_limit_test import test_rate_limits
from backend.scanners.ssl_scan import scan_ssl
from backend.scanners.tech_detect import detect_technologies
from backend.scanners.vuln_scan import check_vulnerabilities
from backend.scanners.xss_scan import scan_xss
from backend.services.authentication import prepare_session, verify_current_session
from backend.services.findings import prepare_findings
from backend.services.projects import project_origin
from backend.services.source import inspect_source
from backend.utils.evidence import record_evidence
from backend.utils.network import pin_target, scanner_session, use_session
from backend.utils.redaction import private_values, redact_data, register_secret
from backend.utils.runtime import scan_options, use_scan_options
from backend.utils.validators import validate_target_address, validate_target_url

logger = logging.getLogger(__name__)
ProgressHandler = Callable[[dict], Awaitable[None]]


async def execute_scan(request: ScanRequest, on_progress: ProgressHandler | None = None, *, persist=True, recheck_of=None) -> ScanResponse:
    target = validate_target_url(request.target_url)
    addresses = await validate_target_address(target)
    headers = request.session.headers() if request.session else {}
    with pin_target(target, addresses), use_session(headers), private_values(headers.values()), use_scan_options(request.environment):
        scan_options()['target'] = target
        scan_options()['started'] = time.monotonic()
        for url in [target, *request.paths]:
            for name, value in parse_qsl(urlsplit(url).query):
                if any(part in name.lower() for part in ('token', 'password', 'secret', 'api_key', 'apikey', 'session', 'access_key', 'authorization')):
                    register_secret(value)
        for name, value in headers.items():
            if name == 'Cookie':
                for part in value.split(';'):
                    if '=' in part:
                        register_secret(part.split('=', 1)[1].strip())
            elif name == 'Authorization' and ' ' in value:
                register_secret(value.split(' ', 1)[1])
        if on_progress and request.session:
            await on_progress({'type': 'session', 'status': 'running'})
        authentication = await prepare_session(target, request.session, headers)
        if on_progress and request.session:
            await on_progress({'type': 'session', 'status': authentication['status']})
        scan_options()['authentication'] = authentication
        result = await _execute_scan(request, target, addresses, on_progress, persist, recheck_of)
    return result


async def _execute_scan(request: ScanRequest, target: str, addresses: tuple[str, ...], on_progress: ProgressHandler | None, persist=True, recheck_of=None) -> ScanResponse:
    started = scan_options().get('started', time.monotonic())
    scan_id = uuid.uuid4().hex
    timestamp = datetime.now(timezone.utc).isoformat()
    audit_targets = list(dict.fromkeys(urldefrag(url)[0] for url in [target, *(project_origin(target) + path for path in request.paths)]))
    route_results = {}

    async def audit_routes(key, function):
        semaphore = asyncio.Semaphore(3)

        async def run_route(url):
            async with semaphore:
                with record_evidence(url) as recorder:
                    result = await function(url) if key != 'vuln_scan' or url == target else await function(url, include_files=False)
                result.evidence = recorder.items
                route_results.setdefault(url, {})[key] = result.model_dump()
                return result

        results = await asyncio.gather(*(run_route(url) for url in audit_targets))
        primary = results[0]
        incomplete = [url for url, result in zip(audit_targets, results) if result.status != 'success']
        if incomplete:
            primary.status = 'partial' if any(result.status != 'error' for result in results) else 'error'
            primary.error = f'{len(incomplete)} of {len(audit_targets)} selected routes had incomplete checks.'
        return primary

    runners = {
        "port_scan": lambda: scan_ports(target, request.ports_to_scan),
        "vuln_scan": lambda: audit_routes('vuln_scan', check_vulnerabilities),
        "ssl_scan": lambda: scan_ssl(target),
        "cors_scan": lambda: audit_routes('cors_scan', scan_cors),
        "cookie_scan": lambda: audit_routes('cookie_scan', scan_cookies),
        "tech_detect": lambda: detect_technologies(target),
        "dns_scan": lambda: scan_dns(target),
        "source_scan": lambda: asyncio.to_thread(inspect_source, request.source_path),
        "browser_check": lambda: check_pages(target, request.paths, request.session.headers() if request.session else {}),
        "load_test": lambda: run_load_test(target, **request.benchmark_config.model_dump()),
        "ddos_test": lambda: test_ddos_resilience(target),
        "rate_limit_test": lambda: test_rate_limits(target),
        "xss_scan": lambda: scan_xss(target),
    }
    enabled = [key for key, value in request.modules.model_dump().items() if value]
    statuses = {key: "pending" if key in enabled else "skipped" for key in runners}
    errors = {}
    result_map = {}

    async def emit(event: dict):
        if on_progress:
            await on_progress(event)

    await emit({"type": "started", "scan_id": scan_id, "target": target, "modules": enabled})

    active_tests = {"load_test", "ddos_test", "rate_limit_test", "xss_scan", "browser_check"}

    async def check_http_target():
        try:
            async with scanner_session(timeout=aiohttp.ClientTimeout(total=5)) as session:
                async with session.get(target, allow_redirects=False):
                    pass
        except (aiohttp.ClientError, TimeoutError) as exc:
            raise ValueError("Active test could not connect to the HTTP target") from exc

    async def run_module(key):
        statuses[key] = "running"
        await emit({"type": "module", "module": key, "status": "running"})
        try:
            authentication = scan_options().get('authentication', {})
            if authentication.get('status') == 'error' and key not in ('source_scan', 'port_scan', 'dns_scan', 'ssl_scan'):
                statuses[key] = 'error'
                errors[key] = authentication.get('error') or 'The session check failed. No anonymous fallback was used.'
                await emit({'type': 'module', 'module': key, 'status': 'error', 'error': errors[key]})
                return
            # Bound scanners with many sequential probes as well as individual requests.
            async with asyncio.timeout(180):
                with record_evidence(target) as recorder:
                    if key in active_tests:
                        await check_http_target()
                    result = await runners[key]()
                if key not in ('vuln_scan', 'cors_scan', 'cookie_scan'):
                    if isinstance(result, dict):
                        result['exchanges' if key == 'rate_limit_test' else 'evidence'] = recorder.items
                    else:
                        result.evidence = recorder.items
            state = result.get("status", "success") if isinstance(result, dict) else result.status
            message = result.get("error") if isinstance(result, dict) else result.error
            result_map[key] = result
            statuses[key] = state
            if state != "success":
                errors[key] = message or "Some checks could not be completed"
        except Exception:
            logger.warning("Module %s could not complete for scan %s", key, scan_id)
            statuses[key] = "error"
            errors[key] = "Module could not complete. Check the target connection and server logs."
        await emit({"type": "module", "module": key, "status": statuses[key], "error": errors.get(key)})

    # Explicit cancellation propagates to every module through gather.
    if 'source_scan' in enabled:
        await run_module('source_scan')
        scan_options()['source'] = result_map.get('source_scan') or {}
    server_modules = {'vuln_scan', 'cookie_scan', 'cors_scan'}
    await asyncio.gather(*(run_module(key) for key in enabled if key not in active_tests and key != 'source_scan' and key not in server_modules))
    if 'browser_check' in enabled:
        await run_module('browser_check')
        authentication = scan_options().get('authentication', {})
        if request.session and authentication.get('status') != 'error':
            scan_options()['authentication'] = await verify_current_session(target, request.session, headers=scan_options().get('session_headers', {}), authentication=authentication)
            authentication = scan_options()['authentication']
            if authentication.get('status') == 'error':
                statuses['browser_check'] = 'partial'
                errors['browser_check'] = 'The session check failed after visiting pages. Authenticated server checks were skipped.'
                if result_map.get('browser_check'):
                    result_map['browser_check'].update(status='partial', error=errors['browser_check'])
        observed_api = (result_map.get('browser_check') or {}).get('api_requests', [])[:20]
        for url in observed_api:
            for name, value in parse_qsl(urlsplit(url).query):
                if any(part in name.lower() for part in ('token', 'password', 'secret', 'api_key', 'apikey', 'session', 'access_key', 'authorization')):
                    register_secret(value)
        audit_targets.extend(url for url in observed_api if url not in audit_targets)
    await asyncio.gather(*(run_module(key) for key in enabled if key in server_modules))
    # Traffic-generating tests run after the audit, one at a time, so their loads
    # do not corrupt each other's measurements or ordinary security checks.
    for key in enabled:
        if key in active_tests and key != 'browser_check':
            await run_module(key)
    warnings = []
    http_audits = {'vuln_scan', 'cors_scan', 'cookie_scan', 'tech_detect'} & set(enabled)
    observed_statuses = {result_map[key].http_status for key in http_audits if key in result_map and result_map[key].http_status is not None}
    observed_statuses.update(data.get('http_status') for route in route_results.values() for key, data in route.items()
                             if key in http_audits and data.get('http_status') is not None)
    if http_audits and not any(200 <= status < 300 for status in observed_statuses):
        # Keep unavailable HTTP app coverage visible alongside port/TLS observations.
        detail = f" (HTTP {', '.join(map(str, sorted(observed_statuses)))})" if observed_statuses else ''
        warnings.append(f'No successful app response was checked{detail}. Review the incomplete checks before relying on this report.')
    completed = sum(statuses[key] != "error" for key in enabled)
    response = ScanResponse(
        scan_id=scan_id, target=target, timestamp=timestamp,
        resolved_addresses=list(addresses),
        status="success" if not errors else "partial" if completed else "error",
        duration_ms=round((time.monotonic() - started) * 1000, 2),
        module_status=statuses, errors=errors, warnings=warnings, request=request,
        authentication_used=bool(request.session),
        authentication=scan_options().get('authentication', {}),
        recheck_of=recheck_of,
        audit_targets=audit_targets, route_results=route_results,
        **{("benchmark" if key == "load_test" else key): value for key, value in result_map.items()},
    )
    response.scope = [
        f'Requested {request.environment} checks at {target}; observed build mode is reported separately.',
        'Source checks read routes, selected configuration, and bounded credential patterns in source and client builds. They do not execute project code.' if request.modules.source_scan else 'No source folder was checked.',
        f'Browser checked the target and {len(request.paths)} additional selected route(s).' if request.modules.browser_check else 'No pages were checked in a browser.',
        f"Session: {response.authentication.get('status', 'not_supplied')}. Only the configured sign-in/assertion was checked; other users and authorization boundaries were not tested." if response.authentication_used else 'No login session was supplied.',
        'SQL injection, stored XSS, business logic, and full application security are outside these checks.',
    ]
    response.scope.append(f'HTTP header, CORS, and cookie checks use each selected server route and up to 20 observed same-origin GET API URLs: {len(audit_targets)} URLs in scope. Only enabled checks run; see the route table for completion.')
    if request.session and request.session.refresh_path:
        response.scope.append(f'Only the configured session refresh POST {request.session.refresh_path} is allowed during page checks. Other writes and external requests are blocked.')
    runtime_pages = [item for modules in route_results.values() for item in modules.get('vuln_scan', {}).get('runtime_observations', [])]
    development = list(dict.fromkeys([item['url'] for item in runtime_pages if item['development_markers']] +
                                    [item['url'] for item in (response.browser_check or {}).get('pages', []) if item.get('development_markers')]))
    production = [item['url'] for item in runtime_pages if item['production_assets_matched']]
    response.environment_observation = {'requested': request.environment,
                                         'observed': 'development' if development else 'production' if production else 'unknown',
                                         'development_pages': development, 'production_build_matches': production,
                                         'note': 'Production means a served script matched a local build artifact. Absence of development markers alone is not proof of production.'}
    response.findings = prepare_findings(response)
    response.summary = {state: sum(f.verification == state and (state == 'not_checked' or f.severity.value not in ('pass', 'info')) for f in response.findings)
                        for state in ('confirmed', 'review', 'not_checked')}
    response.summary['completed'] = sum(state == 'success' for state in statuses.values())
    response.summary['incomplete'] = sum(state in ('partial', 'error') for state in statuses.values())
    response = ScanResponse.model_validate(redact_data(response.model_dump()))
    if not persist:
        response.saved = False
        return response
    try:
        await save_scan(scan_id, response.target, timestamp, 0, '—', response.model_dump())
    except Exception:
        logger.exception("Could not persist scan %s", scan_id)
        response.saved = False
        response.warnings.append("History could not be saved. Export this report to keep a copy.")
    return response
