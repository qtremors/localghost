"""Scanner orchestration service — runs all enabled modules and aggregates results."""

import asyncio
import uuid
from datetime import datetime, timezone

from backend.models.scan import (
    ScanRequest, ScanResponse, ScoreResult,
    PortScanResult, VulnScanResult, SSLScanResult,
    CORSScanResult, CookieScanResult, TechDetectResult,
    DNSScanResult, BenchmarkResult
)
from backend.scanners.port_scan import scan_ports
from backend.scanners.vuln_scan import check_vulnerabilities
from backend.scanners.ssl_scan import scan_ssl
from backend.scanners.cors_scan import scan_cors
from backend.scanners.cookie_scan import scan_cookies
from backend.scanners.tech_detect import detect_technologies
from backend.scanners.dns_scan import scan_dns
from backend.scanners.load_test import run_load_test
from backend.scanners.ddos_test import test_ddos_resilience
from backend.scanners.rate_limit_test import test_rate_limits
from backend.scanners.xss_scan import scan_xss
from backend.services.scoring import compute_score
from backend.database.db import save_scan
from backend.utils.validators import validate_target_url


async def execute_scan(request: ScanRequest) -> ScanResponse:
    """Execute a full scan with all enabled modules."""

    target = validate_target_url(request.target_url)
    scan_id = str(uuid.uuid4())[:8]
    timestamp = datetime.now(timezone.utc).isoformat()

    modules = request.modules

    # Build tasks for enabled modules
    tasks = {}

    if modules.port_scan:
        tasks["port_scan"] = scan_ports(target, request.ports_to_scan)
    if modules.vuln_scan:
        tasks["vuln_scan"] = check_vulnerabilities(target)
    if modules.ssl_scan:
        tasks["ssl_scan"] = scan_ssl(target)
    if modules.cors_scan:
        tasks["cors_scan"] = scan_cors(target)
    if modules.cookie_scan:
        tasks["cookie_scan"] = scan_cookies(target)
    if modules.tech_detect:
        tasks["tech_detect"] = detect_technologies(target)
    if modules.dns_scan:
        tasks["dns_scan"] = scan_dns(target)
    if modules.load_test:
        tasks["load_test"] = run_load_test(
            target,
            concurrency=request.benchmark_config.concurrency,
            duration_seconds=request.benchmark_config.duration_seconds
        )
    if modules.ddos_test:
        tasks["ddos_test"] = test_ddos_resilience(target)
    if modules.rate_limit_test:
        tasks["rate_limit_test"] = test_rate_limits(target)
    if modules.xss_scan:
        tasks["xss_scan"] = scan_xss(target)

    # Run all enabled scans concurrently
    keys = list(tasks.keys())
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    # Map results back
    result_map = {}
    for key, result in zip(keys, results):
        if isinstance(result, Exception):
            result_map[key] = None  # Scan failed, but don't crash
        else:
            result_map[key] = result

    # Compute security score
    score = compute_score(
        vuln=result_map.get("vuln_scan"),
        ssl=result_map.get("ssl_scan"),
        cors=result_map.get("cors_scan"),
        cookies=result_map.get("cookie_scan"),
        ports=result_map.get("port_scan"),
    )

    # Build response
    response = ScanResponse(
        scan_id=scan_id,
        status="success",
        target=target,
        timestamp=timestamp,
        score=score,
        port_scan=result_map.get("port_scan"),
        vuln_scan=result_map.get("vuln_scan"),
        ssl_scan=result_map.get("ssl_scan"),
        cors_scan=result_map.get("cors_scan"),
        cookie_scan=result_map.get("cookie_scan"),
        tech_detect=result_map.get("tech_detect"),
        dns_scan=result_map.get("dns_scan"),
        benchmark=result_map.get("load_test"),
        ddos_test=result_map.get("ddos_test"),
        rate_limit_test=result_map.get("rate_limit_test"),
        xss_scan=result_map.get("xss_scan"),
    )

    # Save to database
    try:
        await save_scan(
            scan_id=scan_id,
            target_url=target,
            timestamp=timestamp,
            score=score.score,
            grade=score.grade,
            results=response.model_dump()
        )
    except Exception:
        pass  # Don't fail the scan if DB save fails

    return response
