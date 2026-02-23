"""Compare repeat assessments using only evidence available in both reports."""

from urllib.parse import urlsplit

FINDING_MODULES = (
    "vuln_scan", "ssl_scan", "cors_scan", "cookie_scan", "tech_detect",
    "dns_scan", "ddos_test", "rate_limit_test", "xss_scan",
    "source_scan", "browser_check",
)
ACTIONABLE = ("critical", "high", "medium", "low")
SEVERITY_ORDER = {value: index for index, value in enumerate(ACTIONABLE)}


def _same_target(url: str):
    parsed = urlsplit(url)
    return (
        parsed.scheme.lower(), (parsed.hostname or "").lower(),
        parsed.port or (443 if parsed.scheme == "https" else 80),
        parsed.path or "/", parsed.query,
    )


def _completed(report: dict, module: str) -> bool:
    result = report.get(module)
    if not isinstance(result, dict):
        return False
    return report.get("module_status", {}).get(module, result.get("status", "success")) == "success"


def _findings(report: dict, modules: list[str]) -> dict:
    findings = {}
    for module in modules:
        candidates = [item for item in report.get('findings', []) if item['module'] == module] if report.get('scanner_version', 1) >= 3 else report[module].get('findings', [])
        for finding in candidates:
            if finding.get("severity") not in ACTIONABLE:
                continue
            key = (module, finding.get('id') or finding['title'])
            candidate = {**finding, "module": module}
            # Deduplicate repeated findings conservatively at the highest severity.
            if key not in findings or SEVERITY_ORDER[candidate["severity"]] < SEVERITY_ORDER[findings[key]["severity"]]:
                findings[key] = candidate
    return findings


def _metadata(report):
    score = report.get("score") or {}
    return {
        "scan_id": report["scan_id"], "timestamp": report["timestamp"],
        "score": score.get("score"), "coverage": score.get("coverage"),
        "resolved_addresses": report.get("resolved_addresses", []),
    }


def compare_scans(baseline: dict, current: dict) -> dict:
    if baseline["scan_id"] == current["scan_id"]:
        raise ValueError("Choose a different scan as the baseline")
    if _same_target(baseline["target"]) != _same_target(current["target"]):
        raise ValueError("Choose two reports for the same target URL")
    rules_changed = baseline.get('scanner_version', 1) != current.get('scanner_version', 1)
    comparable = [module for module in FINDING_MODULES if not rules_changed and _completed(baseline, module) and _completed(current, module)]
    old_request, new_request = baseline.get('request') or {}, current.get('request') or {}
    if (baseline.get('authentication_used', False) != current.get('authentication_used', False)
            or old_request.get('environment') != new_request.get('environment')):
        comparable = []
    if old_request.get('source_path') != new_request.get('source_path'):
        comparable = [module for module in comparable if module != 'source_scan']
    if old_request.get('paths') != new_request.get('paths'):
        comparable = [module for module in comparable if module not in ('browser_check', 'vuln_scan', 'cors_scan', 'cookie_scan')]
    if baseline.get('authentication', {}).get('profile') != current.get('authentication', {}).get('profile'):
        comparable = []
    if baseline.get('audit_targets') != current.get('audit_targets'):
        comparable = [module for module in comparable if module not in ('vuln_scan', 'cors_scan', 'cookie_scan')]
    before, after = _findings(baseline, comparable), _findings(current, comparable)
    old_keys, new_keys = before.keys(), after.keys()
    added = [after[key] for key in new_keys - old_keys]
    resolved = [before[key] for key in old_keys - new_keys]
    changed = [
        {**after[key], "previous_severity": before[key]["severity"]}
        for key in old_keys & new_keys if before[key]["severity"] != after[key]["severity"]
    ]
    def ordering(finding):
        return (SEVERITY_ORDER[finding["severity"]], finding["module"], finding["title"])
    before_score, after_score = baseline.get("score") or {}, current.get("score") or {}
    # A matching percentage alone does not imply matching category coverage.
    before_categories = {key for key, value in before_score.get("breakdown", {}).items() if value is not None}
    after_categories = {key for key, value in after_score.get("breakdown", {}).items() if value is not None}
    scores_comparable = (
        not rules_changed and bool(before_categories) and before_categories == after_categories
        and before_score.get("coverage") is not None and after_score.get("coverage") is not None
        and before_score.get("coverage") == after_score.get("coverage")
        and before_score.get('version', 1) == after_score.get('version', 1)
    )
    ports_comparable = not rules_changed and _completed(baseline, "port_scan") and _completed(current, "port_scan")
    before_ports = {port["port"] for port in baseline.get("port_scan", {}).get("open_ports", [])} if ports_comparable else set()
    after_ports = {port["port"] for port in current.get("port_scan", {}).get("open_ports", [])} if ports_comparable else set()
    # A changed port list can make a previously open port appear to disappear.
    if ports_comparable:
        old_request, new_request = baseline.get("request") or {}, current.get("request") or {}
        ports_comparable = (
            "ports_to_scan" in old_request and "ports_to_scan" in new_request
            and old_request["ports_to_scan"] == new_request["ports_to_scan"]
        )
        old_checked = baseline['port_scan'].get('ports_checked')
        new_checked = current['port_scan'].get('ports_checked')
        if old_checked and new_checked:
            ports_comparable = set(old_checked) == set(new_checked)
    return {
        "target": current["target"], "baseline": _metadata(baseline), "current": _metadata(current),
        "score_delta": after_score["score"] - before_score["score"] if scores_comparable else None,
        "score_note": "Matching assessed categories" if scores_comparable else "Scores use different scoring rules or different checks",
        "rules_changed": rules_changed,
        "endpoint_changed": (
            set(baseline["resolved_addresses"]) != set(current["resolved_addresses"])
            if baseline.get("resolved_addresses") and current.get("resolved_addresses") else None
        ),
        "comparable_modules": comparable,
        "excluded_modules": [module for module in FINDING_MODULES if module not in comparable and (baseline.get(module) or current.get(module))],
        "new_findings": sorted(added, key=ordering), "resolved_findings": sorted(resolved, key=ordering),
        "changed_findings": sorted(changed, key=ordering),
        "unchanged_count": len(old_keys & new_keys) - len(changed),
        "before_counts": {severity: sum(finding["severity"] == severity for finding in before.values()) for severity in ACTIONABLE},
        "after_counts": {severity: sum(finding["severity"] == severity for finding in after.values()) for severity in ACTIONABLE},
        "ports": {
            "comparable": ports_comparable,
            "opened": sorted(after_ports - before_ports) if ports_comparable else [],
            "closed": sorted(before_ports - after_ports) if ports_comparable else [],
        },
    }
