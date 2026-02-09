"""Weighted security scores based only on successfully assessed categories."""

from backend.models.scan import (
    CookieScanResult,
    CORSScanResult,
    PortScanResult,
    ScoreBreakdown,
    ScoreResult,
    SSLScanResult,
    VulnScanResult,
)
from backend.scanners.vuln_scan import CRITICAL_PATHS

WEIGHTS = {"headers": 30, "sensitive_files": 25, "ssl": 20, "cookies": 10, "cors": 10, "ports": 5}


def compute_score(
    vuln: VulnScanResult | None = None,
    ssl: SSLScanResult | None = None,
    cors: CORSScanResult | None = None,
    cookies: CookieScanResult | None = None,
    ports: PortScanResult | None = None,
) -> ScoreResult:
    """Normalize earned points over assessed weights and expose coverage separately."""
    breakdown = ScoreBreakdown()
    if vuln and vuln.status != "error":
        if vuln.security_headers:
            applicable = [header for header in vuln.security_headers.values() if header.applicable]
            if applicable:
                accepted = sum(header.present and header.valid is not False for header in applicable)
                breakdown.headers = round(accepted / len(applicable) * WEIGHTS["headers"], 1)
        # Unreachable paths are unknown, never evidence that a file is protected.
        exposed = {path for path, found in vuln.sensitive_files.items() if found}
        if exposed & CRITICAL_PATHS:
            # A confirmed critical exposure determines this category even when
            # unrelated paths time out; partial scans must not hide known risk.
            breakdown.sensitive_files = 0
        elif vuln.sensitive_files and all(value is not None for value in vuln.sensitive_files.values()):
            breakdown.sensitive_files = max(0, WEIGHTS["sensitive_files"] - len(exposed) * 5)
    if ssl and ssl.status == "success":
        points = 10  # Partial credit for local development over plain HTTP.
        if ssl.has_ssl:
            points = 8 + (6 if ssl.cert_valid and not ssl.cert_expired else 0)
            points += 6 if ssl.protocol_version in ("TLSv1.2", "TLSv1.3") else 2 if ssl.protocol_version else 0
        breakdown.ssl = min(points, WEIGHTS["ssl"])
    if cookies and cookies.status == "success":
        secure = sum(
            bool(cookie.get("secure") and cookie.get("httponly")
                 and cookie.get("samesite", "").lower() in ("lax", "strict") and cookie.get('valid') is not False)
            for cookie in cookies.cookies
        )
        breakdown.cookies = round(secure / len(cookies.cookies) * WEIGHTS["cookies"], 1) if cookies.cookies else WEIGHTS["cookies"]
    if cors and cors.status == "success":
        if not cors.cors_enabled:
            breakdown.cors = WEIGHTS["cors"]
        elif cors.allow_origin == "*":
            breakdown.cors = 4  # Wildcard credentials are blocked by browsers.
        elif cors.allow_origin in ("https://evil-attacker.com", "https://localghost-cors-test.invalid", 'null'):
            breakdown.cors = 0 if cors.allow_credentials else 2
        else:
            breakdown.cors = WEIGHTS["cors"]
    if ports and ports.status == "success" and ports.total_scanned > 0:
        count = len(ports.open_ports)
        breakdown.ports = 5 if count <= 3 else 3 if count <= 6 else 2 if count <= 10 else 1
    values = breakdown.model_dump()
    available = sum(WEIGHTS[key] for key, value in values.items() if value is not None)
    total = round(sum(value for value in values.values() if value is not None) / available * 100) if available else 0
    total = max(0, min(100, total))
    return ScoreResult(
        score=total, grade=_get_grade(total) if available else "—",
        breakdown=breakdown, coverage=available, available_points=available,
    )


def _get_grade(score: int) -> str:
    for threshold, grade in ((90, "A+"), (80, "A"), (70, "B"), (60, "C"), (50, "D")):
        if score >= threshold:
            return grade
    return "F"
