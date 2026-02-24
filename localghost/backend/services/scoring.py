"""Security scoring engine — computes a 0-100 score from scan results."""

from backend.models.scan import (
    ScoreResult, ScoreBreakdown, Severity,
    VulnScanResult, SSLScanResult, CORSScanResult, CookieScanResult, PortScanResult
)


# Weight allocation (total = 100)
WEIGHTS = {
    "headers": 30,
    "sensitive_files": 25,
    "ssl": 20,
    "cookies": 10,
    "cors": 10,
    "ports": 5,
}


def compute_score(
    vuln: VulnScanResult | None = None,
    ssl: SSLScanResult | None = None,
    cors: CORSScanResult | None = None,
    cookies: CookieScanResult | None = None,
    ports: PortScanResult | None = None,
) -> ScoreResult:
    """Compute a security score from scan results."""
    breakdown = ScoreBreakdown()

    # --- Security Headers (30 pts) ---
    if vuln and vuln.security_headers:
        total_headers = len(vuln.security_headers)
        present_count = sum(1 for h in vuln.security_headers.values() if h.present)
        if total_headers > 0:
            breakdown.headers = round((present_count / total_headers) * WEIGHTS["headers"], 1)
    else:
        breakdown.headers = WEIGHTS["headers"]  # If not scanned, give full score

    # --- Sensitive Files (25 pts) ---
    if vuln and vuln.sensitive_files:
        exposed = sum(1 for found in vuln.sensitive_files.values() if found)
        total_files = len(vuln.sensitive_files)
        if total_files > 0:
            # Each exposed file is worth proportional deduction, but critical files cost more
            critical_paths = {"/.env", "/.git/config", "/.git/HEAD", "/backup.sql", "/dump.sql"}
            critical_exposed = sum(1 for path, found in vuln.sensitive_files.items() if found and path in critical_paths)
            if critical_exposed > 0:
                breakdown.sensitive_files = 0  # Any critical exposure = 0 on this category
            elif exposed > 0:
                breakdown.sensitive_files = max(0, WEIGHTS["sensitive_files"] - (exposed * 5))
            else:
                breakdown.sensitive_files = WEIGHTS["sensitive_files"]
    else:
        breakdown.sensitive_files = WEIGHTS["sensitive_files"]

    # --- SSL/TLS (20 pts) ---
    if ssl:
        ssl_score = 0
        if ssl.has_ssl:
            ssl_score += 8  # Has SSL at all
            if ssl.cert_valid and not ssl.cert_expired:
                ssl_score += 6  # Valid cert
            if ssl.protocol_version in ("TLSv1.2", "TLSv1.3"):
                ssl_score += 6  # Modern protocol
            elif ssl.protocol_version:
                ssl_score += 2  # Some protocol but old
        # For local dev without SSL, don't penalize too harshly
        elif not ssl.has_ssl:
            ssl_score = 10  # Half credit for local dev
        breakdown.ssl = min(ssl_score, WEIGHTS["ssl"])
    else:
        breakdown.ssl = WEIGHTS["ssl"]

    # --- Cookies (10 pts) ---
    if cookies and cookies.cookies:
        total_cookies = len(cookies.cookies)
        secure_cookies = sum(
            1 for c in cookies.cookies
            if c.get("secure") and c.get("httponly") and c.get("samesite", "").lower() in ("lax", "strict")
        )
        if total_cookies > 0:
            breakdown.cookies = round((secure_cookies / total_cookies) * WEIGHTS["cookies"], 1)
    else:
        breakdown.cookies = WEIGHTS["cookies"]  # No cookies = nothing to exploit

    # --- CORS (10 pts) ---
    if cors:
        if not cors.cors_enabled:
            breakdown.cors = WEIGHTS["cors"]  # Most restrictive = good
        elif cors.allow_origin == "*" and cors.allow_credentials:
            breakdown.cors = 0  # Worst case
        elif cors.allow_origin == "*":
            breakdown.cors = 4
        elif cors.allow_origin and "evil" not in cors.allow_origin:
            breakdown.cors = WEIGHTS["cors"]  # Specific origin = good
        else:
            breakdown.cors = 2  # Origin reflection = bad
    else:
        breakdown.cors = WEIGHTS["cors"]

    # --- Open Ports (5 pts) ---
    if ports and ports.open_ports:
        open_count = len(ports.open_ports)
        # More open ports = slightly more risk, but minor
        if open_count <= 3:
            breakdown.ports = WEIGHTS["ports"]
        elif open_count <= 6:
            breakdown.ports = 3
        elif open_count <= 10:
            breakdown.ports = 2
        else:
            breakdown.ports = 1
    else:
        breakdown.ports = WEIGHTS["ports"]

    # Calculate total
    total = round(
        breakdown.headers +
        breakdown.sensitive_files +
        breakdown.ssl +
        breakdown.cookies +
        breakdown.cors +
        breakdown.ports
    )
    total = max(0, min(100, total))

    # Determine grade
    grade = _get_grade(total)

    return ScoreResult(score=total, grade=grade, breakdown=breakdown)


def _get_grade(score: int) -> str:
    """Convert a numeric score to a letter grade."""
    if score >= 90:
        return "A+"
    elif score >= 80:
        return "A"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"
