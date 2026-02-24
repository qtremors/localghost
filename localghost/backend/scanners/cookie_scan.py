"""Cookie security audit scanner."""

import aiohttp
from backend.models.scan import CookieScanResult, Finding, Severity


async def scan_cookies(target_url: str) -> CookieScanResult:
    """Audit cookies set by the target URL for security issues."""

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    result = CookieScanResult()
    findings = []

    try:
        jar = aiohttp.CookieJar(unsafe=True)  # Accept all cookies for analysis
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(cookie_jar=jar, timeout=timeout) as session:
            async with session.get(target_url) as resp:
                raw_cookies = resp.headers.getall("Set-Cookie", [])

                if not raw_cookies:
                    findings.append(Finding(
                        title="No Cookies Set",
                        severity=Severity.PASS,
                        description="The server does not set any cookies on the initial response.",
                    ))
                    result.findings = findings
                    return result

                for raw in raw_cookies:
                    cookie_info = parse_set_cookie(raw)
                    result.cookies.append(cookie_info)

                    name = cookie_info["name"]
                    issues = []

                    # Check Secure flag
                    if not cookie_info["secure"]:
                        issues.append(("Secure", Severity.MEDIUM,
                                       "Cookie can be sent over unencrypted HTTP connections.",
                                       "Add the 'Secure' flag to this cookie."))

                    # Check HttpOnly flag
                    if not cookie_info["httponly"]:
                        issues.append(("HttpOnly", Severity.MEDIUM,
                                       "Cookie is accessible to JavaScript (XSS risk).",
                                       "Add the 'HttpOnly' flag to prevent JavaScript access."))

                    # Check SameSite attribute
                    samesite = cookie_info.get("samesite", "").lower()
                    if not samesite or samesite == "none":
                        issues.append(("SameSite", Severity.MEDIUM if samesite == "none" else Severity.LOW,
                                       "Cookie may be sent in cross-site requests (CSRF risk).",
                                       "Set SameSite to 'Lax' or 'Strict'."))

                    if issues:
                        for flag, severity, desc, rec in issues:
                            findings.append(Finding(
                                title=f"Cookie '{name}' Missing {flag} Flag",
                                severity=severity,
                                description=desc,
                                recommendation=rec
                            ))
                    else:
                        findings.append(Finding(
                            title=f"Cookie '{name}' Properly Secured",
                            severity=Severity.PASS,
                            description=f"Cookie '{name}' has Secure, HttpOnly, and SameSite attributes.",
                        ))

    except Exception as e:
        findings.append(Finding(
            title="Cookie Audit Failed",
            severity=Severity.INFO,
            description=f"Could not audit cookies: {str(e)}",
            recommendation="Ensure the target is reachable."
        ))

    result.findings = findings
    return result


def parse_set_cookie(raw: str) -> dict:
    """Parse a raw Set-Cookie header string into a dict."""
    parts = [p.strip() for p in raw.split(";")]
    name_val = parts[0].split("=", 1) if parts else ["", ""]
    name = name_val[0]
    value = name_val[1] if len(name_val) > 1 else ""

    cookie = {
        "name": name,
        "value": value[:20] + "..." if len(value) > 20 else value,  # Truncate for display
        "secure": False,
        "httponly": False,
        "samesite": "",
        "path": "",
        "domain": "",
        "max_age": "",
        "expires": "",
    }

    for part in parts[1:]:
        lower = part.lower()
        if lower == "secure":
            cookie["secure"] = True
        elif lower == "httponly":
            cookie["httponly"] = True
        elif lower.startswith("samesite="):
            cookie["samesite"] = part.split("=", 1)[1]
        elif lower.startswith("path="):
            cookie["path"] = part.split("=", 1)[1]
        elif lower.startswith("domain="):
            cookie["domain"] = part.split("=", 1)[1]
        elif lower.startswith("max-age="):
            cookie["max_age"] = part.split("=", 1)[1]
        elif lower.startswith("expires="):
            cookie["expires"] = part.split("=", 1)[1]

    return cookie
