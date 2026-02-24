"""CORS misconfiguration detection scanner."""

import aiohttp
from backend.models.scan import CORSScanResult, Finding, Severity


async def scan_cors(target_url: str) -> CORSScanResult:
    """Check for CORS misconfigurations."""

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    result = CORSScanResult()
    findings = []

    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            # Send a preflight-like request with a foreign Origin
            headers = {
                "Origin": "https://evil-attacker.com",
                "Access-Control-Request-Method": "GET",
            }

            async with session.options(target_url, headers=headers) as resp:
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
                acam = resp.headers.get("Access-Control-Allow-Methods", "")
                acah = resp.headers.get("Access-Control-Allow-Headers", "")

                result.allow_origin = acao
                result.allow_credentials = acac == "true"
                result.allow_methods = [m.strip() for m in acam.split(",") if m.strip()] if acam else []
                result.allow_headers = [h.strip() for h in acah.split(",") if h.strip()] if acah else []
                result.cors_enabled = bool(acao)

            # Also check with a regular GET
            async with session.get(target_url, headers={"Origin": "https://evil-attacker.com"}) as resp:
                get_acao = resp.headers.get("Access-Control-Allow-Origin", "")
                get_acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                if not result.cors_enabled and get_acao:
                    result.cors_enabled = True
                    result.allow_origin = get_acao
                    result.allow_credentials = get_acac == "true"

            # Analyze CORS configuration
            if not result.cors_enabled:
                findings.append(Finding(
                    title="No CORS Headers Detected",
                    severity=Severity.PASS,
                    description="The server does not send CORS headers, which is the most restrictive setting.",
                ))
            else:
                if result.allow_origin == "*":
                    if result.allow_credentials:
                        findings.append(Finding(
                            title="CORS: Wildcard Origin with Credentials",
                            severity=Severity.CRITICAL,
                            description="Access-Control-Allow-Origin is '*' AND Allow-Credentials is true. This is a dangerous misconfiguration.",
                            recommendation="Never combine wildcard origin with credentials. Specify explicit allowed origins."
                        ))
                    else:
                        findings.append(Finding(
                            title="CORS: Wildcard Origin",
                            severity=Severity.MEDIUM,
                            description="Access-Control-Allow-Origin is set to '*', allowing any origin to make requests.",
                            recommendation="Restrict CORS to specific trusted origins in production."
                        ))
                elif result.allow_origin == "https://evil-attacker.com":
                    findings.append(Finding(
                        title="CORS: Origin Reflection Detected",
                        severity=Severity.HIGH,
                        description="The server reflects back any Origin header, effectively acting as a wildcard.",
                        recommendation="Validate the Origin header against a whitelist of trusted domains."
                    ))
                else:
                    findings.append(Finding(
                        title="CORS: Specific Origin Configured",
                        severity=Severity.PASS,
                        description=f"CORS allows origin: {result.allow_origin}",
                    ))

    except Exception as e:
        findings.append(Finding(
            title="CORS Check Failed",
            severity=Severity.INFO,
            description=f"Could not perform CORS check: {str(e)}",
            recommendation="Ensure the target is reachable."
        ))

    result.findings = findings
    return result
