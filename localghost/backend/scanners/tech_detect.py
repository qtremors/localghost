"""Technology fingerprinting scanner."""

import re

import aiohttp

from backend.models.scan import Finding, Severity, TechDetectResult
from backend.utils.http import decode_body, read_limited
from backend.utils.network import scanner_session

# Technology signatures detected from HTTP headers and response content
HEADER_SIGNATURES = {
    "Server": {
        "Apache": ("Apache", "Web Server"),
        "nginx": ("Nginx", "Web Server"),
        "Microsoft-IIS": ("Microsoft IIS", "Web Server"),
        "Kestrel": ("ASP.NET Kestrel", "Web Server"),
        "uvicorn": ("Uvicorn", "ASGI Server"),
        "gunicorn": ("Gunicorn", "WSGI Server"),
        "Werkzeug": ("Werkzeug", "WSGI Server"),
        "Cowboy": ("Cowboy (Erlang)", "Web Server"),
        "Caddy": ("Caddy", "Web Server"),
        "LiteSpeed": ("LiteSpeed", "Web Server"),
        "openresty": ("OpenResty", "Web Server"),
        "SimpleHTTP": ("Python http.server", "Web Server"),
        "Python": ("Python", "Language"),
    },
    "X-Powered-By": {
        "Express": ("Express.js", "Web Framework"),
        "PHP": ("PHP", "Language"),
        "ASP.NET": ("ASP.NET", "Web Framework"),
        "Next.js": ("Next.js", "Web Framework"),
        "Nuxt": ("Nuxt.js", "Web Framework"),
        "Django": ("Django", "Web Framework"),
        "Flask": ("Flask", "Web Framework"),
        "FastAPI": ("FastAPI", "Web Framework"),
        "Rails": ("Ruby on Rails", "Web Framework"),
        "Laravel": ("Laravel", "Web Framework"),
    },
}

# Content patterns in HTML responses
CONTENT_SIGNATURES = [
    (r"wp-content|wp-includes|wordpress", "WordPress", "CMS"),
    (r"drupal|Drupal\.settings", "Drupal", "CMS"),
    (r"joomla|com_content", "Joomla", "CMS"),
    (r"data-react(?:root|id)|__REACT_DEVTOOLS_GLOBAL_HOOK__|react(?:-dom)?(?:\.production|\.development|(?:\.min)?\.js)", "React", "JS Framework"),
    (r"__next|_next/static", "Next.js", "JS Framework"),
    (r"__nuxt|_nuxt", "Nuxt.js", "JS Framework"),
    (r"ng-app|ng-controller|angular", "Angular", "JS Framework"),
    (r"vue\.js|v-bind|v-if|__vue__", "Vue.js", "JS Framework"),
    (r"svelte", "Svelte", "JS Framework"),
    (r"jquery|jQuery", "jQuery", "JS Library"),
    (r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)", "Bootstrap", "CSS Framework"),
    (r"tailwindcss", "Tailwind CSS", "CSS Framework"),
]


async def detect_technologies(target_url: str) -> TechDetectResult:
    """Fingerprint technologies used by the target."""

    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"

    result = TechDetectResult()
    findings = []
    detected = set()

    try:
        timeout = aiohttp.ClientTimeout(total=8)
        async with scanner_session(timeout=timeout) as session:
            async with session.get(target_url, allow_redirects=False) as resp:
                result.http_status = resp.status
                if not 200 <= resp.status < 300:
                    result.status = 'error'
                    result.error = f'Target returned HTTP {resp.status}; app software could not be checked'
                    return result
                headers = resp.headers
                raw, _ = await read_limited(resp, 50000)
                body = decode_body(raw, resp.charset)

                # Check headers for technology signatures
                for header_name, signatures in HEADER_SIGNATURES.items():
                    header_val = headers.get(header_name, "")
                    for keyword, (tech_name, category) in signatures.items():
                        if keyword.lower() in header_val.lower():
                            if tech_name not in detected:
                                detected.add(tech_name)
                                version = extract_version(header_val, keyword)
                                result.technologies.append({
                                    "name": tech_name,
                                    "version": version,
                                    "category": category,
                                    "source": f"Header: {header_name}"
                                })

                # Check content/body for patterns
                body_lower = body[:50000]  # Only check first 50KB
                for pattern, tech_name, category in CONTENT_SIGNATURES:
                    if tech_name not in detected and re.search(pattern, body_lower, re.IGNORECASE):
                        detected.add(tech_name)
                        result.technologies.append({
                            "name": tech_name,
                            "version": "",
                            "category": category,
                            "source": "HTML Content"
                        })

                # Check common meta headers
                via = headers.get("Via", "")
                if via:
                    result.technologies.append({
                        "name": "Proxy/CDN",
                        "version": via,
                        "category": "Infrastructure",
                        "source": "Header: Via"
                    })

                # Generate findings
                if result.technologies:
                    tech_list = ", ".join(t["name"] for t in result.technologies)
                    findings.append(Finding(
                        title="Technologies Detected",
                        severity=Severity.INFO,
                        description=f"Detected: {tech_list}",
                        recommendation="Review if technology disclosures reveal unnecessary information."
                    ))
                else:
                    findings.append(Finding(
                        title="No Technologies Detected",
                        severity=Severity.INFO,
                        description="Could not fingerprint any specific technologies.",
                    ))

    except Exception as e:
        result.status = "error"
        result.error = "Technology detection could not read the target response"
        findings.append(Finding(
            title="Technology Detection Failed",
            severity=Severity.INFO,
            description=f"Could not perform tech detection: {str(e)}",
        ))

    result.findings = findings
    return result


def extract_version(header_value: str, keyword: str) -> str:
    """Try to extract version number from a header value."""
    pattern = rf"{re.escape(keyword)}\s*/?\s*([\d.]+)"
    match = re.search(pattern, header_value, re.IGNORECASE)
    return match.group(1) if match else ""
