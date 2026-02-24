"""Technology fingerprinting scanner."""

import aiohttp
import re
from backend.models.scan import TechDetectResult, Finding, Severity


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
    (r"react", "React", "JS Framework"),
    (r"__next|_next/static", "Next.js", "JS Framework"),
    (r"__nuxt|_nuxt", "Nuxt.js", "JS Framework"),
    (r"ng-app|ng-controller|angular", "Angular", "JS Framework"),
    (r"vue\.js|v-bind|v-if|__vue__", "Vue.js", "JS Framework"),
    (r"svelte", "Svelte", "JS Framework"),
    (r"jquery|jQuery", "jQuery", "JS Library"),
    (r"bootstrap", "Bootstrap", "CSS Framework"),
    (r"tailwindcss|tailwind", "Tailwind CSS", "CSS Framework"),
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
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(target_url) as resp:
                headers = resp.headers
                body = await resp.text()

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
                        severity=Severity.PASS,
                        description="Could not fingerprint any specific technologies.",
                    ))

    except Exception as e:
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
