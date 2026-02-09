"""Check common security-header values without claiming full policy analysis."""

import re


def parse_csp(value):
    directives = {}
    for entry in value.split(';'):
        parts = entry.strip().split()
        if parts:
            directives.setdefault(parts[0].lower(), parts[1:])
    return directives


def has_frame_policy(value):
    sources = parse_csp(value).get('frame-ancestors', [])
    return bool(sources) and not any(source in ('*', 'http:', 'https:') for source in sources)


def check_header_value(name, value):
    """Return an accepted-value flag and a short explanation for failures."""
    value = value.strip()
    if not value:
        return False, 'The header is empty.'
    if name == 'Strict-Transport-Security':
        match = re.search(r'(?:^|;)\s*max-age\s*=\s*"?(\d+)"?(?:\s*;|\s*$)', value, re.I)
        return (True, '') if match and int(match[1]) > 0 else (False, 'HSTS needs a positive max-age. max-age=0 disables it.')
    if name == 'Content-Security-Policy':
        directives = parse_csp(value)
        scripts = directives.get('script-src-elem', directives.get('script-src', directives.get('default-src', [])))
        nonce = any(re.fullmatch(r"'(?:nonce-[A-Za-z0-9+/_=-]+|sha(?:256|384|512)-[A-Za-z0-9+/=_-]+)'", source) for source in scripts)
        if not scripts:
            return False, 'The policy does not restrict scripts with script-src or default-src.'
        if "'unsafe-inline'" in scripts and not nonce:
            return False, 'The script policy allows inline scripts without a nonce or hash.'
        if any(source in ('*', 'http:', 'https:', 'data:') for source in scripts) and not (nonce and "'strict-dynamic'" in scripts):
            return False, 'The script policy allows scripts from unrestricted sources.'
        if "'unsafe-eval'" in directives.get('script-src', directives.get('default-src', [])):
            return False, 'The script policy allows unsafe-eval.'
        return True, ''
    if name == 'X-Frame-Options':
        return (True, '') if value.upper() in ('DENY', 'SAMEORIGIN') else (False, 'Use DENY or SAMEORIGIN. Other values do not provide current browser protection.')
    if name == 'X-Content-Type-Options':
        return (True, '') if value.lower() == 'nosniff' else (False, 'The supported value is nosniff.')
    if name == 'Referrer-Policy':
        policies = {'no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin',
                    'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'unsafe-url'}
        selected = [part.strip().lower() for part in value.split(',') if part.strip().lower() in policies]
        if not selected:
            return False, 'No supported referrer policy was found.'
        if selected[-1] in ('unsafe-url', 'no-referrer-when-downgrade'):
            return False, 'The policy can send the full URL to other sites. Prefer strict-origin-when-cross-origin or no-referrer.'
        return True, ''
    if name == 'Permissions-Policy':
        restrictions = re.findall(r'(?:^|,)\s*[a-z][a-z-]*\s*=\s*(\([^)]*\)|\*)\s*(?=,|$)', value, re.I)
        return (True, '') if any(part != '*' for part in restrictions) else (False, 'No restricted browser features were found in this policy.')
    if name == 'Cross-Origin-Opener-Policy':
        return (True, '') if value in ('same-origin', 'same-origin-allow-popups', 'noopener-allow-popups') else (False, 'This value does not isolate the page from other origins.')
    return True, ''
