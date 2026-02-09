"""Recognize credential material locally; never contact a credential provider."""

import hashlib
import math
import re
from collections import Counter

from backend.utils.redaction import PROVIDER_PATTERNS, configured_secrets, register_secret

PRIVATE_NAME = re.compile(r'(?i)(?:^|_)(?:secret|password|passwd|private|api_?key|access_?token|auth_?token|database_url)(?:_|$)')
LITERAL = re.compile(r'''(?im)(?<![\w$.-])([A-Za-z_$][\w$.-]{0,127})\s*[:=]\s*(["'])([^\n"']{8,4096})\2''')
PLACEHOLDER = re.compile(r'(?i)example|placeholder|changeme|your[_-]|not[_-]a[_-]real|test[_-]only|dummy|replace[_-]me|\$\{|process\.env|import\.meta\.env')


def plausible(value):
    if len(value) < 8 or PLACEHOLDER.search(value) or set(value) <= {'*', 'x', 'X', '.', '-', '_'}:
        return False
    counts = Counter(value)
    entropy = -sum((count / len(value)) * math.log2(count / len(value)) for count in counts.values())
    return len(value) >= 16 and entropy >= 3


def private_name(name):
    # camelCase configuration names need the same treatment as ENV_NAMES.
    normalized = re.sub(r'([a-z])([A-Z])', r'\1_\2', name).replace('.', '_').replace('-', '_')
    return bool(PRIVATE_NAME.search(normalized))


def scan_text(source, *, include_assignments=True, configured_only=False, configure=False):
    matches = []
    seen = set()

    def add(kind, value, start, end, name=''):
        key = (start, end)
        if key in seen:
            return
        seen.add(key)
        register_secret(value, configured=configure)
        matches.append({'kind': kind, 'name': name, 'line': source[:start].count('\n') + 1,
                        'start': start, 'end': end, 'fingerprint': hashlib.sha256(value.encode()).hexdigest()[:16],
                        'length': len(value)})

    for value in configured_secrets():
        if len(value) < 8:
            continue
        # Supplied session headers are redacted separately and do not become "leaked source secrets".
        start = source.find(value)
        if start >= 0 and plausible(value):
            add('configured-secret', value, start, start + len(value))
    if configured_only:
        return matches
    for kind, pattern in PROVIDER_PATTERNS:
        for match in pattern.finditer(source):
            if kind == 'private-key' or plausible(match[0]):
                add(kind, match[0], match.start(), match.end())
    if include_assignments:
        for match in LITERAL.finditer(source):
            if private_name(match[1]) and plausible(match[3]):
                add('hardcoded-secret', match[3], match.start(3), match.end(3), match[1])
    return matches
