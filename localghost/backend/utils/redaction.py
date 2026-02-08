"""One task-local secret inventory for source, HTTP, browser, and exported evidence."""

import re
from contextlib import contextmanager
from contextvars import ContextVar
from enum import Enum

_values: ContextVar[set[str] | None] = ContextVar('localghost_private_values', default=None)
_configured: ContextVar[set[str] | None] = ContextVar('localghost_configured_secrets', default=None)
# These are scanner schema values, never reflected response content. A cookie
# such as security=low must not corrupt the severity or lifecycle enums.
SCHEMA_FIELDS = {'severity', 'verification', 'status', 'state', 'module', 'rule_id', 'id', 'scan_id',
                 'finding_id', 'scanner_version', 'method', 'type', 'environment', 'requested', 'observed', 'framework'}
SELECTORS = {'username_selector', 'password_selector', 'submit_selector', 'success_selector', 'check_selector'}
PROVIDER_PATTERNS = (
    ('private-key', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ('github-token', re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b')),
    ('stripe-secret', re.compile(r'\b(?:sk|rk)_live_[A-Za-z0-9]{20,255}\b')),
    ('slack-token', re.compile(r'\bxox[baprs]-[A-Za-z0-9-]{20,255}\b')),
    ('google-api-key', re.compile(r'\bAIza[A-Za-z0-9_-]{35}\b')),
)
ASSIGNMENT = re.compile(r'''(?im)(?<![\w.-])(["']?[\w.-]{0,100}(?:password|passwd|secret|private_key|api_key|apikey|token)[\w.-]{0,100}["']?\s*[:=]\s*)(["']?)([^\s"',;<>}{]{4,})(["']?)''')


@contextmanager
def private_values(values=()):
    token = _values.set({value for value in values if value})
    configured_token = _configured.set(set())
    try:
        yield
    finally:
        _values.reset(token)
        _configured.reset(configured_token)


def register_secret(value, *, configured=False):
    inventory = _values.get()
    if inventory is not None and value:
        inventory.add(value)
    configured_inventory = _configured.get()
    if configured and configured_inventory is not None and value:
        configured_inventory.add(value)


def known_secrets():
    return frozenset(_values.get() or ())


def configured_secrets():
    return frozenset(_configured.get() or ())


def has_inventory():
    return _values.get() is not None


def redact_text(text, *, assignments=True):
    text = text.value if isinstance(text, Enum) else str(text)
    for value in sorted(known_secrets(), key=len, reverse=True):
        if len(value) >= 4:
            text = text.replace(value, '[redacted]')
        elif text == value:
            text = '[redacted]'
    for _, pattern in PROVIDER_PATTERNS:
        text = pattern.sub('[redacted credential]', text)
    text = re.sub(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?(?:-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|$)', '[redacted private key]', text)
    return ASSIGNMENT.sub(lambda match: match[0] if match[3].startswith(('process.env.', 'import.meta.env.', 'os.environ', '[redacted]')) else match[1] + match[2] + '[redacted]' + match[4], text) if assignments else text


def redact_data(value, field=''):
    if isinstance(value, str):
        if field in SCHEMA_FIELDS or field in SELECTORS and value in ('input[name="username"]', 'input[type="password"]', 'button[type="submit"]'):
            return value.value if isinstance(value, Enum) else value
        return redact_text(value, assignments=field in ('source_excerpt', 'response_body_excerpt', 'request_body', 'description', 'observation', 'fix_diff', 'fix_example'))
    if isinstance(value, list):
        return [redact_data(item, field) for item in value]
    if isinstance(value, dict):
        return {(redact_text(key, assignments=False) if field == 'route_results' else key): redact_data(item, key) for key, item in value.items()}
    return value
