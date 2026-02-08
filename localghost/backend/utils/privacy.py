"""Remove cookie contents from stored reports and report downloads."""

from backend.utils.redaction import SCHEMA_FIELDS


def redact_cookie_values(report):
    changed = False
    cookies = (report.get('cookie_scan') or {}).get('cookies', [])
    for cookie in cookies:
        if 'value' in cookie and cookie['value'] != '[redacted]':
            cookie['value'] = '[redacted]'
            changed = True
    return changed


def redact_session_values(report, headers):
    """Remove supplied credentials if a target reflects them in report evidence."""
    values = set(headers.values())
    for key, value in headers.items():
        if key.lower() == 'cookie':
            values.update(part.split('=', 1)[1].strip() for part in value.split(';') if '=' in part)
        elif key.lower() == 'authorization' and ' ' in value:
            values.add(value.split(' ', 1)[1])
    values.discard('')

    def clean(value, field=''):
        if isinstance(value, str):
            if field in SCHEMA_FIELDS:
                return value
            for secret in sorted(values, key=len, reverse=True):
                if len(secret) >= 4:
                    value = value.replace(secret, '[redacted]')
                elif value == secret:
                    value = '[redacted]'
            return value
        if isinstance(value, list):
            return [clean(item, field) for item in value]
        if isinstance(value, dict):
            return {key: clean(item, key) for key, item in value.items()}
        return value

    return clean(report)
