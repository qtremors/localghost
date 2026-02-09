"""Recognize likely file contents and distinguish dynamic HTML fallback pages."""

import json
import re
from html import escape

from backend.utils.http import decode_body


def _canonical(body, path):
    text = decode_body(body)
    for value in (path, escape(path), path.lstrip('/')):
        if value:
            text = text.replace(value, '<requested-path>')
    text = re.sub(r'\b[0-9a-f]{16,}\b', '<id>', text, flags=re.I)
    text = re.sub(r'\b[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b', '<id>', text, flags=re.I)
    text = re.sub(r'\b\d{10,}\b', '<timestamp>', text)
    return text


def classify_file(path, body, content_type, fallbacks, complete):
    text = decode_body(body)
    if not body:
        return False if complete else None
    # Positive evidence takes precedence even if a catch-all route leaks the same secret.
    if path.startswith('/.env') and re.search(r'^\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=', text, re.M):
        return True
    if path == '/.git/HEAD' and re.fullmatch(r'\s*(?:ref: refs/[^\s]+|[0-9a-f]{40,64})\s*', text, re.I):
        return True
    if path == '/.git/config' and re.search(r'^\s*\[(?:core|remote\s+"[^"\n]+")\]\s*$', text, re.M):
        return True
    if path.endswith('.sql') and re.search(r'(?im)^\s*(?:CREATE TABLE|INSERT INTO|DROP TABLE|-- (?:MySQL|PostgreSQL|SQLite))\b', text):
        return True
    if path == '/phpinfo.php' and re.search(r'PHP Version|phpinfo\(\)', text):
        return True
    if path == '/server-status' and 'Apache Server Status' in text:
        return True
    if path == '/.DS_Store' and body[4:8] == b'Bud1':
        return True
    canonical = _canonical(body, path)
    if any(canonical == _canonical(fallback, missing_path) for missing_path, fallback in fallbacks):
        return False
    if content_type in ('text/html', 'application/xhtml+xml') or re.match(r'\s*<(?:!doctype|html|head|body)\b', text, re.I):
        return False
    if not complete:
        return None
    if path.endswith('.json'):
        try:
            data = json.loads(text)
            if path == '/package.json':
                return isinstance(data, dict) and bool({'name', 'dependencies', 'scripts', 'version'} & data.keys())
            return isinstance(data, (dict, list)) and bool(data)
        except ValueError:
            return False
    if path.endswith(('.yml', '.yaml')) and re.search(r'^\s*[A-Za-z_][\w.-]*\s*:\s*', text, re.M):
        return True
    if path in ('/.npmrc', '/.htaccess') and re.search(r'^\s*(?:[\w/:.-]+\s*=|(?:Deny|Require|RewriteRule|AuthType|Options)\s+)', text, re.M | re.I):
        return True
    return None
