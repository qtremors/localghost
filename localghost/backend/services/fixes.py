"""Connect observed problems to known project files and reviewable fix examples."""

import re
from urllib.parse import unquote, urlsplit


def route_file(source, url):
    parsed = urlsplit(url)
    path = '/#' + parsed.fragment if parsed.fragment.startswith('/') else parsed.path or '/'
    for route in source.get('routes', []):
        if route['path'] == path:
            return route
    for route in source.get('dynamic_routes', []):
        tokens = re.split(r'(\[\[?\.\.\.[^]]+\]\]?|\[[^]]+\]|:[A-Za-z_][\w]*|\*)', route['route'])
        pattern = ''.join('.*' if token == '*' or token.startswith('[[...') else '.+' if token.startswith('[...') else '[^/]+' if token.startswith(('[', ':')) else re.escape(token) for token in tokens)
        if re.fullmatch(pattern, path):
            return route
    return None


def add_fix_context(findings, source):
    files = set(source.get('source_files', []))
    framework = source.get('framework')
    for finding in findings:
        if finding.verification == 'not_checked' or finding.severity.value in ('pass', 'info'):
            continue
        route = route_file(source, finding.location)
        if finding.module == 'browser_check' and finding.rule_id.startswith('browser.javascript'):
            for match in re.finditer(r'(?:https?://[^\s)]+|webpack[^\s)]+):(\d+):(\d+)', finding.description):
                frame = unquote(match.group(0)).split('?', 1)[0]
                linked = next((file for file in sorted(files, key=len, reverse=True) if file in frame), None)
                if linked:
                    finding.fix_file, finding.fix_line = linked, int(match.group(1))
                    finding.fix_notes.append('The file and line come from the observed stack. A transformed bundle may need its source map to locate the original line.')
                    break
        if not finding.fix_file and route and finding.module in ('browser_check', 'cors_scan', 'cookie_scan', 'vuln_scan'):
            finding.fix_file = route['file']
            finding.fix_line = route.get('line')
            finding.fix_notes.append('This file defines the affected route. Middleware or a proxy may also affect its response.')
        if finding.rule_id.startswith('file:'):
            relative = finding.rule_id[5:].lstrip('/')
            linked = next((name for name in (f'public/{relative}', f'static/{relative}', relative) if name in files), None)
            if linked:
                finding.fix_file = linked
            finding.recommendation = f"Remove {relative} from the web server's public files and deny HTTP access to it. Keep required configuration outside the served folder. Rotate any credentials that were accessible, then check this exact URL again."
        elif finding.module == 'cookie_scan':
            name = finding.title.split("'")[1] if "'" in finding.title else 'session'
            finding.recommendation += f" Change the code or middleware that sets the {name} cookie; the captured Set-Cookie header shows the current attributes."
            finding.fix_notes.append('Apply HttpOnly to cookies that JavaScript does not need. Cross-site sign-in may require SameSite=None with Secure; confirm the intended login flow.')
            if framework == 'Next.js':
                finding.fix_example = "// Merge these attributes into the existing cookie setter.\nresponse.cookies.set('" + name.replace("'", '') + "', sessionValue, {\n  httpOnly: true, secure: process.env.NODE_ENV === 'production',\n  sameSite: 'lax', path: '/'\n});"
            else:
                finding.fix_example = 'Set-Cookie: ' + name + '=<existing-value>; Path=/; HttpOnly; Secure; SameSite=Lax'
        elif finding.module == 'cors_scan':
            finding.recommendation += ' Check the captured Origin request against the returned Access-Control-Allow-Origin and Access-Control-Allow-Credentials headers. Use an explicit origin allowlist for private responses, or remove CORS if no other origin needs this route.'
            finding.fix_example = "// Example origin decision inside the existing CORS middleware.\nconst allowedOrigins = new Set(['https://your-frontend.example']);\nif (allowedOrigins.has(request.headers.get('origin'))) {\n  // Return that exact origin and Vary: Origin.\n}\n// Never reflect an arbitrary origin for credentialed private responses."
        elif finding.rule_id.startswith('browser.http'):
            finding.recommendation = f"Open {finding.location} with the same session and inspect the server log for the captured status. Check the route handler and the request URL used by the affected page. Fix the server error or path, then use Check again."
        elif finding.rule_id.startswith('browser.javascript'):
            finding.recommendation = 'Use the captured exception and script request to locate the failing expression. Fix the error at the linked file/line when available, rebuild if needed, then check the same page with the same session.'
        if finding.fix_diff:
            finding.fix_notes.append('Review this patch against your current file before applying it. Localghost does not change project files.')
        elif finding.fix_example:
            finding.fix_notes.append('This is an example to merge into the existing code, not an automatic edit.')
    return findings
