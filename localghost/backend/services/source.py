"""Read project files without executing code; credential values never leave memory."""

import difflib
import hashlib
import json
import os
import re
from contextlib import nullcontext
from pathlib import Path

from backend.models.scan import Finding, Severity
from backend.services.javascript import config_settings, router_paths
from backend.services.secrets import plausible, private_name, scan_text
from backend.utils.evidence import source_evidence
from backend.utils.redaction import has_inventory, private_values, redact_data, redact_text, register_secret

EXCLUDED = {'.git', '.next', 'node_modules', 'dist', 'build', '.venv', 'venv', '__pycache__', '.turbo', 'coverage'}
CONFIGS = ('next.config.js', 'next.config.mjs', 'next.config.ts', 'vite.config.js', 'vite.config.ts',
           'vite.config.mjs', 'package.json', 'Dockerfile', 'compose.yml', 'compose.yaml', 'docker-compose.yml', 'docker-compose.yaml')
MAX_FILES = 1500
MAX_BYTES = 262144


def inspect_source(source_path: str) -> dict:
    with nullcontext() if has_inventory() else private_values():
        return redact_data(_inspect_source(source_path))


def _inspect_source(source_path: str) -> dict:
    root = Path(source_path).expanduser()
    if not root.is_absolute() or not root.is_dir():
        raise ValueError('Source folder must be an existing absolute path on the machine running Localghost')
    if root.is_symlink():
        raise ValueError('Choose the real source folder, rather than a symbolic link')
    root = root.resolve()
    files, warnings = [], []
    directories = 0
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=lambda error: warnings.append('A folder could not be read.')):
        directories += 1
        if directories > 500:
            warnings.append('Only the first 500 folders were considered. Choose a narrower source folder.')
            break
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED and not (Path(directory) / name).is_symlink())
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink() or not path.is_file():
                continue
            files.append(path.relative_to(root).as_posix())
            if len(files) >= MAX_FILES:
                warnings.append(f'Only the first {MAX_FILES} files were considered. Add a narrower source folder for a larger project.')
                break
        if len(files) >= MAX_FILES:
            break
    known = set(files)
    content = {}
    for name in CONFIGS:
        path = root / name
        if name in known:
            try:
                with path.open('rb') as handle:
                    data = handle.read(MAX_BYTES + 1)
                if len(data) > MAX_BYTES:
                    warnings.append(f'{name} was too large to inspect.')
                else:
                    content[name] = data.decode('utf-8', errors='replace')
            except OSError:
                warnings.append(f'{name} could not be read.')
    package = {}
    if 'package.json' in content:
        try:
            package = json.loads(content['package.json'])
            if not isinstance(package, dict):
                raise ValueError('Package metadata is not an object')
        except ValueError:
            warnings.append('package.json could not be parsed.')
            package = {}
    dependencies = {}
    for key in ('dependencies', 'devDependencies'):
        if isinstance(package.get(key), dict):
            dependencies.update(package[key])
        elif key in package:
            warnings.append(f'package.json {key} is not an object.')
    framework = 'Next.js' if 'next' in dependencies else 'Vite' if 'vite' in dependencies else 'React' if 'react' in dependencies else 'HTML/JavaScript' if any(name.endswith('.html') for name in files) else 'Unknown'
    config = next((name for name in content if name.startswith('next.config' if framework == 'Next.js' else 'vite.config')), '')
    routes = []
    dynamic = []
    unresolved_routes = []
    source_contents = {}
    total_bytes = 0
    source_warnings = []
    for name in files:
        if not name.endswith(('.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.html', '.json', '.py', '.pem', '.key')) and not Path(name).name.startswith('.env'):
            continue
        if total_bytes >= 16 * 1024 * 1024 or len(source_contents) >= 400:
            source_warnings.append('Source inspection reached its 400-file or 16 MiB limit. Some files were not checked.')
            break
        path = root / name
        try:
            limit = min(MAX_BYTES, 16 * 1024 * 1024 - total_bytes)
            if path.stat().st_size > limit:
                source_warnings.append(f'{name} exceeded the per-file limit.')
                continue
            with path.open('rb') as handle:
                body = handle.read(limit + 1)
            if len(body) > limit:
                source_warnings.append(f'{name} exceeded the read limit.')
                continue
            total_bytes += len(body)
            source_contents[name] = body.decode('utf-8', errors='replace')
        except OSError:
            source_warnings.append(f'{name} could not be read.')
    secret_sources = []
    # Environment values are used only as a local comparison inventory.
    for name, body in source_contents.items():
        if Path(name).name.startswith('.env'):
            for line_number, line in enumerate(body.splitlines(), 1):
                key, separator, value = line.strip().removeprefix('export ').partition('=')
                value = value.strip().strip('\"\'')
                if separator and private_name(key.strip()) and plausible(value):
                    register_secret(value, configured=True)
                    secret_sources.append({'name': key.strip(), 'file': name, 'line': line_number,
                                           'fingerprint': hashlib.sha256(value.encode()).hexdigest()[:16]})
    warnings.extend(source_warnings)
    for name in files:
        route = None
        if framework == 'Next.js':
            match = re.match(r'(?:src/)?app/(.*?)(?:/)?(?:page|route)\.(?:[jt]sx?|mdx)$', name)
            pages = re.match(r'(?:src/)?pages/(.+)\.(?:[jt]sx?|mdx)$', name)
            if match:
                parts = [part for part in match[1].split('/') if part and not part.startswith(('(', '@'))]
                route = '/' + '/'.join(parts)
            elif pages and not pages[1].startswith('_'):
                route = '/' + pages[1].removesuffix('/index')
                if route == '/index':
                    route = '/'
        elif name.endswith('.html') and not name.startswith('.'):
            route = '/' + name
        if route:
            if '[' in route:
                dynamic.append({'file': name, 'route': route, 'parameters': [first or second for first, second in re.findall(r'\[\[?\.\.\.(\w+)\]\]?|\[(\w+)\]', route)]})
            else:
                routes.append({'file': name, 'path': route})
    for name, body in source_contents.items():
        if name.endswith(('.js', '.jsx', '.ts', '.tsx')) and 'react-router' in body:
            found, unresolved = router_paths(body, name)
            unresolved_routes.extend(unresolved)
            for route in found:
                if ':' in route['path'] or '*' in route['path']:
                    dynamic.append({**route, 'route': route['path'], 'parameters': re.findall(r':([\w]+)|\*', route['path'])})
                else:
                    routes.append(route)
    routes = list({route['path']: route for route in routes}.values())
    findings = []
    settings = []

    def add(rule, title, file, description, recommendation, line=None, replacement=None, setting=None, severity=Severity.MEDIUM):
        body = source_contents.get(file, content.get(file, ''))
        excerpt = body.splitlines()[line - 1] if line and line <= len(body.splitlines()) else ''
        patch = ''
        if replacement is not None and setting and setting.get('patch_safe'):
            encoded = body.encode()
            edited = encoded[:setting['start']] + replacement.encode() + encoded[setting['end']:]
            patch = ''.join(difflib.unified_diff(redact_text(body).splitlines(keepends=True), redact_text(edited.decode()).splitlines(keepends=True), fromfile=file, tofile=file))
        findings.append(Finding(rule_id=rule, title=title, severity=severity, location=file,
                                description=description, recommendation=recommendation, fix_file=file, fix_line=line, fix_diff=patch,
                                evidence=[source_evidence(file, line, excerpt, description)]).model_dump())

    if config:
        settings, parse_error = config_settings(content[config], config)
        if parse_error:
            warnings.append(f'{config} contains syntax the parser could not fully read.')
        rules = {
            'typescript.ignoreBuildErrors': ('source.next.ignore-build-errors', 'Production builds ignore TypeScript errors', 'Remove this override or set it to false, then run your production build.', 'false'),
            'server.cors': ('source.vite.cors', 'Development server allows any origin', 'Remove broad CORS access or list the specific frontend origins that need it.', 'false'),
            'productionBrowserSourceMaps': ('source.next.source-maps', 'Production browser source maps are enabled', 'Decide whether publishing source maps is intended. Source maps alone do not prove a vulnerability.', 'false'),
            'server.hmr.overlay': ('source.vite.overlay', 'Development error overlay is configured', 'Use the production build when sharing the app. Development error details can expose source paths.', None),
        }
        for setting in settings:
            rule = rules.get(setting['key'])
            if rule and setting['known']['production' if setting['key'] != 'server.cors' else 'development'] and setting['production' if setting['key'] != 'server.cors' else 'development'] is True:
                add(rule[0], rule[1], config, f"{setting['key']} is enabled in the {'development server' if setting['key'].startswith('server.') else 'production configuration'}.", rule[2], setting['line'], rule[3], setting)
        for setting in settings:
            if not setting['known']['production'] and setting['key'] in rules:
                warnings.append(f"{config}:{setting['line']}: {setting['key']} is computed from values that could not be evaluated safely.")
    # High-confidence credential formats and named hardcoded secrets; values are never returned.
    for name, body in source_contents.items():
        if Path(name).name.startswith('.env'):
            continue
        for match in scan_text(body, configure=True):
            kind = match['kind']
            label = match['name'] or kind
            secret_sources.append({'name': label, 'file': name, 'line': match['line'], 'fingerprint': match['fingerprint']})
            add(f'source.secret:{kind}:{label}', 'Possible credential in source', name,
                f"A {kind} value was found in {name}. Its validity was not tested. The value is redacted.",
                'Move server credentials into a private environment variable, remove the literal from source and built client files, and rotate it if it has been shared.',
                match['line'], severity=Severity.HIGH)
    # Python development/debug settings are relevant even for generic HTTP projects.
    for name, body in source_contents.items():
        if not name.endswith('.py'):
            continue
        try:
            import ast
            parsed = ast.parse(body)
            for node in ast.walk(parsed):
                if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'DEBUG' for target in node.targets) and isinstance(node.value, ast.Constant) and node.value.value is True:
                    add('source.python.debug', 'Debug mode is enabled in source', name, 'DEBUG is assigned True in this Python file.', 'Read DEBUG from the deployment environment and set it to False in production.', node.lineno)
                if isinstance(node, ast.Call):
                    for keyword in node.keywords:
                        if keyword.arg == 'debug' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                            add('source.python.debug', 'Debug mode is enabled in source', name, 'A server call explicitly enables debug=True.', 'Set debug=False for production and use the framework production server.', keyword.lineno)
        except SyntaxError:
            warnings.append(f'{name} could not be parsed for Python debug settings.')
    for name in files:
        if name.startswith(('public/', 'static/')) and (Path(name).name.startswith('.env') or '/.git/' in name):
            add('source.public-private-file', 'Private file is inside a public folder', name,
                f'{name} is in a folder commonly served as static content. HTTP exposure has not been proven.',
                'Move this file outside the public folder. Check the corresponding URL, and rotate credentials if it was served.')
    production_assets = []
    build_bytes = 0
    build_files = 0
    build_directories = 0
    for build_root, url_prefix in (('dist', ''), ('build', ''), ('.next/static', '/_next/static')):
        folder = root / build_root
        if not folder.is_dir() or folder.is_symlink():
            continue
        for directory, dirs, names in os.walk(folder, followlinks=False):
            build_directories += 1
            if build_directories > 500:
                warnings.append('Build inspection reached its 500-folder limit.')
                break
            dirs[:] = sorted(name for name in dirs if not (Path(directory) / name).is_symlink())
            for filename in sorted(names):
                path = Path(directory) / filename
                if path.is_symlink() or path.suffix not in ('.js', '.json', '.html', '.css', '.map'):
                    continue
                if build_files >= 150 or build_bytes >= 32 * 1024 * 1024:
                    break
                name = path.relative_to(root).as_posix()
                try:
                    limit = min(2 * 1024 * 1024, 32 * 1024 * 1024 - build_bytes)
                    with path.open('rb') as handle:
                        body = handle.read(limit + 1)
                except OSError:
                    warnings.append(f'{name} could not be read.')
                    continue
                build_files += 1
                complete = len(body) <= limit
                body = body[:limit]
                build_bytes += len(body)
                if not complete:
                    warnings.append(f'{name} exceeded the build-file limit; only the beginning was checked.')
                production_assets.append({'file': name, 'url_path': url_prefix + '/' + path.relative_to(folder).as_posix(),
                                          'sha256': hashlib.sha256(body).hexdigest() if complete else None})
                decoded = body.decode('utf-8', errors='replace')
                for match in scan_text(decoded):
                    findings.append(Finding(rule_id=f"source.build-secret:{match['kind']}", title='Possible credential in built client files',
                                            severity=Severity.HIGH, location=name, fix_file=name, fix_line=match['line'],
                                            description=f"A {match['kind']} value is in a built file. The value is redacted; HTTP exposure is checked separately.",
                                            recommendation='Find the source that inserts this value into the client build, move secret-dependent work to the server, rebuild, and rotate exposed credentials.',
                                            evidence=[source_evidence(name, match['line'], decoded.splitlines()[match['line'] - 1][:1800], 'Credential-like material in build output.')]).model_dump())
            if build_files >= 150 or build_bytes >= 32 * 1024 * 1024:
                warnings.append('Build inspection reached its 150-file or 32 MiB limit. Some build files were not checked.')
                break
    scripts = package.get('scripts') if isinstance(package.get('scripts'), dict) else {}
    start_script = scripts.get('start', '')
    if isinstance(start_script, str) and re.search(r'--inspect(?:-brk)?(?:\b|=)|--debug\b|\bnext\s+dev\b', start_script):
        line = next((number for number, text in enumerate(content.get('package.json', '').splitlines(), 1) if '"start"' in text), 1)
        add('source.start-debug', 'Start command uses development or debugger settings', 'package.json',
            'The start script includes a development server or debugger option. Check whether this command is used in production.',
            'Use the framework production start command and remove debugger flags from the deployed process.', line)
    for finding in findings:
        if finding['rule_id'] == 'source.next.ignore-build-errors':
            finding['fix_example'] = '// Merge into your existing Next.js configuration.\ntypescript: { ignoreBuildErrors: false }'
        elif finding['rule_id'] == 'source.vite.cors':
            finding['fix_example'] = '// Remove broad CORS access, or define the specific origins you need.\nserver: { cors: false }'
    return {'status': 'partial' if warnings else 'success', 'error': '; '.join(warnings) or None,
            'root': str(root), 'name': package['name'][:120] if isinstance(package.get('name'), str) else root.name,
            'framework': framework, 'config_file': config, 'config_files': list(content),
            'routes': routes[:100], 'dynamic_routes': dynamic[:50], 'files_considered': len(files),
            'scripts': [name for name in ('dev', 'build', 'start', 'preview', 'test', 'lint') if name in scripts],
            'docker': any(Path(name).name in ('Dockerfile', 'compose.yml', 'compose.yaml', 'docker-compose.yml', 'docker-compose.yaml') for name in files),
            'warnings': warnings, 'findings': findings, 'settings': [{key: value for key, value in setting.items() if key not in ('start', 'end')} for setting in settings],
            'unresolved_routes': unresolved_routes, 'source_files_checked': len(source_contents), 'source_bytes_checked': total_bytes,
            'source_files': list(source_contents), 'secret_sources': secret_sources, 'production_assets': production_assets, 'build_files_checked': build_files,
            'limitations': ['Configuration is read as text and is not executed.',
                            'Dynamic routes need a real path before they can be tested.',
                            'Only the listed configuration and credential rules were checked; dependency vulnerabilities and general code correctness were not audited.']}
