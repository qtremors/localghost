"""Turn module observations into stable, evidence-bearing report findings."""

import hashlib
from urllib.parse import urljoin

from backend.models.scan import Evidence, Finding, ScanResponse, Severity
from backend.services.fixes import add_fix_context
from backend.utils.evidence import safe_url

MODULES = ('vuln_scan', 'ssl_scan', 'cors_scan', 'cookie_scan', 'tech_detect', 'dns_scan',
           'source_scan', 'browser_check', 'ddos_test', 'rate_limit_test', 'xss_scan')


def prepare_findings(report: ScanResponse, *, link_files=True) -> list[Finding]:
    findings = []
    source = report.source_scan or {}
    config = source.get('config_file')
    for module in MODULES:
        value = getattr(report, module)
        data = value.model_dump() if hasattr(value, 'model_dump') else value or {}
        for raw in data.get('findings', []):
            finding = Finding.model_validate(raw)
            finding.module = module
            finding.location = finding.location or report.target
            finding.rule_id = finding.rule_id or f'{module}:{finding.title}'
            finding.recheckable = finding.severity != Severity.PASS
            if module == 'vuln_scan':
                for name, check in data.get('security_headers', {}).items():
                    if finding.title in (f'Missing {name}', f'{name} needs review'):
                        finding.rule_id = f'header:{name.lower()}'
                        finding.verification = 'review'
                        finding.evidence = [Evidence(url=report.target, status=data.get('http_status'),
                                                     observation=f'{name}: {check.get("value") or "not present"}'[:700])]
                        # A missing hardening header alone is not proof of an exploitable flaw.
                        finding.severity = Severity.LOW
                        if report.request.environment == 'development':
                            finding.description += ' This is a development response; check the deployed server before changing production settings.'
                        if config and source.get('framework') == 'Next.js':
                            finding.fix_file = config
                            finding.recommendation += f' For Next.js, configure response headers in {config}, or in the reverse proxy serving production.'
                            if name == 'X-Content-Type-Options':
                                finding.fix_example = "// Merge into the existing Next.js configuration.\nasync headers() {\n  return [{ source: '/(.*)', headers: [\n    { key: 'X-Content-Type-Options', value: 'nosniff' }\n  ] }];\n}"
                        elif config and source.get('framework') == 'Vite':
                            finding.fix_file = config
                            finding.recommendation += ' Vite development headers do not configure your production host. Set the header on the deployed web server.'
                if finding.title.startswith('Sensitive File Exposed: '):
                    path = finding.title.split(': ', 1)[1]
                    finding.rule_id = f'file:{path}'
                    finding.location = urljoin(report.target, path)
                    finding.verification = 'confirmed'
                    finding.severity = Severity.HIGH
                    if path not in ('/.env', '/.env.local', '/.env.production', '/.git/config', '/.git/HEAD', '/backup.sql', '/dump.sql', '/wp-config.php'):
                        finding.verification = 'review'
                        finding.severity = Severity.MEDIUM
                        finding.description += ' Public access may be intentional; inspect the file before treating it as a security problem.'
                    finding.evidence = [Evidence(url=finding.location, status=200,
                                                 observation='Response content matched the expected file format. Catch-all and error-page checks were applied. File contents were not saved.')]
                    finding.fix_file = path.lstrip('/')
                if finding.title.endswith('Failed'):
                    finding.verification = 'not_checked'
            elif module == 'cors_scan':
                finding.evidence = [Evidence(method=item['method'], url=report.target, status=item.get('status'),
                                             observation=f"Origin: {item['origin']}; Allow-Origin: {item.get('allow_origin') or 'not present'}; Allow-Credentials: {item.get('allow_credentials', False)}")
                                    for item in data.get('observations', [])]
                if config:
                    finding.fix_file = config
                finding.recommendation += ' Confirm whether this route contains private data and whether those origins are intended.'
            elif module == 'cookie_scan' and not any(item.captured for item in finding.evidence):
                for cookie in data.get('cookies', []):
                    if f"'{cookie['name']}'" in finding.title:
                        finding.evidence = [Evidence(url=report.target, status=data.get('http_status'),
                                                     observation=f"Cookie {cookie['name']}: Secure={cookie['secure']}; HttpOnly={cookie['httponly']}; SameSite={cookie['samesite'] or 'not set'}. Value redacted.")]
                if report.request.environment == 'development' and 'Secure' in finding.title:
                    finding.recommendation += ' Check this on HTTPS in the production build; local HTTP settings can differ.'
            elif module == 'ssl_scan':
                finding.evidence = [Evidence.model_validate(item) for item in data.get('evidence', [])] or [Evidence(method='TLS', url=report.target,
                                             observation=f"TLS available: {data.get('has_ssl')}; certificate trusted: {data.get('cert_valid')}; days until expiry: {data.get('days_until_expiry')}")]
            elif module == 'xss_scan':
                finding.verification = 'review'
                if not any(item.captured for item in finding.evidence):
                    finding.evidence = [Evidence(url=report.target, observation=f"{data.get('reflections_found', 0)} HTML reflections observed in {data.get('tests_run', 0)} probes. Browser execution was not tested.")]
            elif module == 'browser_check':
                # Multiple independent errors on the same page need independent identities.
                identity = finding.description.splitlines()[0] if finding.rule_id == 'browser.javascript' else finding.description
                finding.rule_id += ':' + hashlib.sha256(identity.encode()).hexdigest()[:12]
            if not finding.evidence:
                finding.evidence = [Evidence(method='OBSERVATION', url=finding.location,
                                             status=data.get('http_status'), observation=finding.description[:700])]
            captured_data = data.get('exchanges', data.get('evidence', []))
            captures = [Evidence.model_validate(item) for item in captured_data] if isinstance(captured_data, list) else []
            if captures:
                matching = [item for item in captures if item.url == safe_url(finding.location)]
                if module == 'cors_scan':
                    matching = [item for item in captures if item.url == safe_url(report.target)]
                if not matching and module in ('dns_scan', 'ddos_test', 'rate_limit_test'):
                    matching = captures
                if matching and not any(item.captured for item in finding.evidence):
                    finding.evidence = matching[:12]
            finding.affected_pages = list(dict.fromkeys(item.page_url for item in finding.evidence if item.page_url)) or ([report.target] if module != 'source_scan' else [])
            if module == 'source_scan':
                finding.fix_notes.append('This is a source observation. HTTP exposure and affected pages are reported separately when observed.')
            finding.id = hashlib.sha256(f'{module}|{finding.rule_id}|{finding.location}'.encode()).hexdigest()[:24]
            findings.append(finding)
    # An unavailable check must remain visible even if it emitted no finding.
    for module, state in report.module_status.items():
        if state not in ('partial', 'error') or any(f.module == module and f.verification == 'not_checked' for f in findings):
            continue
        findings.append(Finding(id=hashlib.sha256(f'{module}:incomplete'.encode()).hexdigest()[:24],
                                module=module, rule_id=f'{module}:incomplete', title='Check could not complete',
                                severity=Severity.INFO, verification='not_checked', location=report.target,
                                recheckable=True,
                                description=report.errors.get(module, 'Some observations were unavailable.'),
                                recommendation='Review the check details, correct the connection or setup, and run it again.'))
    if report.request.environment == 'production':
        for route, modules in report.route_results.items():
            for observation in modules.get('vuln_scan', {}).get('runtime_observations', []):
                if observation.get('development_markers'):
                    rule = 'web.development-build'
                    findings.append(Finding(id=hashlib.sha256(f'vuln_scan|{rule}|{route}'.encode()).hexdigest()[:24], rule_id=rule,
                                            module='vuln_scan', title='Development server used for a production check',
                                            severity=Severity.MEDIUM, verification='confirmed', location=route, affected_pages=[route], recheckable=True,
                                            description='The HTML includes a known development-server script.',
                                            recommendation='Run the production build and serve its output. For Next.js use build then start; for Vite use build then preview or your production web server.',
                                            fix_file='package.json', evidence=[Evidence.model_validate(item) for item in modules['vuln_scan'].get('evidence', []) if item['url'] == safe_url(route)][:1]))
        for page in (report.browser_check or {}).get('pages', []):
            markers = page.get('development_markers', [])
            if not markers:
                continue
            if page['url'] in report.route_results and any(item.get('development_markers') for item in report.route_results[page['url']].get('vuln_scan', {}).get('runtime_observations', [])):
                continue
            rule = 'browser.development-build'
            findings.append(Finding(id=hashlib.sha256(f'browser_check|{rule}|{page["url"]}'.encode()).hexdigest()[:24],
                                    rule_id=rule, module='browser_check', title='Development script in a production check',
                                    severity=Severity.MEDIUM, verification='confirmed', location=page['url'], recheckable=True,
                                    description='This page includes a development-server script, although this scan was marked as a production build.',
                                    recommendation='Build the app and run its production server or preview, then check that URL again.',
                                    fix_file='package.json' if source.get('framework') in ('Next.js', 'Vite') else '',
                                    evidence=[Evidence.model_validate({**page.get('document_evidence', {}), 'url': page['url'], 'status': page['status'], 'observation': f'Development script: {marker}'}) for marker in markers]))
    # Server audits have independent results and evidence for every selected route.
    for url, modules in report.route_results.items():
        if url == report.target:
            continue
        fields = {key: None for key in MODULES}
        fields.update(modules)
        fields['source_scan'] = {**source, 'findings': []} if source else None
        states = {key: data.get('status', 'success') for key, data in modules.items()}
        child = report.model_copy(update={**fields, 'target': url, 'route_results': {}, 'module_status': states,
                                         'errors': {key: data.get('error') or 'Route check was incomplete.' for key, data in modules.items() if states[key] != 'success'}})
        findings.extend(prepare_findings(child, link_files=False))
    unique = {}
    for finding in findings:
        if finding.id not in unique:
            unique[finding.id] = finding
            continue
        previous = unique[finding.id]
        previous.affected_pages = list(dict.fromkeys([*previous.affected_pages, *finding.affected_pages]))
        for item in finding.evidence:
            if item not in previous.evidence and len(previous.evidence) < 12:
                previous.evidence.append(item)
    priority = {'confirmed': 0, 'review': 1, 'not_checked': 2}
    severity = list(Severity)
    values = add_fix_context(list(unique.values()), source) if link_files else list(unique.values())
    return sorted(values, key=lambda finding: (priority[finding.verification], severity.index(finding.severity)))
