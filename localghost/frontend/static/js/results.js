/**
 * Result rendering — tabs, finding cards, port tables, benchmark stats.
 */

import { severityIcon, escapeHtml } from './utils.js';
import { MODULES } from './config.js';
import { evidenceHTML } from './evidence.js';
import { ACTIONABLE, SEVERITIES, collectFindings, countSeverities, filterFindings as selectFindings } from './findings.js';

/** Render all result tabs from scan data */
export function renderResults(data) {
    currentReportData = data;
    initCopyRecommendations();
    renderQuickStats(data);
    renderAllFindings(data);
    renderAssessmentOverview(data);
    renderSource(data.source_scan);
    renderPages(data.browser_check);
    renderRouteChecks(data);
    const resultFor = key => !data[key] ? null : Array.isArray(data.findings)
        ? { ...data[key], findings: data.findings.filter(f => f.module === key).map(f => ({ ...f, recheckable: false })) }
        : data[key];
    renderPorts(data.port_scan);
    renderHeaders(resultFor('vuln_scan'));
    renderSSL(resultFor('ssl_scan'));
    renderCORS(resultFor('cors_scan'));
    renderCookies(resultFor('cookie_scan'));
    renderTech(resultFor('tech_detect'));
    renderDNS(resultFor('dns_scan'));
    renderBenchmark(data.benchmark);
    renderDDoS(resultFor('ddos_test'));
    renderRateLimit(resultFor('rate_limit_test'));
    renderXSS(resultFor('xss_scan'));
    if (data.xss_scan) document.getElementById('panel-xss').insertAdjacentHTML('afterbegin', '<p class="config-note scope-note">These checks look for reflected HTML in server responses. They do not execute injected scripts or test stored input.</p>');
    const panels = {
        source: 'source_scan', browser: 'browser_check', ports: 'port_scan', headers: 'vuln_scan', ssl: 'ssl_scan', cors: 'cors_scan',
        cookies: 'cookie_scan', tech: 'tech_detect', dns: 'dns_scan', benchmark: 'load_test',
        ddos: 'ddos_test', ratelimit: 'rate_limit_test', xss: 'xss_scan',
    };
    for (const [tab, key] of Object.entries(panels)) {
        const result = data[key === 'load_test' ? 'benchmark' : key];
        const state = data.module_status?.[key] || (result ? 'success' : 'skipped');
        const button = document.querySelector(`[data-tab="${tab}"]`);
        button.dataset.status = state;
        button.title = `${button.textContent.trim()}: ${state === 'skipped' ? 'not run' : state}`;
        button.setAttribute('aria-label', button.title);
        const hasDiagnostics = result?.probe_coverage || result?.observations?.length || (key === 'port_scan' && result?.inconclusive_ports);
        if (state === 'skipped' || (state === 'error' && !hasDiagnostics)) {
            document.getElementById(`panel-${tab}`).innerHTML = emptyPanel('info',
                state === 'error' ? data.errors?.[key] || 'This check could not complete. Try scanning again.' : 'This module was not selected for this scan.');
        }
        if (result?.probe_coverage) {
            const coverage = result.probe_coverage;
            document.getElementById(`panel-${tab}`).insertAdjacentHTML('afterbegin', `
                <div class="probe-coverage" role="group" aria-label="Probe coverage">
                    <div><strong>${escapeHtml(coverage.attempted)}</strong><span>Attempted</span></div>
                    <div><strong>${escapeHtml(coverage.completed)}</strong><span>Completed</span></div>
                    <div class="${coverage.inconclusive ? 'probe-inconclusive' : ''}"><strong>${escapeHtml(coverage.inconclusive)}</strong><span>Inconclusive</span></div>
                </div>${state !== 'success' ? `<p class="probe-note">${escapeHtml(data.errors?.[key] || result.error || 'Some probes could not be assessed.')}</p>` : ''}`);
        }
    }
}

function renderQuickStats(data) {
    // Collect all findings
    const allFindings = collectFindings(data);
    const criticalCount = allFindings.filter(f => f.severity === 'critical').length;
    const portsCount = data.port_scan?.open_ports?.length ?? '—';
    const techCount = data.tech_detect?.status === 'error' ? '—' : data.tech_detect?.technologies?.length ?? '—';

    setText('stat-findings', allFindings.filter(f => f.severity !== 'pass').length);
    setText('stat-ports', portsCount);
    setText('stat-critical', criticalCount);
    setText('stat-tech', techCount);
}

let currentReportData;
let currentFindings = [];
let verificationFilter = 'all';
let filtersInitialized = false;

function renderAllFindings(data) {
    currentFindings = collectFindings(data);
    if (!filtersInitialized) {
        document.querySelectorAll('[data-verification]').forEach(button => button.addEventListener('click', () => {
            verificationFilter = button.dataset.verification;
            filterFindings();
        }));
        document.getElementById('findings-search').addEventListener('input', filterFindings);
        document.getElementById('findings-severity').addEventListener('change', () => {
            if (document.getElementById('findings-severity').value === 'pass') document.getElementById('show-passed').checked = true;
            filterFindings();
        });
        document.getElementById('findings-module').addEventListener('change', filterFindings);
        document.getElementById('show-passed').addEventListener('change', () => {
            if (!document.getElementById('show-passed').checked && document.getElementById('findings-severity').value === 'pass') document.getElementById('findings-severity').value = 'all';
            filterFindings();
        });
        document.getElementById('severity-filters').addEventListener('click', event => {
            const button = event.target.closest('[data-severity]');
            if (!button) return;
            const select = document.getElementById('findings-severity');
            select.value = select.value === button.dataset.severity ? 'all' : button.dataset.severity;
            if (select.value === 'pass') document.getElementById('show-passed').checked = true;
            filterFindings();
        });
        document.getElementById('review-priority-btn').addEventListener('click', () => {
            const priority = currentFindings.find(finding => ACTIONABLE.includes(finding.severity));
            document.getElementById('findings-severity').value = priority?.severity || 'all';
            document.getElementById('findings-module').value = 'all';
            document.getElementById('findings-search').value = '';
            filterFindings();
            document.getElementById('tab-all-findings').click();
            document.getElementById('panel-all-findings').scrollIntoView({ block: 'start', behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth' });
            document.getElementById('findings-search').focus({ preventScroll: true });
        });
        filtersInitialized = true;
    }
    verificationFilter = 'all';
    document.getElementById('findings-search').value = '';
    document.getElementById('findings-severity').value = 'all';
    document.getElementById('show-passed').checked = false;
    const modules = document.getElementById('findings-module');
    modules.replaceChildren(new Option('All checks', 'all'));
    for (const module of new Set(currentFindings.map(finding => finding.module))) modules.add(new Option(MODULES[module][1], module));
    const counts = countSeverities(currentFindings);
    document.getElementById('severity-filters').innerHTML = SEVERITIES.map(severity => `
        <button type="button" class="severity-filter" data-severity="${severity}" aria-pressed="false" ${counts[severity] ? '' : 'disabled'}>
        <span class="severity-dot" style="--severity-color:var(--severity-${severity})"></span>${severity === 'pass' ? 'Passed' : severity}<b>${counts[severity]}</b></button>`).join('');
    filterFindings();
}

function filterFindings() {
    const panel = document.getElementById('findings-list');
    if (!panel) return;
    const query = document.getElementById('findings-search').value;
    const severity = document.getElementById('findings-severity').value;
    const findings = selectFindings(currentFindings, {
        query, severity, verification: verificationFilter, module: document.getElementById('findings-module').value,
        includePassed: document.getElementById('show-passed').checked,
    });
    document.querySelectorAll('[data-verification]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.verification === verificationFilter)));
    document.querySelectorAll('[data-severity]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.severity === severity)));
    document.getElementById('findings-count').textContent = `${findings.length} of ${currentFindings.length} findings shown`;
    if (findings.length === 0) {
        panel.innerHTML = emptyPanel('shield', currentFindings.length ? 'No findings match your filters.' : 'No findings were returned by the selected checks.');
        return;
    }

    panel.innerHTML = findings.map(f => findingCard(f)).join('');
}

function renderAssessmentOverview(data) {
    const counts = countSeverities(currentFindings);
    const issues = ACTIONABLE.reduce((sum, severity) => sum + counts[severity], 0);
    const highest = currentFindings.find(finding => ACTIONABLE.includes(finding.severity));
    const incomplete = Object.values(data.module_status || {}).filter(state => ['partial', 'error'].includes(state)).length;
    const completed = Object.values(data.module_status || {}).filter(state => state === 'success').length;
    const card = document.getElementById('attention-card');
    card.dataset.priority = highest?.severity || (incomplete ? 'medium' : 'pass');
    document.getElementById('attention-icon').textContent = highest ? 'policy' : incomplete ? 'info' : 'verified_user';
    document.getElementById('attention-eyebrow').textContent = 'Results';
    document.getElementById('attention-title').textContent = data.summary ? `${data.summary.confirmed} confirmed · ${data.summary.review} need review` : issues ? `${issues} findings in this older report` : incomplete ? 'Some checks did not finish' : 'No issues in the completed checks';
    document.getElementById('attention-description').textContent = highest
        ? `${counts[highest.severity]} ${highest.severity} · ${highest.title}`
        : `${completed} checks completed${incomplete ? ` · ${incomplete} did not finish` : ''}.`;
    document.getElementById('review-priority-btn').textContent = highest ? `View ${highest.severity} issues →` : 'View findings →';
}

function renderRouteChecks(report) {
    const session = report.authentication || {};
    const sessionTarget = document.getElementById('session-results');
    sessionTarget.innerHTML = `<h3>Session: ${escapeHtml(session.status || 'not supplied')}</h3>${session.profile?.check_path ? `<p>Session check: <code>${escapeHtml(session.profile.check_path)}</code>${session.profile.check_selector ? ` · ${escapeHtml(session.profile.check_selector)}` : ''}</p>` : ''}${session.note ? `<p class="config-note">${escapeHtml(session.note)}</p>` : ''}${session.evidence?.length ? `<details><summary>Session request evidence</summary>${session.evidence.map(evidenceHTML).join('')}</details>` : ''}`;
    const routes = Object.entries(report.route_results || {});
    const target = document.getElementById('route-check-results');
    target.innerHTML = routes.length ? `<h3>Server checks by route</h3><p class="config-note">Private-file probes run once at the origin. Each listed route gets the enabled header, content, cookie, and CORS checks.</p><table class="port-table"><thead><tr><th>Route</th><th>HTTP checks</th><th>Cookies</th><th>CORS</th></tr></thead><tbody>${routes.map(([url, modules]) => `<tr><td>${escapeHtml(url)}</td>${['vuln_scan', 'cookie_scan', 'cors_scan'].map(key => `<td>${escapeHtml(modules[key] ? `${modules[key].http_status ?? 'No response'} · ${modules[key].status}` : 'Not selected')}</td>`).join('')}</tr>`).join('')}</tbody></table>` : '<p class="config-note">No route-level server results are available in this report.</p>';
}

function renderSource(source) {
    const panel = document.getElementById('panel-source');
    if (!source) { panel.innerHTML = ''; return; }
    panel.innerHTML = `<h3>${escapeHtml(source.name)} · ${escapeHtml(source.framework)}</h3><p class="config-note">${escapeHtml(source.root)}</p>
        <p>${escapeHtml(source.files_considered)} files considered${source.docker ? ' · Docker files found' : ''}</p>
        ${source.config_file ? `<p>Framework configuration: <code>${escapeHtml(source.config_file)}</code></p>` : ''}
        <p>Available scripts: ${escapeHtml((source.scripts || []).join(', ') || 'None found')}</p>
        <h3>Routes found in source</h3><table class="port-table"><thead><tr><th>Path</th><th>File</th></tr></thead><tbody>
        ${(source.routes || []).map(route => `<tr><td>${escapeHtml(route.path)}</td><td>${escapeHtml(route.file)}</td></tr>`).join('') || '<tr><td colspan="2">No static routes identified. Enter paths in the scan options.</td></tr>'}</tbody></table>
        ${source.settings?.length ? `<h3>Development and production settings</h3><table class="port-table"><thead><tr><th>Setting</th><th>Development</th><th>Production</th></tr></thead><tbody>${source.settings.map(item => `<tr><td>${escapeHtml(item.key)} · line ${item.line}</td><td>${escapeHtml(item.known.development ? JSON.stringify(item.development) : 'Not resolved')}</td><td>${escapeHtml(item.known.production ? JSON.stringify(item.production) : 'Not resolved')}</td></tr>`).join('')}</tbody></table>` : ''}
        ${(source.limitations || []).map(note => `<p class="config-note">${escapeHtml(note)}</p>`).join('')}`;
}

function renderPages(result) {
    const panel = document.getElementById('panel-browser');
    if (!result) { panel.innerHTML = ''; return; }
    panel.innerHTML = `<table class="port-table"><thead><tr><th>Page</th><th>HTTP</th><th>JavaScript errors</th><th>Failed requests</th></tr></thead><tbody>
        ${(result.pages || []).map(page => `<tr><td>${escapeHtml(page.url)}${page.error ? `<small>${escapeHtml(page.error)}</small>` : ''}</td><td>${escapeHtml(page.status ?? 'Unavailable')}</td><td>${page.errors.length}</td><td>${page.failed_requests.length}</td></tr>`).join('')}</tbody></table>
        ${(result.limitations || []).map(note => `<p class="config-note">${escapeHtml(note)}</p>`).join('')}
        ${result.blocked_requests ? `<p class="config-note">Blocked ${result.blocked_requests.external} external requests, ${result.blocked_requests.writes} requests that could change data, and ${result.blocked_requests.websockets || 0} WebSockets.</p>` : ''}`;
}

function renderPorts(portScan) {
    const panel = document.getElementById('panel-ports');
    if (!panel) return;

    if (!portScan) {
        panel.innerHTML = emptyPanel('lan', 'No open ports found');
        return;
    }

    const overview = `<p class="config-note">${escapeHtml(portScan.total_scanned)} ports checked · ${escapeHtml(portScan.closed_count ?? 'Unknown')} confirmed closed · ${escapeHtml(portScan.inconclusive_ports?.length ?? 'Unknown')} inconclusive</p>
        ${portScan.inconclusive_ports?.length ? `<p class="probe-note">Unreachable or timed out: ${escapeHtml(portScan.inconclusive_ports.join(', '))}. These ports are not confirmed closed.</p>` : ''}
        ${portScan.error ? `<p class="probe-note">${escapeHtml(portScan.error)}</p>` : ''}`;
    if (!portScan.open_ports?.length) {
        panel.innerHTML = overview + emptyPanel('lan', 'No open ports were confirmed');
        return;
    }

    let html = overview + `
        <p style="font-size:0.78rem;color:var(--md-on-surface-variant);margin-bottom:12px;">
            Scanned ${portScan.total_scanned} ports in ${portScan.scan_time_ms}ms
        </p>
        <table class="port-table">
            <thead><tr><th>Port</th><th>Service</th><th>Status</th></tr></thead>
            <tbody>
    `;
    for (const p of portScan.open_ports) {
        html += `
            <tr>
                <td>${p.port}</td>
                <td>${escapeHtml(p.service)}</td>
                <td><span class="port-status"><span class="port-status__dot"></span> ${escapeHtml(p.state)}</span></td>
            </tr>
        `;
    }
    html += '</tbody></table>';
    panel.innerHTML = html;
}

function renderHeaders(vulnScan) {
    const panel = document.getElementById('panel-headers');
    if (!panel) return;

    if (!vulnScan) {
        panel.innerHTML = emptyPanel('security', 'Vulnerability scan was not run');
        return;
    }

    let html = '';

    // Security headers
    if (vulnScan.security_headers) {
        html += '<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:10px;color:var(--md-on-surface);">Security Headers</h3>';
        for (const [name, check] of Object.entries(vulnScan.security_headers)) {
            const sev = check.applicable === false ? 'info' : check.valid === false ? check.severity : check.present ? 'pass' : check.severity;
            html += findingCard({
                title: name,
                severity: sev,
                description: `${check.note || (check.present ? 'Header is set.' : 'Missing')}${check.value ? ` Value: ${check.value}` : ''}`,
                recommendation: ''
            });
        }
    }

    // Sensitive files
    if (vulnScan.sensitive_files && Object.keys(vulnScan.sensitive_files).length > 0) {
        html += '<h3 style="font-size:0.82rem;font-weight:600;margin:16px 0 10px;color:var(--md-on-surface);">Sensitive Files</h3>';
        for (const [path, found] of Object.entries(vulnScan.sensitive_files)) {
            html += findingCard({
                title: path,
                severity: found === null ? 'info' : found ? 'critical' : 'pass',
                description: found === null ? 'Not assessed — request could not complete' : found ? 'EXPOSED — Accessible (HTTP 200)' : 'Not exposed',
                recommendation: found ? `Block access to ${path}` : ''
            });
        }
    }

    panel.innerHTML = html || emptyPanel('security', 'No header data');
}

function renderSSL(sslScan) {
    const panel = document.getElementById('panel-ssl');
    if (!panel) return;

    if (!sslScan) {
        panel.innerHTML = emptyPanel('lock', 'SSL scan was not run');
        return;
    }

    let html = '';

    if (sslScan.has_ssl && sslScan.certificate) {
        const cert = sslScan.certificate;
        html += `
            <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-bottom:16px;">
                ${infoChip('Subject', cert.subject || '—')}
                ${infoChip('Issuer', cert.issuer || '—')}
                ${infoChip('Protocol', sslScan.protocol_version || '—')}
                ${infoChip('Cipher', sslScan.cipher_suite || '—')}
                ${infoChip('Expires', cert.not_after || '—')}
                ${infoChip('Days Left', sslScan.days_until_expiry ?? '—')}
            </div>
        `;
    }

    if (sslScan.findings) {
        html += sslScan.findings.map(f => findingCard(f)).join('');
    }

    panel.innerHTML = html || emptyPanel('lock', 'No SSL data');
}

function renderCORS(corsScan) {
    const panel = document.getElementById('panel-cors');
    if (!panel) return;

    if (!corsScan) {
        panel.innerHTML = emptyPanel('public', 'CORS scan was not run');
        return;
    }

    let html = `
        <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-bottom:16px;">
            ${infoChip('CORS Enabled', corsScan.status === 'error' ? 'Not checked' : corsScan.cors_enabled ? 'Yes' : 'No')}
            ${infoChip('Allow-Origin', corsScan.allow_origin || 'None')}
            ${infoChip('Credentials', corsScan.allow_credentials ? 'Yes' : 'No')}
            ${infoChip('Methods', corsScan.allow_methods?.join(', ') || 'None')}
        </div>
    `;

    if (corsScan.observations?.length) {
        html += `<table class="port-table" style="margin-bottom:20px"><thead><tr><th>Request</th><th>HTTP status</th><th>Allowed origin</th><th>Credentials</th></tr></thead><tbody>${corsScan.observations.map(item => `<tr><td>${escapeHtml(item.method)}<br><small>${escapeHtml(item.origin)}</small></td><td>${escapeHtml(item.status ?? 'No response')}</td><td>${escapeHtml(item.allow_origin || 'None')}</td><td>${item.allow_credentials ? 'Yes' : 'No'}</td></tr>`).join('')}</tbody></table>`;
    }

    if (corsScan.findings) {
        html += corsScan.findings.map(f => findingCard(f)).join('');
    }

    panel.innerHTML = html;
}

function renderCookies(cookieScan) {
    const panel = document.getElementById('panel-cookies');
    if (!panel) return;

    if (!cookieScan) {
        panel.innerHTML = emptyPanel('cookie', 'Cookie scan was not run');
        return;
    }

    let html = '';

    if (cookieScan.cookies?.length > 0) {
        html += `
            <table class="port-table" style="margin-bottom:16px;">
                <thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr></thead>
                <tbody>
        `;
        for (const c of cookieScan.cookies) {
            html += `
                <tr>
                    <td>${escapeHtml(c.name)}</td>
                    <td>${flag(c.secure)}</td>
                    <td>${flag(c.httponly)}</td>
                    <td>${escapeHtml(c.samesite || '—')}</td>
                </tr>
            `;
        }
        html += '</tbody></table>';
    }

    if (cookieScan.findings) {
        html += cookieScan.findings.map(f => findingCard(f)).join('');
    }

    panel.innerHTML = html || emptyPanel('cookie', 'No cookies found');
}

function renderTech(techDetect) {
    const panel = document.getElementById('panel-tech');
    if (!panel) return;

    if (!techDetect || !techDetect.technologies?.length) {
        panel.innerHTML = emptyPanel('code', 'No technologies detected');
        return;
    }

    let html = '<div style="margin-bottom:16px;">';
    for (const t of techDetect.technologies) {
        html += `
            <span class="tech-chip">
                ${escapeHtml(t.name)}${t.version ? ` ${escapeHtml(t.version)}` : ''}
                <span class="tech-chip__category">${escapeHtml(t.category)}</span>
            </span>
        `;
    }
    html += '</div>';

    if (techDetect.findings) {
        html += techDetect.findings.map(f => findingCard(f)).join('');
    }

    panel.innerHTML = html;
}

function renderDNS(dnsScan) {
    const panel = document.getElementById('panel-dns');
    if (!panel) return;

    if (!dnsScan) {
        panel.innerHTML = emptyPanel('dns', 'DNS scan was not run');
        return;
    }

    let html = '<div class="dns-records">';
    if (dnsScan.records) {
        for (const [type, values] of Object.entries(dnsScan.records)) {
            if (values.length > 0) {
                html += `
                    <div class="dns-record-group">
                        <h3>${escapeHtml(type)} Records</h3>
                        ${values.map(v => `<div class="dns-value">${escapeHtml(v)}</div>`).join('')}
                    </div>
                `;
            }
        }
    }
    html += '</div>';

    if (dnsScan.findings) {
        html += dnsScan.findings.map(f => findingCard(f)).join('');
    }

    panel.innerHTML = html;
}

function renderBenchmark(benchmark) {
    const panel = document.getElementById('panel-benchmark');
    if (!panel) return;

    if (!benchmark || !benchmark.requests_attempted) {
        panel.innerHTML = emptyPanel('speed', 'Load test was not run');
        return;
    }

    const latency = value => value == null ? '—' : `${value}ms`;
    panel.innerHTML = `
        <div class="bench-grid">
            ${benchStat(benchmark.req_per_sec, 'Req/sec')}
            ${benchStat(benchmark.requests_successful, 'Successful')}
            ${benchStat(benchmark.requests_failed, 'Failed')}
            ${benchStat(benchmark.requests_incomplete || 0, 'Stopped at deadline')}
            ${benchStat(benchmark.duration + 's', 'Duration')}
            ${benchStat(latency(benchmark.avg_latency_ms), 'Avg Latency')}
            ${benchStat(latency(benchmark.min_latency_ms), 'Min Latency')}
            ${benchStat(latency(benchmark.max_latency_ms), 'Max Latency')}
            ${benchStat(latency(benchmark.p50_latency_ms), 'P50')}
            ${benchStat(latency(benchmark.p95_latency_ms), 'P95')}
            ${benchStat(latency(benchmark.p99_latency_ms), 'P99')}
            ${benchStat(benchmark.error_rate == null ? '—' : `${benchmark.error_rate}%`, 'Error Rate')}
            ${benchStat(benchmark.requests_attempted, 'Total Requests')}
        </div>
        ${benchmark.requests_incomplete ? `<p class="config-note">${benchmark.requests_incomplete} requests stopped when the test time ended. They are excluded from failure rate and latency statistics.</p>` : ''}
        ${benchmark.latency_sampled ? `<p class="config-note">P50, P95, and P99 use a sample of ${benchmark.latency_samples} requests. Average, minimum, maximum, and counts use all requests.</p>` : ''}
    `;
}

function renderDDoS(ddos) {
    const panel = document.getElementById('panel-ddos');
    if (!panel) return;

    if (!ddos) {
        panel.innerHTML = emptyPanel('bolt', 'Traffic test was not run');
        return;
    }

    let html = '';

    // Resilience score
    const scoreColor = ddos.resilience_score == null ? 'var(--md-on-surface-variant)' : ddos.resilience_score >= 70 ? 'var(--severity-pass)' :
        ddos.resilience_score >= 40 ? 'var(--severity-medium)' : 'var(--severity-critical)';
    html += `<div style="text-align:center;margin-bottom:20px;">
        <div style="font-family:var(--font-mono);font-size:2rem;font-weight:700;color:${scoreColor};">${ddos.resilience_score == null ? 'Not assessed' : `${ddos.resilience_score}/100`}</div>
        <div style="font-size:0.72rem;color:var(--md-on-surface-variant);text-transform:uppercase;letter-spacing:0.05em;">Resilience Score</div>
    </div>`;

    // Connection flood stats
    if (ddos.connection_flood?.total_connections !== undefined) {
        const cf = ddos.connection_flood;
        html += `<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Connection Flood</h3>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(cf.total_connections, 'Connections')}
            ${benchStat(cf.successful, 'Successful')}
            ${benchStat(cf.failed, 'Failed')}
            ${benchStat(cf.success_rate + '%', 'Success Rate')}
            ${benchStat(cf.total_time_ms + 'ms', 'Total Time')}
            ${benchStat(cf.avg_latency_ms + 'ms', 'Avg Latency')}
        </div>`;
    }

    // Slowloris stats
    if (ddos.slowloris?.attempted !== undefined) {
        const sl = ddos.slowloris;
        html += `<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Slowloris</h3>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(sl.attempted, 'Attempted')}
            ${benchStat(sl.connections_held, 'Established')}
            ${benchStat(sl.still_alive_after_hold, 'Still Alive')}
            ${benchStat(sl.hold_duration_sec + 's', 'Hold Duration')}
        </div>`;
    }

    // Rapid fire stats
    if (ddos.rapid_fire?.total_requests !== undefined) {
        const rf = ddos.rapid_fire;
        html += `<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Rapid Fire</h3>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(rf.total_requests, 'Requests')}
            ${benchStat(rf.accepted, 'Accepted')}
            ${benchStat(rf.rejected_count, 'Rejected')}
            ${benchStat(rf.errors ?? 0, 'Errors')}
            ${benchStat(rf.avg_response_ms + 'ms', 'Avg Response')}
        </div>`;
    }

    // Findings
    if (ddos.findings) {
        html += ddos.findings.map(f => findingCard(f)).join('');
    }

    panel.innerHTML = html;
}

function renderRateLimit(rateLimit) {
    const panel = document.getElementById('panel-ratelimit');
    if (!panel) return;

    if (!rateLimit) {
        panel.innerHTML = emptyPanel('block', 'Rate limit test was not run');
        return;
    }

    let html = '';

    // Summary info chips
    html += `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-bottom:16px;">
        ${infoChip('Rate Limiting', rateLimit.has_rate_limiting == null ? 'Not assessed' : rateLimit.has_rate_limiting ? rateLimit.evidence === 'headers' ? 'Advertised in headers' : 'Observed' : 'Not observed at this workload')}
        ${infoChip('First 429 response', rateLimit.first_429_response || rateLimit.trigger_threshold || 'Not observed')}
    </div>`;

    // Rate limit headers
    if (rateLimit.rate_limit_headers && Object.keys(rateLimit.rate_limit_headers).length > 0) {
        html += '<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Rate Limit Headers</h3>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:16px;">';
        for (const [header, value] of Object.entries(rateLimit.rate_limit_headers)) {
            html += infoChip(header, value);
        }
        html += '</div>';
    }

    // Burst test
    if (rateLimit.burst_test?.total_requests !== undefined) {
        const bt = rateLimit.burst_test;
        html += `<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Burst Test</h3>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(bt.total_requests, 'Requests')}
            ${benchStat(bt.accepted, 'Accepted')}
            ${benchStat(bt.rate_limited_count, 'Rate Limited')}
            ${benchStat(bt.errors, 'Errors')}
            ${benchStat(bt.unavailable ?? 0, 'Unavailable')}
            ${bt.first_429_at ? benchStat(bt.first_429_at, '429 At #') : ''}
        </div>`;
    }

    // Sustained test
    if (rateLimit.sustained_test?.total_requests !== undefined) {
        const st = rateLimit.sustained_test;
        html += `<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Sustained Test</h3>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(st.total_requests, 'Requests')}
            ${benchStat(st.accepted, 'Accepted')}
            ${benchStat(st.rate_limited_count, 'Rate Limited')}
            ${benchStat(st.errors ?? 0, 'Errors')}
            ${benchStat(st.unavailable ?? 0, 'Unavailable')}
            ${benchStat(st.rps_target + '/s', 'Target RPS')}
            ${benchStat(st.duration_sec + 's', 'Duration')}
        </div>`;
    }

    // Per-endpoint tests
    if (rateLimit.endpoint_tests?.length > 0) {
        html += '<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Per-Endpoint Results</h3>';
        html += `<table class="port-table" style="margin-bottom:16px;">
            <thead><tr><th>Path</th><th>Sent</th><th>Accepted</th><th>429</th><th>Errors</th><th>Unavailable</th><th>Limited</th></tr></thead>
            <tbody>`;
        for (const ep of rateLimit.endpoint_tests) {
            html += `<tr>
                <td>${escapeHtml(ep.path)}</td>
                <td>${ep.requests_sent}</td>
                <td>${ep.accepted}</td>
                <td>${ep.rejected}</td>
                <td>${ep.errors ?? 0}</td>
                <td>${ep.unavailable ?? 0}</td>
                <td>${ep.rate_limited ? '<span style="color:var(--severity-pass);">✓</span>' : '<span style="color:var(--severity-critical);">✗</span>'}</td>
            </tr>`;
        }
        html += '</tbody></table>';
    }

    // Findings
    if (rateLimit.findings) {
        html += rateLimit.findings.map(f => findingCard(f)).join('');
    }

    panel.innerHTML = html;
}

function renderXSS(xss) {
    const panel = document.getElementById('panel-xss');
    if (!panel) return;

    if (!xss) {
        panel.innerHTML = emptyPanel('bug_report', 'XSS scan was not run');
        return;
    }

    let html = '';

    // Summary chips
    html += `<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-bottom:16px;">
        ${infoChip('Potential XSS', xss.vulnerable == null ? 'Not assessed' : xss.vulnerable ? 'Unescaped HTML reflections observed' : 'No reflections observed')}
        ${infoChip('Reflections Found', xss.reflections_found)}
        ${infoChip('Tests Run', xss.tests_run)}
    </div>`;

    // Vulnerable params
    if (xss.vulnerable_params?.length > 0) {
        html += '<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Vulnerable Parameters</h3>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;">';
        for (const param of xss.vulnerable_params) {
            html += `<span class="tech-chip" style="border-color:var(--severity-critical);">${escapeHtml(param)}</span>`;
        }
        html += '</div>';
    }

    // Vulnerable paths
    if (xss.vulnerable_paths?.length > 0) {
        html += '<h3 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Vulnerable Paths</h3>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;">';
        for (const path of xss.vulnerable_paths) {
            html += `<span class="tech-chip" style="border-color:var(--severity-high);">${escapeHtml(path)}</span>`;
        }
        html += '</div>';
    }

    // Findings
    if (xss.findings) {
        html += xss.findings.map(f => findingCard(f)).join('');
    }

    panel.innerHTML = html;
}


/* --- Helpers --- */

function findingCard(f) {
    const severity = ['critical', 'high', 'medium', 'low', 'info', 'pass'].includes(f.severity) ? f.severity : 'info';
    const icon = severityIcon(severity);
    const state = f.verification || 'review';
    const label = { confirmed: 'Confirmed', review: 'Needs review', not_checked: 'Not checked' }[state];
    const latest = (currentReportData?.rechecks || []).filter(item => item.finding_id === f.id).at(-1);
    const recheckLabel = latest ? { resolved: 'Resolved in the latest recheck', still_present: 'Still present', not_checked: 'Could not verify the fix' }[latest.state] : '';
    return `
        <div class="finding finding--${severity}">
            <span class="material-symbols-outlined finding__icon finding__icon--${severity}" aria-hidden="true">${icon}</span>
            <div class="finding__body">
                <div class="finding__title">
                    ${escapeHtml(f.title)}
                    <span class="severity-badge severity-badge--${severity}">${severity}</span>
                    ${f.module ? `<span class="verification-label verification-label--${escapeHtml(state)}">${escapeHtml(label)}</span>` : ''}
                </div>
                ${f.module ? `<div class="finding__source">${escapeHtml(MODULES[f.module]?.[1] || f.module)}</div>` : ''}
                <div class="finding__desc">${escapeHtml(f.description)}</div>
                ${f.location ? `<p class="finding__location">${escapeHtml(f.location)}</p>` : ''}
                ${f.affected_pages?.length > 1 ? `<p class="config-note">Affected pages: ${f.affected_pages.map(escapeHtml).join(', ')}</p>` : ''}
                ${f.fix_file ? `<p class="finding__file">Relevant file: <code>${escapeHtml(f.fix_file)}${f.fix_line ? `:${escapeHtml(f.fix_line)}` : ''}</code></p>` : ''}
                ${f.evidence?.length ? `<details class="finding__evidence"><summary>Evidence (${f.evidence.length})</summary>${f.evidence.map(evidenceHTML).join('')}</details>` : ''}
                ${f.recommendation ? `<div class="finding__rec"><div class="finding__rec-heading"><strong>Recommended fix</strong><button type="button" class="copy-fix" aria-label="Copy recommendation"><span class="material-symbols-outlined" aria-hidden="true">content_copy</span>Copy</button></div><p>${escapeHtml(f.recommendation)}</p></div>` : ''}
                ${f.fix_diff ? `<details class="finding__patch"><summary>Review suggested edit</summary><pre><code>${escapeHtml(f.fix_diff)}</code></pre><button type="button" class="copy-patch preset-btn">Copy patch</button></details>` : ''}
                ${f.fix_notes?.length ? f.fix_notes.map(note => `<p class="config-note">${escapeHtml(note)}</p>`).join('') : ''}
                ${f.fix_example ? `<pre class="finding__example"><code>${escapeHtml(f.fix_example)}</code></pre><button type="button" class="copy-example preset-btn">Copy example</button>` : ''}
                ${f.recheckable && f.id && currentReportData?.saved !== false ? `<div class="finding__recheck"><button type="button" class="md-btn md-btn--outlined" data-recheck="${escapeHtml(f.id)}">Check again</button><p class="finding__recheck-status" role="status">${escapeHtml(recheckLabel)}${latest?.scan_id ? ` <a href="#report/${encodeURIComponent(latest.scan_id)}" data-evidence-report="${escapeHtml(latest.scan_id)}">View new evidence</a>` : ''}</p></div>` : ''}
            </div>
        </div>
    `;
}

let copyInitialized = false;
function initCopyRecommendations() {
    if (copyInitialized) return;
    copyInitialized = true;
    document.getElementById('results-dashboard').addEventListener('click', async event => {
        const button = event.target.closest('.copy-fix, .copy-example, .copy-patch');
        if (!button) return;
        const source = button.matches('.copy-patch') ? button.closest('.finding__patch').querySelector('code') : button.matches('.copy-example') ? button.closest('.finding').querySelector('.finding__example code') : button.closest('.finding__rec').querySelector('p');
        const text = source.textContent;
        try {
            await navigator.clipboard.writeText(text);
            document.getElementById('app-status').textContent = 'Recommended fix copied.';
            button.textContent = 'Copied';
        } catch {
            const selection = window.getSelection();
            const range = document.createRange();
            range.selectNodeContents(source);
            selection.removeAllRanges(); selection.addRange(range);
            document.getElementById('app-status').textContent = 'Recommendation selected. Use your browser’s copy command.';
        }
    });
}

function benchStat(value, label) {
    return `
        <div class="bench-stat">
            <div class="bench-stat__value">${escapeHtml(String(value))}</div>
            <div class="bench-stat__label">${escapeHtml(label)}</div>
        </div>
    `;
}

function infoChip(label, value) {
    return `
        <div style="background:var(--md-surface-container-low);border-radius:var(--radius-sm);padding:10px 14px;">
            <div style="font-size:0.68rem;color:var(--md-on-surface-variant);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:2px;">${label}</div>
            <div style="font-family:var(--font-mono);font-size:0.82rem;color:var(--md-on-surface);word-break:break-all;">${escapeHtml(String(value))}</div>
        </div>
    `;
}

function flag(val) {
    return val
        ? '<span style="color:var(--severity-pass);">✓</span>'
        : '<span style="color:var(--severity-critical);">✗</span>';
}

function emptyPanel(icon, msg) {
    return `
        <div class="panel-empty">
            <span class="material-symbols-outlined" aria-hidden="true">${icon}</span>
            ${escapeHtml(msg)}
        </div>
    `;
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}
