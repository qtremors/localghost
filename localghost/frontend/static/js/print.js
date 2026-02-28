/** Printable reports work directly from memory, including unsaved scans. */
import { escapeHtml as escape, formatTimestamp } from './utils.js';
import { MODULES } from './config.js';
import { evidenceHTML } from './evidence.js';
import { ACTIONABLE, collectFindings } from './findings.js';

function detailTable(title, headers, rows) {
    if (!rows.length) return '';
    return `<section><h2>${escape(title)}</h2><table><thead><tr>${headers.map(header => `<th>${escape(header)}</th>`).join('')}</tr></thead>
        <tbody>${rows.map(row => `<tr>${row.map(value => `<td>${escape(value)}</td>`).join('')}</tr>`).join('')}</tbody></table></section>`;
}

export function printableReport(report) {
    const findings = collectFindings(report);
    const confirmed = report.summary?.confirmed ?? 'Unavailable for this older report';
    const review = report.summary?.review ?? findings.filter(f => ACTIONABLE.includes(f.severity)).length;
    const warnings = [...(report.warnings || []), ...Object.entries(report.errors || {}).map(([module, message]) => `${MODULES[module]?.[1] || module}: ${message}`)];
    const modules = Object.keys(MODULES).filter(module => report.module_status?.[module] === 'success' || (!report.module_status && report[module === 'load_test' ? 'benchmark' : module]));
    const diagnostics = [
        detailTable('Build and session', ['Field', 'Observation'], [['Requested build', report.environment_observation?.requested || 'Unknown'], ['Observed build', report.environment_observation?.observed || 'Unknown'], ['Session', report.authentication?.status || 'Not supplied'], ['Session check', report.authentication?.profile?.check_path || 'Not configured']]),
        detailTable('Server routes checked', ['Route', 'Check', 'HTTP', 'State'], Object.entries(report.route_results || {}).flatMap(([url, modules]) => Object.entries(modules).map(([key, value]) => [url, MODULES[key]?.[1] || key, value.http_status ?? 'No response', value.status]))),
        detailTable('Pages checked', ['Page', 'HTTP', 'JavaScript errors', 'Failed requests'], (report.browser_check?.pages || []).map(page => [page.url, page.status ?? 'Unavailable', page.errors.length, page.failed_requests.length])),
        detailTable('Project context', ['Field', 'Value'], report.source_scan ? [['Framework', report.source_scan.framework], ['Source folder', report.source_scan.root], ['Configuration', report.source_scan.config_file || 'Not identified']] : []),
        detailTable('Routes found in source', ['Path', 'File'], (report.source_scan?.routes || []).map(route => [route.path, route.file])),
        detailTable('Active probe coverage', ['Module', 'Attempted', 'Completed', 'Inconclusive'], Object.entries(MODULES).filter(([module]) => report[module]?.probe_coverage).map(([module, [, name]]) => {
            const coverage = report[module].probe_coverage;
            return [name, coverage.attempted, coverage.completed, coverage.inconclusive];
        })),
        detailTable('Port check coverage', ['Observation', 'Value'], report.port_scan?.inconclusive_ports ? [
            ['Confirmed closed', report.port_scan.closed_count],
            ['Inconclusive ports', report.port_scan.inconclusive_ports.join(', ') || 'None'],
        ] : []),
        detailTable('HTTP security headers', ['Header', 'Result', 'Value'], Object.entries(report.vuln_scan?.security_headers || {}).map(([name, check]) => [name, check.applicable === false ? 'Not applicable' : !check.present ? 'Missing' : check.valid === false ? 'Needs review' : 'Present', check.value || '—'])),
        detailTable('Sensitive file checks', ['Path', 'Observation'], Object.entries(report.vuln_scan?.sensitive_files || {}).map(([path, found]) => [path, found === null ? 'Not assessed' : found ? 'Exposed' : 'Not exposed'])),
        detailTable('TLS certificate', ['Field', 'Value'], Object.entries(report.ssl_scan?.certificate || {}).map(([key, value]) => [key.replaceAll('_', ' '), Array.isArray(value) ? value.join(', ') : value])),
        detailTable('Technologies', ['Name', 'Version', 'Category'], (report.tech_detect?.technologies || []).map(tech => [tech.name, tech.version || '—', tech.category])),
        detailTable('DNS records', ['Type', 'Addresses'], Object.entries(report.dns_scan?.records || {}).map(([type, addresses]) => [type, addresses.join(', ') || 'None returned'])),
        detailTable('Benchmark metrics', ['Metric', 'Value'], Object.entries(report.benchmark || {}).filter(([, value]) => typeof value === 'number').map(([key, value]) => [key.replaceAll('_', ' '), value])) + (report.benchmark?.latency_sampled ? '<p>P50, P95, and P99 use a bounded sample. Deadline stops are listed separately and excluded from latency and failure-rate calculations.</p>' : ''),
        detailTable('Active test summary', ['Test', 'Observation'], [
            ...(report.ddos_test ? [['Traffic test result', report.ddos_test.resilience_score == null ? 'Not assessed' : `${report.ddos_test.resilience_score}/100`]] : []),
            ...(report.rate_limit_test ? [['Rate limiting', report.rate_limit_test.has_rate_limiting == null ? 'Not assessed' : report.rate_limit_test.has_rate_limiting ? report.rate_limit_test.evidence === 'headers' ? 'Advertised in headers' : 'Observed' : 'Not observed at the tested workload']] : []),
            ...(report.xss_scan ? [['XSS reflections', report.xss_scan.reflections_found], ['XSS tests run', report.xss_scan.tests_run]] : []),
        ]),
    ].join('');
    return `
        <header class="print-heading"><p class="print-eyebrow">LOCALGHOST · APP REPORT</p>
            <h1>${escape(report.target)}</h1>
            <p>${escape(formatTimestamp(report.timestamp))} · Scan ${escape(report.scan_id)}</p>
            ${report.resolved_addresses?.length ? `<p>Target addresses: ${escape(report.resolved_addresses.join(', '))}</p>` : ''}
        </header>
        <section class="print-summary"><div><h2>Confirmed problems</h2><strong>${escape(confirmed)}</strong></div>
            <div><h2>Need review</h2><strong>${escape(review)}</strong><p>${escape(report.summary?.incomplete ?? 'Unknown')} incomplete checks</p></div>
        </section>
        ${warnings.length ? `<section class="print-warnings"><h2>Incomplete checks and warnings</h2>${warnings.map(message => `<p>${escape(message)}</p>`).join('')}</section>` : ''}
        <section><h2>Scope</h2>${(report.scope || ['Older report: Not assessed against the current finding rules.']).map(note => `<p>${escape(note)}</p>`).join('')}
            <p>Completed modules: ${escape(modules.map(module => MODULES[module][1]).join(', ') || 'None')}.</p>
            ${(report.authentication?.evidence || []).map(evidenceHTML).join('')}
        </section>
        <section><h2>Findings</h2>
            ${findings.length ? findings.map(finding => `<article class="print-finding"><h3><span>${escape(finding.verification || 'review')} · ${escape(finding.severity.toUpperCase())}</span> ${escape(finding.title)}</h3>
                <p class="print-source">${escape(MODULES[finding.module]?.[1] || finding.module)}</p><p>${escape(finding.description)}</p>
                ${(finding.evidence || []).map(evidenceHTML).join('')}
                ${finding.fix_file ? `<p>Relevant file: ${escape(finding.fix_file)}${finding.fix_line ? `:${escape(finding.fix_line)}` : ''}</p>` : ''}
                ${finding.recommendation ? `<p><b>Recommendation:</b> ${escape(finding.recommendation)}</p>` : ''}${finding.fix_diff ? `<pre>${escape(finding.fix_diff)}</pre>` : ''}${finding.fix_example ? `<pre>${escape(finding.fix_example)}</pre>` : ''}</article>`).join('') : '<p>No findings were returned by the selected checks.</p>'}
        </section>
        ${report.port_scan ? `<section><h2>Open TCP ports</h2><table><thead><tr><th>Port</th><th>Service</th><th>State</th></tr></thead><tbody>
            ${report.port_scan.open_ports.map(port => `<tr><td>${escape(port.port)}</td><td>${escape(port.service)}</td><td>${escape(port.state)}</td></tr>`).join('') || '<tr><td colspan="3">No open ports were confirmed. Review any inconclusive checks.</td></tr>'}
            </tbody></table></section>` : ''}
        ${report.rechecks?.length ? detailTable('Rechecks', ['Finding', 'Result', 'Time', 'New report'], report.rechecks.map(item => [item.finding_id, item.state, item.timestamp, item.scan_id])) : ''}
        ${diagnostics}
        <footer>Generated by Localghost. Results apply to this URL at the time of the scan.</footer>`;
}

export function preparePrint(report) {
    document.getElementById('print-report').innerHTML = printableReport(report);
}
