/**
 * Result rendering — tabs, finding cards, port tables, benchmark stats.
 */

import { severityIcon, severityOrder, escapeHtml, getScoreColor } from './utils.js';

/** Render all result tabs from scan data */
export function renderResults(data) {
    renderQuickStats(data);
    renderAllFindings(data);
    renderPorts(data.port_scan);
    renderHeaders(data.vuln_scan);
    renderSSL(data.ssl_scan);
    renderCORS(data.cors_scan);
    renderCookies(data.cookie_scan);
    renderTech(data.tech_detect);
    renderDNS(data.dns_scan);
    renderBenchmark(data.benchmark);
    renderDDoS(data.ddos_test);
    renderRateLimit(data.rate_limit_test);
    renderXSS(data.xss_scan);
}

function renderQuickStats(data) {
    // Collect all findings
    const allFindings = collectFindings(data);
    const criticalCount = allFindings.filter(f => f.severity === 'critical').length;
    const portsCount = data.port_scan?.open_ports?.length || 0;
    const techCount = data.tech_detect?.technologies?.length || 0;

    setText('stat-findings', allFindings.filter(f => f.severity !== 'pass').length);
    setText('stat-ports', portsCount);
    setText('stat-critical', criticalCount);
    setText('stat-tech', techCount);
}

function collectFindings(data) {
    const findings = [];
    const sources = ['vuln_scan', 'ssl_scan', 'cors_scan', 'cookie_scan', 'tech_detect', 'dns_scan', 'ddos_test', 'rate_limit_test', 'xss_scan'];
    for (const key of sources) {
        if (data[key]?.findings) {
            findings.push(...data[key].findings);
        }
    }
    return findings.sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));
}

function renderAllFindings(data) {
    const panel = document.getElementById('panel-all-findings');
    if (!panel) return;

    const findings = collectFindings(data);
    if (findings.length === 0) {
        panel.innerHTML = emptyPanel('shield', 'No findings to display');
        return;
    }

    panel.innerHTML = findings.map(f => findingCard(f)).join('');
}

function renderPorts(portScan) {
    const panel = document.getElementById('panel-ports');
    if (!panel) return;

    if (!portScan || !portScan.open_ports?.length) {
        panel.innerHTML = emptyPanel('lan', 'No open ports found');
        return;
    }

    let html = `
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
                <td><span class="port-status"><span class="port-status__dot"></span> ${p.state}</span></td>
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
        html += '<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:10px;color:var(--md-on-surface);">Security Headers</h4>';
        for (const [name, check] of Object.entries(vulnScan.security_headers)) {
            const sev = check.present ? 'pass' : check.severity;
            html += findingCard({
                title: name,
                severity: sev,
                description: check.present ? `Present: ${check.value || 'Set'}` : 'Missing',
                recommendation: ''
            });
        }
    }

    // Sensitive files
    if (vulnScan.sensitive_files && Object.keys(vulnScan.sensitive_files).length > 0) {
        html += '<h4 style="font-size:0.82rem;font-weight:600;margin:16px 0 10px;color:var(--md-on-surface);">Sensitive Files</h4>';
        for (const [path, found] of Object.entries(vulnScan.sensitive_files)) {
            html += findingCard({
                title: path,
                severity: found ? 'critical' : 'pass',
                description: found ? 'EXPOSED — Accessible (HTTP 200)' : 'Not exposed',
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
            ${infoChip('CORS Enabled', corsScan.cors_enabled ? 'Yes' : 'No')}
            ${infoChip('Allow-Origin', corsScan.allow_origin || 'None')}
            ${infoChip('Credentials', corsScan.allow_credentials ? 'Yes' : 'No')}
            ${infoChip('Methods', corsScan.allow_methods?.join(', ') || 'None')}
        </div>
    `;

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
                    <td>${c.samesite || '—'}</td>
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
                ${escapeHtml(t.name)}${t.version ? ` ${t.version}` : ''}
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
                        <h4>${type} Records</h4>
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

    panel.innerHTML = `
        <div class="bench-grid">
            ${benchStat(benchmark.req_per_sec, 'Req/sec')}
            ${benchStat(benchmark.requests_successful, 'Successful')}
            ${benchStat(benchmark.requests_failed, 'Failed')}
            ${benchStat(benchmark.duration + 's', 'Duration')}
            ${benchStat(benchmark.avg_latency_ms + 'ms', 'Avg Latency')}
            ${benchStat(benchmark.min_latency_ms + 'ms', 'Min Latency')}
            ${benchStat(benchmark.max_latency_ms + 'ms', 'Max Latency')}
            ${benchStat(benchmark.p50_latency_ms + 'ms', 'P50')}
            ${benchStat(benchmark.p95_latency_ms + 'ms', 'P95')}
            ${benchStat(benchmark.p99_latency_ms + 'ms', 'P99')}
            ${benchStat(benchmark.error_rate + '%', 'Error Rate')}
            ${benchStat(benchmark.requests_attempted, 'Total Requests')}
        </div>
    `;
}

function renderDDoS(ddos) {
    const panel = document.getElementById('panel-ddos');
    if (!panel) return;

    if (!ddos) {
        panel.innerHTML = emptyPanel('bolt', 'DDoS resilience test was not run');
        return;
    }

    let html = '';

    // Resilience score
    const scoreColor = ddos.resilience_score >= 70 ? 'var(--severity-pass)' :
        ddos.resilience_score >= 40 ? 'var(--severity-medium)' : 'var(--severity-critical)';
    html += `<div style="text-align:center;margin-bottom:20px;">
        <div style="font-family:var(--font-mono);font-size:2rem;font-weight:700;color:${scoreColor};">${ddos.resilience_score}/100</div>
        <div style="font-size:0.72rem;color:var(--md-on-surface-variant);text-transform:uppercase;letter-spacing:0.05em;">Resilience Score</div>
    </div>`;

    // Connection flood stats
    if (ddos.connection_flood) {
        const cf = ddos.connection_flood;
        html += `<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Connection Flood</h4>
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
    if (ddos.slowloris) {
        const sl = ddos.slowloris;
        html += `<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Slowloris</h4>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(sl.attempted, 'Attempted')}
            ${benchStat(sl.connections_held, 'Held Open')}
            ${benchStat(sl.still_alive_after_hold, 'Still Alive')}
            ${benchStat(sl.hold_duration_sec + 's', 'Hold Duration')}
        </div>`;
    }

    // Rapid fire stats
    if (ddos.rapid_fire) {
        const rf = ddos.rapid_fire;
        html += `<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Rapid Fire</h4>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(rf.total_requests, 'Requests')}
            ${benchStat(rf.accepted, 'Accepted')}
            ${benchStat(rf.rejected_count, 'Rejected')}
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
        ${infoChip('Rate Limiting', rateLimit.has_rate_limiting ? 'Detected ✓' : 'Not Detected ✗')}
        ${infoChip('Trigger Threshold', rateLimit.trigger_threshold || 'N/A')}
    </div>`;

    // Rate limit headers
    if (rateLimit.rate_limit_headers && Object.keys(rateLimit.rate_limit_headers).length > 0) {
        html += '<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Rate Limit Headers</h4>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:16px;">';
        for (const [header, value] of Object.entries(rateLimit.rate_limit_headers)) {
            html += infoChip(header, value);
        }
        html += '</div>';
    }

    // Burst test
    if (rateLimit.burst_test) {
        const bt = rateLimit.burst_test;
        html += `<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Burst Test</h4>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(bt.total_requests, 'Requests')}
            ${benchStat(bt.accepted, 'Accepted')}
            ${benchStat(bt.rate_limited_count, 'Rate Limited')}
            ${benchStat(bt.errors, 'Errors')}
            ${bt.first_429_at ? benchStat(bt.first_429_at, '429 At #') : ''}
        </div>`;
    }

    // Sustained test
    if (rateLimit.sustained_test) {
        const st = rateLimit.sustained_test;
        html += `<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Sustained Test</h4>
        <div class="bench-grid" style="margin-bottom:16px;">
            ${benchStat(st.total_requests, 'Requests')}
            ${benchStat(st.accepted, 'Accepted')}
            ${benchStat(st.rate_limited_count, 'Rate Limited')}
            ${benchStat(st.rps_target + '/s', 'Target RPS')}
            ${benchStat(st.duration_sec + 's', 'Duration')}
        </div>`;
    }

    // Per-endpoint tests
    if (rateLimit.endpoint_tests?.length > 0) {
        html += '<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Per-Endpoint Results</h4>';
        html += `<table class="port-table" style="margin-bottom:16px;">
            <thead><tr><th>Path</th><th>Sent</th><th>Accepted</th><th>Rejected</th><th>Limited</th></tr></thead>
            <tbody>`;
        for (const ep of rateLimit.endpoint_tests) {
            html += `<tr>
                <td>${escapeHtml(ep.path)}</td>
                <td>${ep.requests_sent}</td>
                <td>${ep.accepted}</td>
                <td>${ep.rejected}</td>
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
        ${infoChip('Vulnerable', xss.vulnerable ? 'YES ✗' : 'NO ✓')}
        ${infoChip('Reflections Found', xss.reflections_found)}
        ${infoChip('Tests Run', xss.tests_run)}
    </div>`;

    // Vulnerable params
    if (xss.vulnerable_params?.length > 0) {
        html += '<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Vulnerable Parameters</h4>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;">';
        for (const param of xss.vulnerable_params) {
            html += `<span class="tech-chip" style="border-color:var(--severity-critical);">${escapeHtml(param)}</span>`;
        }
        html += '</div>';
    }

    // Vulnerable paths
    if (xss.vulnerable_paths?.length > 0) {
        html += '<h4 style="font-size:0.82rem;font-weight:600;margin-bottom:8px;color:var(--md-on-surface);">Vulnerable Paths</h4>';
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
    const icon = severityIcon(f.severity);
    return `
        <div class="finding finding--${f.severity}">
            <span class="material-symbols-outlined finding__icon finding__icon--${f.severity}">${icon}</span>
            <div class="finding__body">
                <div class="finding__title">
                    ${escapeHtml(f.title)}
                    <span class="severity-badge severity-badge--${f.severity}">${f.severity}</span>
                </div>
                <div class="finding__desc">${escapeHtml(f.description)}</div>
                ${f.recommendation ? `<div class="finding__rec">💡 ${escapeHtml(f.recommendation)}</div>` : ''}
            </div>
        </div>
    `;
}

function benchStat(value, label) {
    return `
        <div class="bench-stat">
            <div class="bench-stat__value">${value}</div>
            <div class="bench-stat__label">${label}</div>
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
            <span class="material-symbols-outlined">${icon}</span>
            ${msg}
        </div>
    `;
}

function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
}
