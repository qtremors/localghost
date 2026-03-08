import test from 'node:test';
import assert from 'node:assert/strict';
import { parsePorts } from '../frontend/static/js/config.js';
import { escapeHtml, formatTimestamp } from '../frontend/static/js/utils.js';
import { startScan } from '../frontend/static/js/api.js';
import { projectIdentity } from '../frontend/static/js/projects.js';

test('project labels preserve ports and IPv6 while paths share an origin', () => {
    assert.equal(projectIdentity('http://localhost:3000/old').key, projectIdentity('http://localhost:3000/new').key);
    assert.notEqual(projectIdentity('http://localhost:3000').key, projectIdentity('https://localhost:3000').key);
    assert.equal(projectIdentity('http://localhost:3000').name, 'localhost:3000');
    assert.equal(projectIdentity('http://[::1]:8000/path').name, '[::1]:8000');
    assert.equal(projectIdentity('legacy target').name, 'legacy target');
});
test('custom ports support ranges, boundaries, sorting, and duplicates', () => {
    assert.equal(parsePorts(' '), null);
    assert.deepEqual(parsePorts('443,80, 3000-3002, 80,65535'), [80, 443, 3000, 3001, 3002, 65535]);
    assert.equal(parsePorts('1-1024').length, 1024);
});
test('malformed ports and unbounded ranges are rejected', () => {
    for (const value of ['0', '65536', '4-2', '1-1025', '1-1024,65535', '80,', 'a', '3.5', '-1']) {
        assert.throws(() => parsePorts(value));
    }
});
test('HTML escaping includes attribute quotes and invalid dates have a fallback', () => {
    assert.equal(escapeHtml('<img src="x" onerror=\'alert(1)\'>'), '&lt;img src=&quot;x&quot; onerror=&#39;alert(1)&#39;&gt;');
    assert.equal(escapeHtml(null), '');
    assert.equal(formatTimestamp('not-a-date'), 'Unknown date');
});

test('stream parser handles split UTF-8 characters, multiple events, and final partial lines', async t => {
    const text = '{"type":"started","target":"dévelop"}\n{"type":"complete","result":{"score":80}}';
    const bytes = new TextEncoder().encode(text);
    t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({
        start(controller) {
            for (let i = 0; i < bytes.length; i++) controller.enqueue(bytes.slice(i, i + 1));
            controller.close();
        },
    })));
    const events = [];
    assert.deepEqual(await startScan({}, { onEvent: event => events.push(event) }), { score: 80 });
    assert.equal(events[0].target, 'dévelop');
});
test('structured API validation errors produce actionable messages', async t => {
    t.mock.method(globalThis, 'fetch', async () => new Response(JSON.stringify({ detail: [{ loc: ['body', 'target_url'], msg: 'Invalid port' }] }), { status: 422 }));
    await assert.rejects(startScan({}), /target_url: Invalid port/);
});
test('interrupted and failed streams never appear successful', async t => {
    t.mock.method(globalThis, 'fetch', async () => new Response('{"type":"started"}\n'));
    await assert.rejects(startScan({}), /connection ended/);
    globalThis.fetch.mock.mockImplementation(async () => new Response('{"type":"error","message":"Target unreachable"}\n'));
    await assert.rejects(startScan({}), /Target unreachable/);
});

import { collectFindings, countSeverities, filterFindings } from '../frontend/static/js/findings.js';
import { printableReport } from '../frontend/static/js/print.js';

test('shared findings preserve module identity and prioritize actionable issues', () => {
    const findings = collectFindings({
        cookie_scan: { findings: [{ title: 'Cookie', severity: 'medium' }] },
        vuln_scan: { findings: [{ title: 'Header', severity: 'high' }, { title: 'Protected', severity: 'pass' }] },
    });
    assert.equal(findings[0].module, 'vuln_scan');
    assert.equal(countSeverities(findings).high, 1);
    assert.equal(filterFindings(findings).length, 2);
    assert.equal(filterFindings(findings, { severity: 'pass' }).length, 1);
    assert.equal(filterFindings(findings, { module: 'cookie_scan' }).length, 1);
    assert.equal(filterFindings(findings, { query: 'headers & files' }).length, 1);
});

test('print reports escape target-controlled content and preserve incomplete coverage', () => {
    const html = printableReport({
        scan_id: 'example', target: '<img src=x onerror=alert(1)>', timestamp: '2026-10-16T12:00:00Z',
        score: { score: 0, grade: '—', coverage: 0, breakdown: { headers: null } },
        saved: false, warnings: ['Storage unavailable'], errors: { cors_scan: 'Connection failed' },
        vuln_scan: { findings: [{ title: '<script>alert(1)</script>', severity: 'high', description: 'Example', recommendation: '<b>escape me</b>' }] },
    });
    assert.ok(html.includes('&lt;img'));
    assert.ok(!html.includes('<script>'));
    assert.ok(html.includes('Not assessed'));
    assert.ok(html.includes('Storage unavailable'));
    assert.ok(html.includes('Connection failed'));
    assert.ok(html.includes('&lt;b&gt;escape me&lt;/b&gt;'));
});

test('print reports include metrics and observations even for benchmark-only scans', () => {
    const html = printableReport({
        scan_id: 'benchmark', target: 'http://localhost', timestamp: '2026-10-16T12:00:00Z',
        score: { score: 0, grade: '—', coverage: 0, breakdown: {} },
        module_status: { load_test: 'success' },
        benchmark: { requests_attempted: 20, req_per_sec: 10.5, p95_latency_ms: 45.3 },
    });
    assert.ok(html.includes('Benchmark metrics'));
    assert.ok(html.includes('45.3'));
    assert.ok(html.includes('Completed modules: Load test'));
});

test('print reports keep inconclusive probe outcomes and target addresses visible', () => {
    const html = printableReport({
        scan_id: 'partial', target: 'http://localhost', timestamp: '2026-10-16T12:00:00Z',
        resolved_addresses: ['127.0.0.1'], score: { score: 0, coverage: 0, breakdown: {} },
        module_status: { rate_limit_test: 'partial', ddos_test: 'error' },
        rate_limit_test: { has_rate_limiting: null, probe_coverage: { attempted: 7, completed: 1, inconclusive: 6 } },
        ddos_test: { resilience_score: null, probe_coverage: { attempted: 1, completed: 0, inconclusive: 1 } },
    });
    assert.ok(html.includes('Target addresses: 127.0.0.1'));
    assert.ok(html.includes('Active probe coverage'));
    assert.ok(html.includes('Inconclusive'));
    assert.ok(!html.includes('null/100'));
    assert.ok(!html.includes('Rate limiting detected'));
});

test('current reports use structured evidence and verification filters without duplicating module findings', () => {
    const findings = [
        { id: 'file', module: 'vuln_scan', title: 'Exposed file', severity: 'critical', verification: 'confirmed', evidence: [{ method: 'GET', url: 'http://localhost/.env', status: 200, observation: 'Format matched' }] },
        { id: 'header', module: 'vuln_scan', title: 'Missing header', severity: 'low', verification: 'review' },
        { id: 'unknown', module: 'browser_check', title: 'Unavailable browser', severity: 'info', verification: 'not_checked' },
    ];
    const report = { findings, vuln_scan: { findings: [{ title: 'Legacy duplicate', severity: 'high' }] } };
    assert.equal(collectFindings(report).length, 3);
    assert.deepEqual(filterFindings(findings, { verification: 'confirmed' }).map(item => item.id), ['file']);
    assert.deepEqual(filterFindings(findings, { verification: 'review' }).map(item => item.id), ['header']);
    assert.deepEqual(filterFindings(findings, { verification: 'not_checked' }).map(item => item.id), ['unknown']);
    const html = printableReport({ ...report, target: 'http://localhost', scan_id: 'current', timestamp: '2026-10-17',
        score: null, summary: { confirmed: 1, review: 1, incomplete: 1 }, scope: ['Selected pages only'] });
    assert.ok(html.includes('Format matched'));
    assert.ok(html.includes('Selected pages only'));
    assert.ok(!html.includes('Security score'));
    assert.ok(!html.includes('Legacy duplicate'));
});

test('routine observations stay available without crowding the default issue list', () => {
    const findings = [{id:'dns', module:'dns_scan', title:'Address resolved', description:'Local address', severity:'info', verification:'review'},
        {id:'offline', module:'cookie_scan', title:'Check unavailable', description:'No response', severity:'info', verification:'not_checked'}];
    assert.deepEqual(filterFindings(findings).map(item => item.id), ['offline']);
    assert.deepEqual(filterFindings(findings, {severity:'info'}).map(item => item.id), ['dns','offline']);
    assert.deepEqual(filterFindings(findings, {query:'address'}).map(item => item.id), ['dns']);
});

import { evidenceHTML } from '../frontend/static/js/evidence.js';
test('captured exchanges preserve exact fields while escaping response-controlled HTML', () => {
    const html = evidenceHTML({method:'GET', url:'http://localhost/private', status:500, captured:true,
        page_url:'http://localhost/account', request_headers:{Origin:'https://test.invalid'},
        response_headers:{'X-Details':'<script>bad()</script>'}, response_body_excerpt:'<img src=x onerror=bad()>', observation:'Observed failure'});
    assert.ok(html.includes('Origin: https://test.invalid'));
    assert.ok(html.includes('HTTP 500'));
    assert.ok(html.includes('Affected page:'));
    assert.ok(html.includes('&lt;script&gt;'));
    assert.ok(!html.includes('<img src=x'));
    const tls = evidenceHTML({method:'TLS',url:'https://localhost',observation:'Transport evidence',captured:true,response_details:{protocol:'TLSv1.3'}});
    assert.ok(tls.includes('TLSv1.3'));
});
