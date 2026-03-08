/** Compare saved reports with explicit scope and failure handling. */
import { getHistory, getComparison } from './api.js';
import { MODULES } from './config.js';
import { escapeHtml as escape, formatTimestamp } from './utils.js';

let report;
let controller;
let version = 0;
const $ = id => document.getElementById(id);

export function initComparison() {
    $('compare-toggle-btn').addEventListener('click', async () => {
        const open = $('comparison-card').classList.contains('hidden');
        setOpen(open);
        if (open) await loadBaselines();
    });
    $('close-comparison-btn').addEventListener('click', () => {
        setOpen(false); $('compare-toggle-btn').focus();
    });
    $('compare-scans-btn').addEventListener('click', runComparison);
    $('comparison-baseline').addEventListener('change', () => {
        controller?.abort(); version++;
        $('comparison-results').replaceChildren();
        $('comparison-status').textContent = 'Choose Compare to view changes.';
        $('compare-scans-btn').disabled = !$('comparison-baseline').value;
    });
}

function setOpen(open) {
    $('comparison-card').classList.toggle('hidden', !open);
    $('compare-toggle-btn').setAttribute('aria-expanded', String(open));
    if (!open) { controller?.abort(); version++; }
}
export function setComparisonReport(value) {
    report = value;
    controller?.abort(); version++;
    $('comparison-results').replaceChildren();
    setOpen(false);
}

async function loadBaselines() {
    const currentVersion = ++version;
    controller?.abort(); controller = new AbortController();
    const select = $('comparison-baseline');
    select.disabled = true; $('compare-scans-btn').disabled = true;
    select.replaceChildren(new Option('Loading previous scans…', ''));
    $('comparison-results').replaceChildren();
    if (!report || report.saved === false) {
        select.replaceChildren(new Option('Report has not been saved', ''));
        $('comparison-status').textContent = 'History must be available to compare reports. You can still print or export this scan.';
        return;
    }
    $('comparison-status').textContent = 'Looking for earlier scans of this target…';
    try {
        const history = await getHistory(200, 0, { target: report.target, signal: controller.signal });
        if (currentVersion !== version) return;
        const baselines = history.scans.filter(scan => scan.scan_id !== report.scan_id && Date.parse(scan.timestamp) <= Date.parse(report.timestamp));
        select.replaceChildren(...baselines.map(scan => new Option(`${formatTimestamp(scan.timestamp)} · ${scan.confirmed == null ? 'Older report' : `${scan.confirmed} confirmed`} · ${scan.scan_id.slice(0, 8)}`, scan.scan_id)));
        if (!baselines.length) {
            select.replaceChildren(new Option('No earlier scans for this target', ''));
            $('comparison-status').textContent = 'Run another scan of the same target to track what changed.';
            return;
        }
        select.disabled = false; $('compare-scans-btn').disabled = false;
        $('comparison-status').textContent = 'Compare against an earlier report. Only checks completed in both scans are included.';
        select.focus({ preventScroll: true });
    } catch (error) {
        if (error.name === 'AbortError' || currentVersion !== version) return;
        select.replaceChildren(new Option('Could not load previous reports', ''));
        $('comparison-status').textContent = error.message;
    }
}

async function runComparison() {
    const baseline = $('comparison-baseline').value;
    if (!baseline || !report) return;
    const currentVersion = ++version;
    controller?.abort(); controller = new AbortController();
    $('compare-scans-btn').disabled = true;
    $('comparison-status').textContent = 'Comparing scans…';
    $('comparison-results').replaceChildren();
    try {
        const data = await getComparison(report.scan_id, baseline, controller.signal);
        if (currentVersion !== version) return;
        renderComparison(data);
        $('comparison-status').textContent = `${data.comparable_modules.length} checks completed in both scans · Earlier scan ${formatTimestamp(data.baseline.timestamp)}`;
    } catch (error) {
        if (error.name !== 'AbortError' && currentVersion === version) $('comparison-status').textContent = error.message;
    } finally {
        if (currentVersion === version) $('compare-scans-btn').disabled = false;
    }
}

function renderComparison(data) {
    const metric = (value, label, tone = '') => `<div class="comparison-metric ${tone}"><strong>${escape(value)}</strong><span>${escape(label)}</span></div>`;
    const group = (title, findings, tone) => findings.length ? `<section class="comparison-group ${tone}"><h4>${escape(title)} <span>${findings.length}</span></h4><ul>${findings.map(finding => `<li><span class="severity-badge severity-badge--${escape(finding.severity)}">${escape(finding.severity)}</span><span>${escape(finding.title)}${finding.previous_severity ? `<small>${escape(finding.previous_severity)} → ${escape(finding.severity)}</small>` : ''}<small>${escape(MODULES[finding.module]?.[1] || finding.module)}</small></span></li>`).join('')}</ul></section>` : '';
    $('comparison-results').innerHTML = `
        <div class="comparison-metrics">
            ${metric(data.resolved_findings.length, 'Resolved issues', 'change-positive')}
            ${metric(data.new_findings.length, 'New issues', data.new_findings.length ? 'change-negative' : '')}
            ${metric(data.changed_findings.length, 'Severity changes')}
        </div>
        ${data.rules_changed ? '<p class="comparison-note">Scanner rules changed between these reports. Finding and port changes are not compared.</p>' : ''}
        ${data.endpoint_changed ? '<p class="comparison-note">The target addresses changed between these scans. Results may refer to different server instances.</p>' : ''}
        ${data.excluded_modules.length ? `<p class="comparison-note">Excluded incomplete or unselected checks: ${escape(data.excluded_modules.map(module => MODULES[module]?.[1] || module).join(', '))}.</p>` : ''}
        ${data.comparable_modules.length ? `<p class="config-note">${data.unchanged_count} issue${data.unchanged_count === 1 ? '' : 's'} unchanged in checks completed in both scans.</p>` : '<p class="comparison-note">No checks with findings completed in both scans. Issue changes cannot be determined.</p>'}
        <div class="comparison-groups">${group('Resolved', data.resolved_findings, 'change-positive')}${group('New', data.new_findings, 'change-negative')}${group('Severity changed', data.changed_findings, '')}</div>
        ${data.ports.comparable ? `<p class="config-note comparison-ports">Ports: ${data.ports.opened.length ? `newly open ${escape(data.ports.opened.join(', '))}` : 'no newly open ports'} · ${data.ports.closed.length ? `closed ${escape(data.ports.closed.join(', '))}` : 'no closed ports'}</p>` : '<p class="config-note comparison-ports">Port changes require the same port configuration in both scans.</p>'}`;
}
