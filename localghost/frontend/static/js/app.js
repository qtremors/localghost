/** Dashboard interactions and scan lifecycle. */
import { startScan, getScanDetail } from './api.js';
import { initTheme } from './theme.js';
import { renderResults } from './results.js';
import { initProjectContext } from './project-context.js';
import { initRechecks, setRecheckReport } from './rechecks.js';
import { collectFindings } from './findings.js';
import { buildSession, clearSession, restoreSessionProfile } from './session.js';
import { loadHistory, initHistory, setHistoryBusy, selectHistory } from './history.js';
import { MODULES, parsePorts } from './config.js';
import { initComparison, setComparisonReport } from './comparison.js';
import { preparePrint } from './print.js';
import { initWorkspace, showView, setWorkspaceReport, setWorkspaceBusy, refreshWorkspace } from './workspace.js';
import { projectIdentity } from './projects.js';
import { initXcrape } from '../xcrape/script.js';
import { $, show, hide, formatTimestamp } from './utils.js';

let currentReport = null;
let activeScan = null;
let closeSidebar = () => {};

function announce(message) { $('#app-status').textContent = message; }
function formError(message = '') {
    $('#form-error').textContent = message;
    $('#form-error').classList.toggle('hidden', !message);
}

document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initSidebar();
    initTabs();
    initConfiguration();
    initProjectContext();
    initRechecks({ setBusy(value) { setBusy(value); $('#running-scan-nav').classList.add('hidden'); }, refresh() { loadHistory(); refreshWorkspace(); } });
    initScanForm();
    initComparison();
    initXcrape();
    initWorkspace({
        openReport(data) { displayResults(data); restoreConfiguration(data); },
        async configureProject(scanId) {
            let detail = await getScanDetail(scanId);
            if (detail.results.recheck_of?.scan_id) {
                try { detail = await getScanDetail(detail.results.recheck_of.scan_id); } catch { /* The original may have been deleted. */ }
            }
            restoreConfiguration(detail.results);
        },
        chooseTarget(target, sourcePath = '') {
            $('#source-path').value = sourcePath; $('#source-status').textContent = ''; $('#source-route-choices').replaceChildren();
            $('#scan-paths').value = ''; clearSession();
            $('#mod-source').checked = Boolean(sourcePath);
            syncConfiguration();
            $('#target-url').value = target;
            $('#target-url').dispatchEvent(new Event('input', { bubbles: true }));
        },
        closeNavigation() { closeSidebar(); },
    });
    initHistory(data => {
        displayResults(data);
        restoreConfiguration(data);
        closeSidebar();
    });
    loadHistory();
});

function initSidebar() {
    const sidebar = $('#sidebar');
    const toggle = $('#menu-toggle');
    const mobile = window.matchMedia('(max-width: 768px)');
    function setOpen(open, restoreFocus = false) {
        sidebar.classList.toggle('open', open);
        toggle.setAttribute('aria-expanded', String(open));
        sidebar.inert = mobile.matches && !open;
        if (open) sidebar.querySelector('.primary-nav .nav-item').focus();
        else if (restoreFocus) toggle.focus();
    }
    closeSidebar = () => setOpen(false);
    toggle.addEventListener('click', () => setOpen(!sidebar.classList.contains('open')));
    $('#sidebar-overlay').addEventListener('click', () => setOpen(false, true));
    document.addEventListener('keydown', event => {
        if (!mobile.matches || !sidebar.classList.contains('open')) return;
        if (event.key === 'Escape') { setOpen(false, true); return; }
        if (event.key !== 'Tab') return;
        const items = [...sidebar.querySelectorAll('a[href], button:not(:disabled), input:not(:disabled)')]
            .filter(element => element.getClientRects().length);
        const first = items[0], last = items.at(-1);
        if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
        else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    });
    mobile.addEventListener('change', () => setOpen(false));
    setOpen(false);
}

function initTabs() {
    const container = $('#results-tabs');
    const tabs = [...container.querySelectorAll('.results-tab')];
    const horizontal = window.matchMedia('(max-width: 950px)');
    const orientation = () => container.setAttribute('aria-orientation', horizontal.matches ? 'horizontal' : 'vertical');
    horizontal.addEventListener('change', orientation); orientation();
    function activate(tab, focus = false) {
        for (const item of tabs) {
            const selected = item === tab;
            item.classList.toggle('active', selected);
            item.setAttribute('aria-selected', String(selected));
            item.tabIndex = selected ? 0 : -1;
            const panel = $(`#panel-${item.dataset.tab}`);
            panel.classList.toggle('active', selected);
            panel.hidden = !selected;
        }
        $('#result-section-title').textContent = tab.querySelector('span:last-child').textContent;
        $('#result-section-note').textContent = tab.dataset.tab === 'all-findings' ? 'Issues and suggested fixes' : 'Check results';
        if (focus) { tab.focus(); tab.scrollIntoView({ block: 'nearest', inline: 'nearest' }); }
    }
    tabs.forEach(tab => {
        tab.id = `tab-${tab.dataset.tab}`;
        tab.setAttribute('role', 'tab');
        tab.setAttribute('aria-controls', `panel-${tab.dataset.tab}`);
        const panel = $(`#panel-${tab.dataset.tab}`);
        panel.setAttribute('role', 'tabpanel');
        panel.setAttribute('aria-labelledby', tab.id);
        panel.tabIndex = 0;
        tab.addEventListener('click', () => activate(tab));
    });
    container.addEventListener('keydown', event => {
        const index = tabs.indexOf(event.target);
        if (index < 0) return;
        const next = ['ArrowRight', 'ArrowDown'].includes(event.key) ? (index + 1) % tabs.length
            : ['ArrowLeft', 'ArrowUp'].includes(event.key) ? (index - 1 + tabs.length) % tabs.length
            : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : null;
        if (next === null) return;
        event.preventDefault(); activate(tabs[next], true);
    });
    activate(tabs[0]);
}

function syncConfiguration() {
    const enabled = Object.values(MODULES).filter(([id]) => $(`#mod-${id}`).checked).length;
    $('#module-count').textContent = `${enabled} of ${Object.keys(MODULES).length} checks selected`;
    $('#plan-check-count').textContent = enabled;
    $('#mobile-plan-count').textContent = `${enabled} checks selected`;
    const active = ['bench', 'ddos', 'ratelimit', 'xss'].filter(id => $(`#mod-${id}`).checked).length;
    $('#plan-active-count').textContent = active || 'None';
    const bench = $('#mod-bench').checked;
    $('#bench-config').classList.toggle('hidden', !bench);
    $('#bench-config').querySelectorAll('input').forEach(input => { input.disabled = !bench || Boolean(activeScan); });
    $('#port-config').classList.toggle('hidden', !$('#mod-ports').checked);
    $('#custom-ports').disabled = !$('#mod-ports').checked || Boolean(activeScan);
    $('#no-extra-options').classList.toggle('hidden', bench || $('#mod-ports').checked);
    $('#active-test-note').classList.toggle('hidden', !['bench', 'ddos', 'ratelimit', 'xss'].some(id => $(`#mod-${id}`).checked));
}

function initConfiguration() {
    document.querySelectorAll('[data-preset]').forEach(button => button.addEventListener('click', () => {
        const preset = button.dataset.preset;
        if (preset !== 'custom') {
            const enabled = preset === 'quick' ? ['port_scan', 'tech_detect', 'dns_scan']
                : ['port_scan', 'vuln_scan', 'ssl_scan', 'cors_scan', 'cookie_scan', 'tech_detect', 'dns_scan', 'browser_check', ...($('#source-path').value.trim() ? ['source_scan'] : [])];
            for (const [key, [id]] of Object.entries(MODULES)) $(`#mod-${id}`).checked = enabled.includes(key);
        }
        document.querySelectorAll('[data-preset]').forEach(item => item.setAttribute('aria-pressed', String(item === button)));
        syncConfiguration(); formError();
    }));
    $('#scan-form').addEventListener('change', event => {
        if (event.target.type === 'checkbox') {
            document.querySelectorAll('[data-preset]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.preset === 'custom')));
        }
        syncConfiguration();
    });
    $('#scan-form').addEventListener('input', () => formError());
    syncConfiguration();
}

function buildRequest() {
    const modules = Object.fromEntries(Object.entries(MODULES).map(([key, [id]]) => [key, $(`#mod-${id}`).checked]));
    if (!Object.values(modules).some(Boolean)) throw new Error('Select at least one check.');
    if (modules.source_scan && !$('#source-path').value.trim()) throw new Error('Enter a source folder or turn off project configuration checks.');
    return {
        target_url: $('#target-url').value.trim(), modules,
        source_path: $('#source-path').value.trim() || null,
        environment: $('#scan-environment').value,
        paths: $('#scan-paths').value.split('\n').map(path => path.trim()).filter(Boolean),
        session: buildSession(),
        ports_to_scan: modules.port_scan ? parsePorts($('#custom-ports').value) : null,
        benchmark_config: {
            concurrency: modules.load_test ? Number($('#bench-concurrency').value) : 50,
            duration_seconds: modules.load_test ? Number($('#bench-duration').value) : 5,
        },
    };
}

function restoreConfiguration(data) {
    $('#target-url').value = data.target;
    const request = data.request;
    $('#source-path').value = request?.source_path || '';
    $('#scan-environment').value = request?.environment || 'development';
    $('#scan-paths').value = (request?.paths || []).join('\n');
    clearSession(); restoreSessionProfile(data.authentication?.profile);
    $('#source-status').textContent = '';
    $('#source-route-choices').replaceChildren();
    for (const [key, [id]] of Object.entries(MODULES)) {
        const resultKey = key === 'load_test' ? 'benchmark' : key;
        const previousState = data.module_status?.[key];
        $(`#mod-${id}`).checked = request?.modules ? Boolean(request.modules[key])
            : previousState ? previousState !== 'skipped' : Boolean(data[resultKey]);
    }
    const ports = request ? request.ports_to_scan : data.port_scan?.ports_checked;
    $('#custom-ports').value = Array.isArray(ports) ? ports.join(', ') : '';
    const setting = (value, fallback, maximum) => Number.isFinite(Number(value)) && Number(value) >= 1 ? Math.min(Math.floor(Number(value)), maximum) : fallback;
    $('#bench-concurrency').value = setting(request?.benchmark_config?.concurrency, 50, 500);
    $('#bench-duration').value = setting(request?.benchmark_config?.duration_seconds, 5, 60);
    $('#scan-settings-note').classList.toggle('hidden', Boolean(request));
    document.querySelectorAll('[data-preset]').forEach(button => button.setAttribute('aria-pressed', String(button.dataset.preset === 'custom')));
    syncConfiguration();
}

function setBusy(busy) {
    $('#scan-form').querySelectorAll('input, button, select, textarea').forEach(element => { element.disabled = busy; });
    $('#scan-btn-text').textContent = busy ? 'Scanning…' : 'Start scan';
    $('#mobile-scan-btn').disabled = busy;
    $('#rescan-btn').disabled = busy;
    setHistoryBusy(busy);
    setWorkspaceBusy(busy);
    if (!busy) syncConfiguration();
}

function initScanForm() {
    $('#scan-form').addEventListener('submit', async event => {
        event.preventDefault();
        if (activeScan) return;
        let request;
        try { request = buildRequest(); } catch (error) { formError(error.message); return; }
        formError();
        const controller = new AbortController();
        activeScan = controller;
        setBusy(true); closeSidebar();
        showView('progress');
        hide('#scan-recovery');
        $('#progress-target').textContent = request.target_url;
        $('#terminal-output').replaceChildren();
        $('#module-progress').replaceChildren();
        $('#progress-header').classList.remove('scan-failed');
        $('#progress-header .material-symbols-outlined').classList.add('spinning');
        $('#progress-header .material-symbols-outlined').textContent = 'sync';
        $('#progress-text').textContent = 'Connecting to scan engine…';
        $('#cancel-scan-btn').disabled = false;
        show('#cancel-scan-btn');
        updateProgress(0);
        const start = performance.now();
        $('#scan-elapsed').textContent = '0s';
        const timer = setInterval(() => { $('#scan-elapsed').textContent = `${Math.floor((performance.now() - start) / 1000)}s`; }, 1000);
        const states = new Map();
        logTerminal(`> Target: ${request.target_url}`, 'prompt');
        announce('Scan started');
        try {
            const data = await startScan(request, {
                signal: controller.signal,
                onEvent(event) {
                    if (event.type === 'session') {
                        $('#progress-text').textContent = event.status === 'running' ? 'Preparing and checking the login session…' : `Session: ${event.status}`;
                    } else if (event.type === 'started') {
                        event.modules.forEach(key => {
                            const item = document.createElement('div');
                            item.className = 'module-status'; item.dataset.module = key; item.dataset.status = 'pending';
                            item.textContent = `${MODULES[key][1]} · pending`;
                            $('#module-progress').appendChild(item); states.set(key, 'pending');
                        });
                    } else if (event.type === 'module') {
                        states.set(event.module, event.status);
                        const item = [...$('#module-progress').children].find(child => child.dataset.module === event.module);
                        item.dataset.status = event.status;
                        item.textContent = `${MODULES[event.module][1]} · ${event.status === 'success' ? 'complete' : event.status}`;
                        const done = [...states.values()].filter(value => ['success', 'partial', 'error'].includes(value)).length;
                        $('#progress-text').textContent = `${done} of ${states.size} checks complete`;
                        updateProgress(Math.round(done / states.size * 100));
                        if (event.status !== 'running') logTerminal(`> ${MODULES[event.module][1]}: ${event.error || 'complete'}`, event.status === 'success' ? '' : 'warn');
                    }
                },
            });
            clearSession();
            displayResults(data);
            loadHistory();
            refreshWorkspace();
            announce(data.status === 'partial' ? 'Scan finished with incomplete checks.' : 'Scan finished.');
        } catch (error) {
            $('#progress-header .material-symbols-outlined').classList.remove('spinning');
            $('#progress-header .material-symbols-outlined').textContent = 'info';
            $('#progress-header').classList.add('scan-failed');
            const message = error.name === 'AbortError' ? 'Scan cancelled. You can start a new scan.' : error.message;
            $('#progress-text').textContent = error.name === 'AbortError' ? 'Scan cancelled' : 'Scan could not complete';
            logTerminal(`> ${message}`, error.name === 'AbortError' ? 'warn' : 'error');
            announce(message);
            formError(message);
        } finally {
            clearInterval(timer); activeScan = null; setBusy(false); hide('#cancel-scan-btn');
        }
    });
    $('#cancel-scan-btn').addEventListener('click', () => {
        $('#cancel-scan-btn').disabled = true;
        activeScan?.abort();
    });
    $('#rescan-btn').addEventListener('click', () => {
        restoreConfiguration(currentReport);
        if (!currentReport.request) { showView('scan'); return; }
        if (currentReport.authentication_used) {
            showView('scan');
            formError('This report used a login session. Supply the session again before running a new scan.');
            $('#session-cookie').closest('details').open = true;
            $('#session-cookie').focus(); return;
        }
        $('#scan-form').requestSubmit();
    });
    $('#export-json-btn').addEventListener('click', () => {
        if (!currentReport) return;
        const url = URL.createObjectURL(new Blob([JSON.stringify(currentReport, null, 2)], { type: 'application/json' }));
        const link = document.createElement('a');
        link.href = url; link.download = `localghost_report_${currentReport.scan_id}.json`;
        document.body.appendChild(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    $('#print-report-btn').addEventListener('click', () => {
        if (!currentReport) return;
        preparePrint(currentReport);
        window.print();
    });
    $('#clear-results-btn').addEventListener('click', () => {
        showView('home');
    });
}

function updateProgress(value) {
    $('#progress-bar').style.width = `${value}%`;
    $('#scan-progress-meter').setAttribute('aria-valuenow', String(value));
}

function displayResults(data) {
    currentReport = data;
    setComparisonReport(data);
    setRecheckReport(data);
    preparePrint(data);
    selectHistory(data.scan_id);
    setWorkspaceReport(data);
    $('#report-name').textContent = data.source_scan?.name || data.recheck_of?.project_name || projectIdentity(data.target).name;
    $('#report-status').textContent = data.status === 'partial' ? 'Scan incomplete' : data.status === 'error' ? 'Scan failed' : 'Scan complete';
    $('#report-status').dataset.status = data.status || 'success';
    $('#report-target').textContent = data.target;
    $('#report-connection').textContent = data.resolved_addresses?.length ? `Target addresses: ${data.resolved_addresses.join(', ')}` : '';
    const duration = data.duration_ms >= 1000 ? `${(data.duration_ms / 1000).toFixed(1)}s` : `${Math.round(data.duration_ms)}ms`;
    const observedEnvironment = data.environment_observation?.observed;
    $('#report-meta').textContent = `${formatTimestamp(data.timestamp)} · ${observedEnvironment === 'production' ? 'Production build matched' : observedEnvironment === 'development' ? 'Development server detected' : data.request?.environment ? `${data.request.environment} requested · environment unverified` : 'Older report'} · ${data.duration_ms ? `${duration} · ` : ''}Scan ${data.scan_id.slice(0, 8)}`;
    const notices = $('#report-notices');
    notices.replaceChildren();
    const groupedErrors = new Map();
    for (const [key, message] of Object.entries(data.errors || {})) groupedErrors.set(message, [...(groupedErrors.get(message) || []), MODULES[key]?.[1] || key]);
    const messages = [...(data.authentication?.status === 'error' ? [data.authentication.error] : []), ...(data.authentication?.status === 'verified' ? ['The configured login/session check passed.'] : []), ...(data.recheck_of ? ['This report repeats one check from an earlier scan. Other checks were not rerun.'] : []), ...(data.warnings || []), ...[...groupedErrors].map(([message, names]) => `${names.join(', ')}: ${message}`)];
    messages.forEach(message => {
        const item = document.createElement('p'); item.className = 'report-notice'; item.textContent = message; notices.appendChild(item);
        if (message === 'The configured login/session check passed.') item.dataset.state = 'success';
    });
    const findings = collectFindings(data).filter(f => !['pass', 'info'].includes(f.severity));
    $('#confirmed-count').textContent = data.summary?.confirmed ?? '—';
    $('#review-count').textContent = data.summary?.review ?? findings.length;
    $('#incomplete-count').textContent = data.summary?.incomplete ?? Object.values(data.module_status || {}).filter(state => ['error', 'partial'].includes(state)).length;
    $('#completed-count').textContent = data.summary?.completed ?? Object.values(data.module_status || {}).filter(state => state === 'success').length;
    const scope = $('#scope-details'); scope.replaceChildren();
    for (const note of data.scope || ['This older report has no detailed scope. Findings have not been classified as confirmed or needing review.']) {
        const item = document.createElement('li'); item.textContent = note; scope.append(item);
    }
    renderResults(data);
    $('.results-tab').click();
    $('#report-target').focus({ preventScroll: true });
    $('#main-content').scrollTop = 0;
}

function logTerminal(text, type = '') {
    const line = document.createElement('div');
    line.className = `tui-line${type ? ` tui-line--${type}` : ''}`;
    line.textContent = text; $('#terminal-output').appendChild(line);
    $('#terminal-output').scrollTop = $('#terminal-output').scrollHeight;
}
