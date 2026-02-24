/**
 * Localghost — Main application entry point.
 * Initializes all modules, binds events, and orchestrates the scan flow.
 */

import { startScan, getReportUrl } from './api.js';
import { initTheme } from './theme.js';
import { renderResults } from './results.js';
import { renderScoreGauge, renderBreakdown } from './score.js';
import { loadHistory, setHistorySelectHandler } from './history.js';
import { $, show, hide } from './utils.js';

// ─── Initialize ───
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initSidebar();
    initTabs();
    initScanForm();
    initBenchToggle();
    loadHistory();
});

// ─── Sidebar Toggle (mobile) ───
function initSidebar() {
    const toggle = $('#menu-toggle');
    const sidebar = $('#sidebar');
    const overlay = $('#sidebar-overlay');

    toggle?.addEventListener('click', () => {
        sidebar.classList.toggle('open');
    });

    overlay?.addEventListener('click', () => {
        sidebar.classList.remove('open');
    });
}

// ─── Tab Switching ───
function initTabs() {
    const tabContainer = $('#results-tabs');
    if (!tabContainer) return;

    tabContainer.addEventListener('click', (e) => {
        const tab = e.target.closest('.results-tab');
        if (!tab) return;

        // Deactivate all
        tabContainer.querySelectorAll('.results-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.results-panel').forEach(p => p.classList.remove('active'));

        // Activate clicked
        tab.classList.add('active');
        const panel = $(`#panel-${tab.dataset.tab}`);
        if (panel) panel.classList.add('active');
    });
}

// ─── Show/hide bench config when toggle changes ───
function initBenchToggle() {
    const benchCheckbox = $('#mod-bench');
    const benchConfig = $('#bench-config');
    if (!benchCheckbox || !benchConfig) return;

    benchCheckbox.addEventListener('change', () => {
        if (benchCheckbox.checked) {
            show(benchConfig);
        } else {
            hide(benchConfig);
        }
    });
}

// ─── Scan Form ───
function initScanForm() {
    const form = $('#scan-form');
    const scanBtn = $('#scan-btn');
    const btnText = $('#scan-btn-text');

    // History select handler — display results from a past scan
    setHistorySelectHandler((scanData) => {
        displayResults(scanData);
        // Close sidebar on mobile
        $('#sidebar')?.classList.remove('open');
    });

    form?.addEventListener('submit', async (e) => {
        e.preventDefault();

        const targetUrl = $('#target-url')?.value?.trim();
        if (!targetUrl) return;

        // Build request
        const request = {
            target_url: targetUrl,
            modules: {
                port_scan: $('#mod-ports')?.checked ?? true,
                vuln_scan: $('#mod-vulns')?.checked ?? true,
                ssl_scan: $('#mod-ssl')?.checked ?? true,
                cors_scan: $('#mod-cors')?.checked ?? true,
                cookie_scan: $('#mod-cookies')?.checked ?? true,
                tech_detect: $('#mod-tech')?.checked ?? true,
                dns_scan: $('#mod-dns')?.checked ?? true,
                load_test: $('#mod-bench')?.checked ?? false,
                ddos_test: $('#mod-ddos')?.checked ?? false,
                rate_limit_test: $('#mod-ratelimit')?.checked ?? false,
                xss_scan: $('#mod-xss')?.checked ?? false,
            },
            benchmark_config: {
                concurrency: parseInt($('#bench-concurrency')?.value) || 50,
                duration_seconds: parseInt($('#bench-duration')?.value) || 5,
            },
        };

        // Enter loading state
        scanBtn.disabled = true;
        btnText.textContent = 'Scanning...';
        hide('#empty-state');
        hide('#results-dashboard');
        show('#scan-progress');
        clearTerminal();
        logTerminal('> Initializing scan engine...', 'prompt');
        logTerminal(`> Target: ${targetUrl}`);

        // Log which modules are active
        const activeModules = Object.entries(request.modules)
            .filter(([, v]) => v)
            .map(([k]) => k.replace('_', ' '));
        logTerminal(`> Modules: ${activeModules.join(', ')}`, 'dim');
        logTerminal('> Running scans concurrently...');

        try {
            const data = await startScan(request);

            logTerminal('> Scan complete!', 'prompt');
            logTerminal(`> Security Score: ${data.score?.score}/100 (${data.score?.grade})`);
            logTerminal(`> Scan ID: ${data.scan_id}`, 'dim');

            // Small delay for the terminal to be visible
            await sleep(500);

            displayResults(data);

            // Refresh history
            loadHistory();

        } catch (error) {
            logTerminal(`> ERROR: ${error.message}`, 'error');
            logTerminal('> Scan failed. Check if the target is reachable.', 'error');
        } finally {
            scanBtn.disabled = false;
            btnText.textContent = 'Start Scan';
        }
    });

    // Export JSON button
    $('#export-json-btn')?.addEventListener('click', () => {
        const scanId = currentScanId;
        if (scanId) {
            window.open(getReportUrl(scanId), '_blank');
        }
    });

    // Clear results button
    $('#clear-results-btn')?.addEventListener('click', () => {
        hide('#results-dashboard');
        hide('#scan-progress');
        show('#empty-state');
        currentScanId = null;
    });
}

// ─── Current scan state ───
let currentScanId = null;

function displayResults(data) {
    currentScanId = data.scan_id;

    hide('#scan-progress');
    hide('#empty-state');
    show('#results-dashboard');

    // Render score gauge
    if (data.score) {
        renderScoreGauge(data.score.score, data.score.grade);
        if (data.score.breakdown) {
            renderBreakdown(data.score.breakdown);
        }
    }

    // Render all result panels
    renderResults(data);

    // Reset to first tab
    const firstTab = document.querySelector('.results-tab');
    if (firstTab) firstTab.click();
}


// ─── Terminal Output ───
function clearTerminal() {
    const body = $('#terminal-output');
    if (body) body.innerHTML = '';
}

function logTerminal(text, type = '') {
    const body = $('#terminal-output');
    if (!body) return;

    const line = document.createElement('div');
    line.className = `tui-line${type ? ` tui-line--${type}` : ''}`;
    line.textContent = text;
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
