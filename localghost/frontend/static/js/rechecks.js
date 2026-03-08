/** Recheck one finding without replacing the original evidence. */
import { recheckFinding } from './api.js';
import { preparePrint } from './print.js';
import { openSavedReport } from './workspace.js';

let report;
let running = false;
let handlers;
const $ = id => document.getElementById(id);

export function setRecheckReport(value) { report = value; }

function sessionFromDialog() {
    return new Promise(resolve => {
        const dialog = $('recheck-session-dialog');
        $('recheck-cookie').value = ''; $('recheck-authorization').value = ''; $('recheck-session-json').value = '';
        const profile = report.authentication?.profile || {};
        $('recheck-username').value = ''; $('recheck-password').value = '';
        $('recheck-login-fields').classList.toggle('hidden', !profile.login);
        $('recheck-login-note').textContent = profile.login ? `Sign in at ${profile.login.path}. The original selectors will be reused.` : '';
        $('recheck-assertion-note').textContent = profile.check_path || profile.check_selector ? `The original session check will be repeated: ${profile.check_path || report.target}${profile.check_selector ? ' · ' + profile.check_selector : ''}.` : 'The original report did not verify that the session was signed in.';
        dialog.returnValue = 'cancel';
        dialog.addEventListener('close', () => {
            let session = null;
            try { session = dialog.returnValue === 'check' ? { ...($('recheck-session-json').value.trim() ? JSON.parse($('recheck-session-json').value) : {}), ...($('recheck-cookie').value ? {cookie: $('recheck-cookie').value} : {}), ...($('recheck-authorization').value ? {authorization: $('recheck-authorization').value} : {}) } : null; }
            catch { $('app-status').textContent = 'Session settings must be a valid JSON object.'; }
            if (session && profile.login && ($('recheck-username').value || $('recheck-password').value)) session.login = {...profile.login, username: $('recheck-username').value, password: $('recheck-password').value};
            $('recheck-username').value = ''; $('recheck-password').value = '';
            $('recheck-cookie').value = ''; $('recheck-authorization').value = ''; $('recheck-session-json').value = '';
            resolve(session);
        }, { once: true });
        dialog.showModal();
    });
}

export function initRechecks(callbacks) {
    handlers = callbacks;
    $('results-dashboard').addEventListener('click', async event => {
        const evidenceLink = event.target.closest('[data-evidence-report]');
        if (evidenceLink && !running) { event.preventDefault(); openSavedReport(evidenceLink.dataset.evidenceReport); return; }
        const button = event.target.closest('[data-recheck]');
        if (!button || running || !report) return;
        const original = report;
        const id = button.dataset.recheck;
        const output = button.closest('.finding').querySelector('.finding__recheck-status');
        running = true;
        let session = null;
        if (original.authentication_used) {
            session = await sessionFromDialog();
            if (!session) { running = false; return; }
        }
        handlers.setBusy(true);
        document.querySelectorAll('[data-recheck]').forEach(control => { control.disabled = true; });
        button.textContent = 'Checking…'; output.textContent = 'Running the relevant check again…';
        try {
            const result = await recheckFinding(original.scan_id, id, session);
            original.rechecks = [...(original.rechecks || []), result];
            const finding = original.findings.find(item => item.id === id);
            const label = result.state === 'resolved' && finding?.verification === 'not_checked' ? 'Check completed in this recheck' : { resolved: 'Resolved in this recheck', still_present: 'Still present', not_checked: 'Could not verify the fix' }[result.state];
            output.replaceChildren(document.createTextNode(`${label}. `));
            if (result.saved) {
                const link = document.createElement('a'); link.href = `#report/${encodeURIComponent(result.scan_id)}`;
                link.textContent = 'View new evidence';
                link.dataset.evidenceReport = result.scan_id;
                output.append(link);
            }
            if (result.unsaved_report) {
                const download = document.createElement('button'); download.type = 'button'; download.className = 'preset-btn';
                download.textContent = 'Download unsaved evidence';
                download.addEventListener('click', () => {
                    const url = URL.createObjectURL(new Blob([JSON.stringify(result.unsaved_report, null, 2)], { type: 'application/json' }));
                    const link = document.createElement('a'); link.href = url; link.download = `localghost_recheck_${result.scan_id}.json`; link.click();
                    setTimeout(() => URL.revokeObjectURL(url), 1000);
                });
                output.append(document.createTextNode('New evidence could not be saved. '), download);
            }
            output.dataset.state = result.state;
            $('app-status').textContent = label;
            preparePrint(original);
            handlers.refresh();
        } catch (error) { output.textContent = error.message; }
        finally {
            session = null; running = false;
            handlers.setBusy(false);
            document.querySelectorAll('[data-recheck]').forEach(control => { control.disabled = false; });
            button.textContent = 'Check again';
        }
    });
}
