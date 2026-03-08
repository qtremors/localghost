/** Accessible, paginated history using text nodes for target-controlled content. */
import { getHistory, getScanDetail, deleteScan } from './api.js';
import { formatTimestamp } from './utils.js';

let onSelect;
let busy = false;
let selected = null;
let scans = [];
let selectionController;
let loadVersion = 0;
let historyController;
let searchTimer;
const PAGE_SIZE = 20;

export function initHistory(handler) {
    onSelect = handler;
    document.addEventListener('workspace-navigation', () => selectionController?.abort());
    document.getElementById('history-more').addEventListener('click', () => loadHistory(true));
    document.getElementById('history-refresh').addEventListener('click', async () => {
        await loadHistory();
        document.dispatchEvent(new CustomEvent('history-updated'));
    });
    document.getElementById('history-search').addEventListener('input', () => {
        clearTimeout(searchTimer);
        historyController?.abort();
        // Invalidate previous pages immediately, before the debounce expires.
        loadVersion++;
        document.getElementById('history-more').disabled = true;
        searchTimer = setTimeout(() => loadHistory(), 200);
    });
}
export function setHistoryBusy(value) {
    busy = value;
    if (busy) selectionController?.abort();
    document.querySelectorAll('.history-item button, .history-controls button').forEach(button => { button.disabled = value; });
}
export function selectHistory(scanId) {
    selected = scanId;
    document.querySelectorAll('.history-item').forEach(item => {
        const active = item.dataset.scanId === selected;
        item.classList.toggle('history-item--active', active);
        item.querySelector('.history-open').setAttribute('aria-pressed', String(active));
    });
}
function status(message) { document.getElementById('history-status').textContent = message; }

export async function loadHistory(append = false) {
    clearTimeout(searchTimer);
    const version = ++loadVersion;
    historyController?.abort();
    const controller = new AbortController();
    historyController = controller;
    const more = document.getElementById('history-more');
    more.disabled = true;
    status('Loading history…');
    try {
        const query = document.getElementById('history-search').value.trim();
        const data = await getHistory(PAGE_SIZE, append ? scans.length : 0, { query, signal: controller.signal });
        if (version !== loadVersion) return;
        scans = append ? [...scans, ...data.scans] : data.scans;
        scans = [...new Map(scans.map(scan => [scan.scan_id, scan])).values()];
        renderHistory();
        status(`${data.total} ${query ? 'matching' : 'saved'} scan${data.total === 1 ? '' : 's'}`);
        more.classList.toggle('hidden', scans.length >= data.total);
    } catch (error) {
        if (version === loadVersion && error.name !== 'AbortError') status(error.message);
    } finally {
        if (version === loadVersion) more.disabled = busy;
    }
}

function renderHistory() {
    const container = document.getElementById('history-list');
    container.replaceChildren();
    if (!scans.length) {
        const empty = document.createElement('p'); empty.className = 'history-list__empty';
        empty.textContent = document.getElementById('history-search').value.trim()
            ? 'No saved targets match your search.' : 'No scans yet. Your reports will appear here.';
        container.appendChild(empty);
        return;
    }
    for (const scan of scans) {
        const row = document.createElement('div');
        row.className = 'history-item'; row.dataset.scanId = scan.scan_id;
        const open = document.createElement('button');
        open.type = 'button'; open.className = 'history-open'; open.disabled = busy;
        open.title = `${scan.target} · ${formatTimestamp(scan.timestamp)}`;
        open.setAttribute('aria-label', `Open scan of ${scan.target}, ${formatTimestamp(scan.timestamp)}`);
        const score = document.createElement('span'); score.className = 'history-item__score';
        score.textContent = scan.confirmed == null ? '—' : scan.confirmed;
        const label = document.createElement('small'); label.textContent = scan.confirmed == null ? 'Older' : 'Confirmed';
        score.appendChild(label);
        const target = document.createElement('span'); target.className = 'history-item__target'; target.textContent = scan.target;
        const time = document.createElement('span'); time.className = 'history-item__time'; time.textContent = formatTimestamp(scan.timestamp);
        open.append(score, target, time);
        open.addEventListener('click', async () => {
            if (busy) return;
            selectionController?.abort();
            const controller = new AbortController(); selectionController = controller;
            status('Loading report…');
            try {
                const detail = await getScanDetail(scan.scan_id, controller.signal);
                if (!busy && !controller.signal.aborted) {
                    onSelect(detail.results);
                    status('Report loaded');
                }
            } catch (error) { if (error.name !== 'AbortError') status(error.message); }
        });
        const remove = document.createElement('button');
        remove.type = 'button'; remove.className = 'history-delete'; remove.textContent = '×';
        remove.setAttribute('aria-label', `Delete scan of ${scan.target}`); remove.disabled = busy;
        remove.addEventListener('click', () => {
            if (busy) return;
            const dialog = document.getElementById('delete-history-dialog');
            dialog.returnValue = 'cancel';
            dialog.addEventListener('close', async () => {
                if (dialog.returnValue !== 'delete' || busy) return;
                remove.disabled = true;
                try {
                    await deleteScan(scan.scan_id);
                    await loadHistory();
                    document.dispatchEvent(new CustomEvent('history-updated'));
                } catch (error) { status(error.message); remove.disabled = busy; }
            }, { once: true });
            dialog.showModal();
        });
        row.append(open, remove); container.appendChild(row);
    }
    selectHistory(selected);
}
