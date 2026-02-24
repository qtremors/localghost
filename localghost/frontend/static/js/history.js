/**
 * Scan history management — sidebar list and history loading.
 */

import { getHistory, getScanDetail } from './api.js';
import { formatTimestamp, getScoreColor } from './utils.js';

let onHistorySelect = null;

export function setHistorySelectHandler(handler) {
    onHistorySelect = handler;
}

export async function loadHistory() {
    const container = document.getElementById('history-list');
    if (!container) return;

    try {
        const data = await getHistory(20);
        if (!data.scans || data.scans.length === 0) {
            container.innerHTML = '<p class="history-list__empty">No scans yet</p>';
            return;
        }

        container.innerHTML = data.scans.map(scan => `
            <div class="history-item" data-scan-id="${scan.scan_id}" title="${scan.target}">
                <span class="history-item__score" style="color:${getScoreColor(scan.score)}">${scan.score}</span>
                <span class="history-item__target">${scan.target}</span>
                <span class="history-item__time">${formatTimestamp(scan.timestamp)}</span>
            </div>
        `).join('');

        // Attach click handlers
        container.querySelectorAll('.history-item').forEach(item => {
            item.addEventListener('click', async () => {
                const scanId = item.dataset.scanId;
                if (onHistorySelect) {
                    try {
                        const detail = await getScanDetail(scanId);
                        onHistorySelect(detail.results);
                    } catch (e) {
                        console.error('Failed to load scan detail:', e);
                    }
                }
            });
        });
    } catch (e) {
        container.innerHTML = '<p class="history-list__empty">Could not load history</p>';
    }
}
