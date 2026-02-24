/**
 * API client — centralized fetch wrappers for Localghost endpoints.
 */

const API_BASE = '/api';

export async function startScan(scanRequest) {
    const resp = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scanRequest),
    });
    if (!resp.ok) {
        const err = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(err.detail || `HTTP ${resp.status}`);
    }
    return resp.json();
}

export async function getHistory(limit = 50, offset = 0) {
    const resp = await fetch(`${API_BASE}/history?limit=${limit}&offset=${offset}`);
    if (!resp.ok) throw new Error(`Failed to load history`);
    return resp.json();
}

export async function getScanDetail(scanId) {
    const resp = await fetch(`${API_BASE}/history/${scanId}`);
    if (!resp.ok) throw new Error(`Scan not found`);
    return resp.json();
}

export async function deleteScan(scanId) {
    const resp = await fetch(`${API_BASE}/history/${scanId}`, { method: 'DELETE' });
    return resp.ok;
}

export function getReportUrl(scanId) {
    return `${API_BASE}/report/${scanId}`;
}
