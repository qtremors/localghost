/** API client with structured validation errors and incremental scan progress. */
const API_BASE = '/api';

async function checkResponse(response) {
    if (response.ok) return response;
    const error = await response.json().catch(() => ({}));
    const detail = error.detail;
    const message = Array.isArray(detail)
        ? detail.map(item => `${item.loc?.slice(1).join('.') || 'Request'}: ${item.msg}`).join('; ')
        : typeof detail === 'string' ? detail : `Request failed (HTTP ${response.status})`;
    throw new Error(message);
}

export async function startScan(request, { signal, onEvent } = {}) {
    const response = await checkResponse(await fetch(`${API_BASE}/scan/stream`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request), signal,
    }));
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    let result;
    function processLine(line) {
        if (!line.trim()) return;
        const event = JSON.parse(line);
        if (event.type === 'error') throw new Error(event.message);
        onEvent?.(event);
        if (event.type === 'complete') result = event.result;
    }
    try {
        while (true) {
            const { value, done } = await reader.read();
            buffer += done ? decoder.decode() : decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop();
            lines.forEach(processLine);
            if (done) break;
        }
        processLine(buffer);
    } finally {
        await reader.cancel().catch(() => {});
        reader.releaseLock();
    }
    if (!result) throw new Error('The connection ended before the scan completed. Try again.');
    return result;
}

export async function getHistory(limit = 20, offset = 0, { query = '', target, signal } = {}) {
    const params = new URLSearchParams({ limit, offset });
    if (query) params.set('q', query);
    if (target !== undefined) params.set('target', target);
    return (await checkResponse(await fetch(`${API_BASE}/history?${params}`, { signal }))).json();
}
export async function getScanDetail(scanId, signal) {
    return (await checkResponse(await fetch(`${API_BASE}/history/${encodeURIComponent(scanId)}`, { signal }))).json();
}
export async function deleteScan(scanId) {
    return (await checkResponse(await fetch(`${API_BASE}/history/${encodeURIComponent(scanId)}`, { method: 'DELETE' }))).json();
}

export async function getComparison(scanId, baselineId, signal) {
    return (await checkResponse(await fetch(`${API_BASE}/history/${encodeURIComponent(scanId)}/comparison/${encodeURIComponent(baselineId)}`, { signal }))).json();
}

export async function discoverProjects(signal) {
    return (await checkResponse(await fetch(`${API_BASE}/projects/discover`, { method: 'POST', signal }))).json();
}

export async function getProjects(limit = 24, offset = 0, signal) {
    return (await checkResponse(await fetch(`${API_BASE}/projects?${new URLSearchParams({ limit, offset })}`, { signal }))).json();
}

export async function inspectSource(source_path) {
    return (await checkResponse(await fetch(`${API_BASE}/projects/inspect`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ source_path }),
    }))).json();
}

export async function recheckFinding(scanId, findingId, session) {
    return (await checkResponse(await fetch(`${API_BASE}/history/${encodeURIComponent(scanId)}/findings/${encodeURIComponent(findingId)}/recheck`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ session }),
    }))).json();
}

export async function discoverDocker(signal) {
    return (await checkResponse(await fetch(`${API_BASE}/projects/docker`, { method: 'POST', signal }))).json();
}
