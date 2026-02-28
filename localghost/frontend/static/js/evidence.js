/** Render captured exchanges and source excerpts consistently on screen and in exports. */
import { escapeHtml as escape } from './utils.js';

function headers(values) {
    return Object.entries(values || {}).map(([key, value]) => `${key}: ${value}`).join('\n');
}
export function evidenceHTML(item) {
    const request = `${item.method} ${item.url}${Object.keys(item.request_headers || {}).length ? '\n' + headers(item.request_headers) : ''}${item.request_body ? '\n\n' + item.request_body : ''}${Object.keys(item.request_details || {}).length ? '\n' + JSON.stringify(item.request_details, null, 2) : ''}`;
    const response = `${item.status == null ? item.error ? 'No response: ' + item.error : '' : 'HTTP ' + item.status}${Object.keys(item.response_headers || {}).length ? '\n' + headers(item.response_headers) : ''}${item.response_body_excerpt != null ? '\n\n' + item.response_body_excerpt : ''}${Object.keys(item.response_details || {}).length ? '\n' + JSON.stringify(item.response_details, null, 2) : ''}`;
    return `<div class="captured-evidence">${item.page_url ? `<p>Affected page: <code>${escape(item.page_url)}</code></p>` : ''}
        ${item.source_file ? `<p><code>${escape(item.source_file)}${item.source_line ? ':' + escape(item.source_line) : ''}</code></p><pre>${escape(item.source_excerpt || '')}</pre>`
            : `<p class="evidence-heading">${item.captured ? 'Captured request' : 'Observation'}</p><pre>${escape(request)}</pre>${response ? `<p class="evidence-heading">${item.captured ? 'Captured response' : 'Response summary'}</p><pre>${escape(response)}</pre>` : ''}`}
        <p>${escape(item.observation)}</p>${item.response_body_truncated ? '<p class="config-note">The body excerpt is shortened. Credential values are redacted.</p>' : ''}</div>`;
}
