/**
 * DOM utility helpers and formatters.
 */

export function $(selector) {
    return document.querySelector(selector);
}

export function $$(selector) {
    return document.querySelectorAll(selector);
}

export function show(el) {
    if (typeof el === 'string') el = $(el);
    el?.classList.remove('hidden');
}

export function hide(el) {
    if (typeof el === 'string') el = $(el);
    el?.classList.add('hidden');
}

export function formatTimestamp(isoString) {
    try {
        const d = new Date(isoString);
        return d.toLocaleString(undefined, {
            month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    } catch {
        return isoString;
    }
}

export function severityIcon(severity) {
    const icons = {
        critical: 'gpp_bad',
        high: 'warning',
        medium: 'info',
        low: 'info',
        info: 'help',
        pass: 'check_circle',
    };
    return icons[severity] || 'help';
}

export function severityOrder(severity) {
    const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4, pass: 5 };
    return order[severity] ?? 6;
}

export function getScoreColor(score) {
    if (score >= 80) return 'var(--severity-pass)';
    if (score >= 60) return 'var(--severity-medium)';
    if (score >= 40) return 'var(--severity-high)';
    return 'var(--severity-critical)';
}

export function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
