/** Shared finding normalization and filtering for screen and print reports. */
import { severityOrder } from './utils.js';
import { MODULES } from './config.js';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'pass'];
export const ACTIONABLE = SEVERITIES.slice(0, 4);
export function collectFindings(report) {
    if (Array.isArray(report.findings)) return report.findings;
    return Object.keys(MODULES).flatMap(module =>
        (report[module]?.findings || []).map(finding => ({ ...finding, module })))
        .sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));
}
export function countSeverities(findings) {
    return Object.fromEntries(SEVERITIES.map(severity => [severity, findings.filter(finding => finding.severity === severity).length]));
}
export function filterFindings(findings, { query = '', severity = 'all', module = 'all', verification = 'all', includePassed = false } = {}) {
    const text = query.trim().toLowerCase();
    return findings.filter(finding =>
        (finding.severity !== 'info' || finding.verification === 'not_checked' || includePassed || severity === 'info' || text) &&
        (includePassed || finding.severity !== 'pass' || severity === 'pass' || verification === 'not_checked') &&
        (verification === 'all' || (finding.verification || 'review') === verification) &&
        (severity === 'all' || finding.severity === severity) &&
        (module === 'all' || finding.module === module) &&
        `${finding.title} ${finding.description} ${finding.recommendation || ''} ${MODULES[finding.module]?.[1] || ''}`.toLowerCase().includes(text));
}
