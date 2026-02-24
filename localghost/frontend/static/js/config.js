/** Pure configuration helpers shared by the form and regression tests. */
export const MODULES = {
    port_scan: ['ports', 'Ports'], vuln_scan: ['vulns', 'Headers & files'],
    ssl_scan: ['ssl', 'SSL/TLS'], cors_scan: ['cors', 'CORS'],
    cookie_scan: ['cookies', 'Cookies'], tech_detect: ['tech', 'Technologies'],
    dns_scan: ['dns', 'DNS'], load_test: ['bench', 'Load test'],
    source_scan: ['source', 'Project details'], browser_check: ['browser', 'Pages'],
    ddos_test: ['ddos', 'Traffic test'], rate_limit_test: ['ratelimit', 'Rate limits'], xss_scan: ['xss', 'Input checks'],
};
export function parsePorts(value) {
    if (!value.trim()) return null;
    const ports = new Set();
    for (const part of value.split(',')) {
        const match = part.trim().match(/^(\d+)(?:\s*-\s*(\d+))?$/);
        if (!match) throw new Error('Use comma-separated ports or ranges, e.g. 80, 443, 3000-3010.');
        const start = Number(match[1]);
        const end = Number(match[2] ?? match[1]);
        if (start < 1 || end > 65535 || start > end) throw new Error('Ports must be between 1 and 65535, with ranges in ascending order.');
        if (end - start >= 1024) throw new Error('Choose at most 1,024 ports.');
        for (let port = start; port <= end; port++) {
            ports.add(port);
            if (ports.size > 1024) throw new Error('Choose at most 1,024 ports.');
        }
    }
    return [...ports].sort((a, b) => a - b);
}
