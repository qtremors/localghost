/** Project identity comes from a URL origin; paths remain attached to each report. */
export function projectIdentity(target) {
    try {
        const url = new URL(target);
        return { key: url.origin, name: `${url.hostname}${url.port ? `:${url.port}` : ''}`, origin: url.origin };
    } catch {
        return { key: target, name: target, origin: target };
    }
}
