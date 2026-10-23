/** Load the independent capture interface inside the shared workspace shell. */
export function initXcrape() {
    const root = document.getElementById('xcrape-view');
    let mounted = false;
    let loading = false;
    async function load() {
        if (mounted || loading) return;
        loading = true;
        try {
            const response = await fetch('/static/xcrape/view.html');
            if (!response.ok) throw new Error('Could not open Captures. Try again.');
            // This is our own static template. Captured page content is rendered as text.
            const markup = await response.text();
            const headingFocused = document.activeElement === root.querySelector('#xcrape-heading');
            root.innerHTML = markup;
            mountXcrape(root);
            mounted = true;
            if (headingFocused && !root.classList.contains('hidden')) {
                root.querySelector('#xcrape-heading').focus({ preventScroll: true });
            }
        } catch (error) {
            const message = document.createElement('p');
            message.setAttribute('role', 'alert');
            message.textContent = error.message;
            const retry = document.createElement('button');
            retry.type = 'button';
            retry.className = 'md-btn md-btn--outlined';
            retry.textContent = 'Try again';
            retry.addEventListener('click', load);
            root.append(message, retry);
        } finally {
            loading = false;
        }
    }
    document.addEventListener('workspace-view', (event) => {
        if (event.detail === 'xcrape') load();
    });
}

function mountXcrape(root) {

    // Scraped content is always text or a validated URL, never an HTML template.
    const $ = (id) => root.querySelector('#xc-' + id);
    const paths = {
        layers: ['m12 3 9 5-9 5-9-5 9-5Z', 'm3 12 9 5 9-5', 'm3 16 9 5 9-5'],
        monitor: ['M4 4h16v12H4z', 'M8 21h8', 'M12 16v5'],
        capture: [
            'M8 3H4a1 1 0 0 0-1 1v4',
            'M16 3h4a1 1 0 0 1 1 1v4',
            'M21 16v4a1 1 0 0 1-1 1h-4',
            'M8 21H4a1 1 0 0 1-1-1v-4',
            'M8 8h8v8H8z',
        ],
        link: [
            'M10 13a5 5 0 0 0 7 .3l3-3a5 5 0 0 0-7-7l-2 2',
            'M14 11a5 5 0 0 0-7-.3l-3 3a5 5 0 0 0 7 7l2-2',
        ],
        'arrow-right': ['M4 12h16', 'm14 6 6 6-6 6'],
        'arrow-left': ['M20 12H4', 'm10 6-6 6 6 6'],
        'chevron-down': ['m6 9 6 6 6-6'],
        info: ['M12 8h.01', 'M12 11v6', 'M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0Z'],
        refresh: ['M20 11a8 8 0 0 0-14-5L3 9', 'M3 3v6h6', 'M4 13a8 8 0 0 0 14 5l3-3', 'M21 21v-6h-6'],
        search: ['M17 10a7 7 0 1 1-14 0 7 7 0 0 1 14 0Z', 'm15 15 6 6'],
        page: [
            'M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-6-6Z',
            'M14 3v6h6',
            'M8 13h8',
            'M8 17h5',
        ],
        download: ['M12 3v12', 'm7 10 5 5 5-5', 'M4 16v4a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-4'],
        close: ['m6 6 12 12', 'M18 6 6 18'],
        trash: ['M3 6h18', 'M9 6V3h6v3', 'm5 6 1 15h12l1-15', 'M10 10v7', 'M14 10v7'],
        check: ['m5 12 4 4L19 6'],
        external: [
            'M14 3h7v7',
            'm10 14 11-11',
            'M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5',
        ],
        copy: ['M9 9h12v12H9z', 'M15 9V3H3v12h6'],
    };

    function icon(name) {
        const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        svg.setAttribute('viewBox', '0 0 24 24');
        svg.setAttribute('class', 'icon');
        svg.setAttribute('aria-hidden', 'true');
        (paths[name] || paths.page).forEach((d) => {
            const path = document.createElementNS(svg.namespaceURI, 'path');
            path.setAttribute('d', d);
            svg.append(path);
        });
        return svg;
    }

    function el(tag, attrs = {}, ...children) {
        const node = document.createElement(tag);
        if (tag === 'pre') node.tabIndex = 0;
        for (const [key, value] of Object.entries(attrs)) {
            if (value === null || value === undefined) continue;
            if (key === 'class') node.className = value;
            else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
            else if (key in node && !key.startsWith('aria-') && key !== 'role') node[key] = value;
            else node.setAttribute(key, String(value));
        }
        for (const child of children.flat(Infinity)) {
            if (child !== null && child !== undefined)
                node.append(child instanceof Node ? child : String(child));
        }
        return node;
    }

    root.querySelectorAll('[data-icon]').forEach((node) => node.append(icon(node.dataset.icon)));

    const labels = {
        pending: 'Waiting',
        running: 'Capturing',
        completed: 'Saved',
        failed: 'Needs attention',
    };
    const state = {
        page: 1,
        pageSize: 20,
        query: '',
        status: '',
        jobs: [],
        total: 0,
        selected: null,
        job: null,
        data: null,
        tab: 'overview',
    };
    let listController, detailController, searchTimer, pollTimer, toastTimer, deleteTarget;
    let listSignature = '';

    function safeUrl(value, image = false) {
        if (typeof value !== 'string') return null;
        if (image && /^data:image\/(png|jpeg|webp|gif|avif|svg\+xml|bmp);base64,/i.test(value))
            return value;
        try {
            const url = new URL(value);
            return ['http:', 'https:'].includes(url.protocol) ? url.href : null;
        } catch {
            return null;
        }
    }

    function address(value) {
        try {
            const url = new URL(value);
            return url.host + (url.pathname === '/' ? '' : url.pathname) + url.search;
        } catch {
            return String(value || 'Untitled page');
        }
    }

    function date(value, full = false) {
        if (!value) return ' - ';
        const iso = value.replace(' ', 'T');
        const parsed = new Date(/Z$|[+-]\d\d:\d\d$/.test(iso) ? iso : iso + 'Z');
        if (Number.isNaN(parsed.getTime())) return ' - ';
        return full
            ? parsed.toLocaleString()
            : parsed.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    }

    function number(value) {
        return new Intl.NumberFormat().format(Number(value) || 0);
    }
    function pretty(value) {
        return JSON.stringify(value, null, 2);
    }
    function withoutScreenshot(data) {
        const { screenshot, ...rest } = data || {};
        return rest;
    }
    function badge(status) {
        return el(
            'span',
            { class: 'status ' + (labels[status] ? status : 'pending') },
            labels[status] || 'Unknown',
        );
    }

    function positionToast() {
        ($('deleteDialog').open
            ? $('deleteDialog')
            : $('detailDialog').open
              ? $('detailDialog')
              : root
        ).append($('toastRegion'));
    }

    function toast(message, error = false) {
        positionToast();
        clearTimeout(toastTimer);
        $('toastRegion').replaceChildren(
            el(
                'div',
                { class: 'toast' + (error ? ' error' : '') },
                icon(error ? 'info' : 'check'),
                el('span', {}, message),
            ),
        );
        toastTimer = setTimeout(() => $('toastRegion').replaceChildren(), 5000);
    }

    async function request(url, options = {}) {
        const response = await fetch(url, options);
        let data;
        try {
            data = await response.json();
        } catch {
            data = {};
        }
        if (!response.ok) {
            const detail = Array.isArray(data.detail)
                ? data.detail.map(item => item.msg).filter(Boolean).join(' ')
                : data.detail;
            const error = new Error(data.error || detail || 'Check the address and capture options, then try again.');
            error.status = response.status;
            throw error;
        }
        return data;
    }

    function connection(ok) {
        $('connectionDot').classList.toggle('offline', !ok);
        $('connectionLabel').textContent = ok ? 'Saved on this device' : 'Connection lost';
    }

    function enableExport(enabled) {
        const menu = $('exportMenu');
        menu.classList.toggle('disabled', !enabled);
        const summary = menu.querySelector('summary');
        summary.tabIndex = enabled ? 0 : -1;
        summary.setAttribute('aria-disabled', String(!enabled));
        if (!enabled) menu.open = false;
    }

    async function refreshJobs() {
        listController?.abort();
        const controller = new AbortController();
        listController = controller;
        const params = new URLSearchParams({ page: state.page, page_size: state.pageSize });
        if (state.query) params.set('q', state.query);
        if (state.status) params.set('status', state.status);
        $('refreshButton').disabled = true;
        try {
            const result = await request('/api/xcrape/jobs?' + params, { signal: controller.signal });
            if (controller !== listController) return;
            state.jobs = result.jobs;
            state.total = result.total;
            if (!state.jobs.length && state.page > 1) {
                state.page = Math.max(1, Math.ceil(state.total / state.pageSize));
                return refreshJobs();
            }
            const count = Object.values(result.counts).reduce((sum, n) => sum + n, 0);
            $('libraryCount').textContent = number(count);
            $('totalLabel').textContent =
                number(result.total) + (result.total === 1 ? ' page' : ' pages');
            const working = result.counts.pending + result.counts.running;
            $('workingLabel').hidden = !working;
            $('workingLabel').textContent = number(working) + ' in progress';
            const signature = pretty([state.jobs, state.query, state.status]);
            if (signature !== listSignature) {
                renderJobs();
                listSignature = signature;
            }
            updatePagination();
            $('listError').hidden = true;
            connection(true);
            if (state.selected && state.job && ['pending', 'running'].includes(state.job.status))
                await loadDetail(state.selected);
        } catch (error) {
            if (error.name === 'AbortError') return;
            connection(false);
            $('listError').textContent = error.status === 503 ? error.message :
                'Can’t reach the app. Check that it’s running, then try Refresh.';
            if (error.status === 503) $('connectionLabel').textContent = 'Captures unavailable';
            $('listError').hidden = false;
            if (!listSignature) {
                $('emptyTitle').textContent = 'Your pages couldn’t be loaded';
                $('emptyDescription').textContent =
                    'Your saved pages are still on this device. Try refreshing in a moment.';
            }
        } finally {
            if (controller === listController) {
                $('refreshButton').disabled = false;
                $('historySurface').setAttribute('aria-busy', 'false');
            }
        }
    }

    function renderJobs() {
        const empty = !state.jobs.length;
        $('emptyState').hidden = !empty;
        $('tableWrap').hidden = empty;
        if (empty) {
            const filtered = Boolean(state.query || state.status);
            $('emptyTitle').textContent = filtered ? 'No pages found' : 'Your first page starts here';
            $('emptyDescription').textContent = filtered
                ? 'Try another search or clear your filters.'
                : 'Enter an address above. Your captures will appear here.';
            $('emptyAction').hidden = false;
            $('emptyAction').replaceChildren(
                filtered ? 'Clear filters' : 'Capture your first page',
                icon('arrow-right'),
            );
            return;
        }
        const focused = document.activeElement?.closest('[data-job]');
        const focusJob = focused?.dataset.job;
        const focusAction = focused?.dataset.action;
        const rows = state.jobs.map((job) => {
            const title = job.title || address(job.url);
            const open = el(
                'button',
                {
                    class: 'page-cell',
                    type: 'button',
                    'data-job': job.id,
                    'data-action': 'open',
                    'aria-label': 'Open ' + title,
                    onclick: () => openDetail(job.id),
                },
                el('span', { class: 'page-symbol' }, icon('page')),
                el(
                    'span',
                    { class: 'page-cell-text' },
                    el('span', { class: 'page-title' }, title),
                    el('span', { class: 'page-address' }, address(job.url)),
                ),
            );
            const remove = el(
                'button',
                {
                    class: 'icon-button delete',
                    type: 'button',
                    'data-job': job.id,
                    'data-action': 'delete',
                    'aria-label': 'Delete ' + title,
                    title: 'Delete capture',
                    onclick: () => askDelete(job),
                },
                icon('trash'),
            );
            return el(
                'tr',
                {},
                el('td', {}, open),
                el('td', {}, badge(job.status)),
                el(
                    'td',
                    { class: 'date-cell', title: date(job.created_at, true) },
                    date(job.created_at),
                ),
                el('td', {}, remove),
            );
        });
        $('captureRows').replaceChildren(...rows);
        if (focusJob)
            $('captureRows')
                .querySelector(`[data-job="${focusJob}"][data-action="${focusAction}"]`)
                ?.focus({ preventScroll: true });
    }

    function updatePagination() {
        $('pagination').hidden = state.total <= state.pageSize;
        $('previousPage').disabled = state.page <= 1;
        $('nextPage').disabled = state.page * state.pageSize >= state.total;
        $('pageRange').textContent =
            `${number((state.page - 1) * state.pageSize + 1)}–${number(Math.min(state.page * state.pageSize, state.total))} of ${number(state.total)}`;
    }

    async function openDetail(id) {
        if (root.classList.contains('hidden')) return;
        state.selected = id;
        state.job = null;
        state.data = null;
        state.tab = 'overview';
        $('detailTitle').textContent = 'Loading page…';
        $('detailUrl').textContent = '';
        $('detailNumber').textContent = 'Capture ' + id;
        $('detailStatus').hidden = true;
        $('detailContent').replaceChildren(
            el(
                'div',
                { class: 'progress-view' },
                el('span', { class: 'spinner' }),
                el('p', {}, 'Loading saved content…'),
            ),
        );
        $('againButton').disabled = true;
        enableExport(false);
        $('exportMenu').open = false;
        $('detailTabs').hidden = true;
        if (!$('detailDialog').open) $('detailDialog').showModal();
        positionToast();
        const url = new URL(location.href);
        url.searchParams.set('capture', id);
        history.replaceState(null, '', url);
        await loadDetail(id);
    }

    async function loadDetail(id) {
        detailController?.abort();
        const controller = new AbortController();
        detailController = controller;
        try {
            const result = await request('/api/xcrape/jobs/' + id, { signal: controller.signal });
            if (state.selected !== id || controller !== detailController) return;
            const wasActive = state.job && ['pending', 'running'].includes(state.job.status);
            state.job = result.job;
            try {
                state.data = state.job.data ? JSON.parse(state.job.data) : null;
            } catch {
                state.data = {
                    error: 'The saved content could not be read. Try capturing this page again.',
                };
            }
            $('detailTitle').textContent =
                state.data?.meta?.title || state.job.title || address(state.job.url);
            const url = safeUrl(state.data?.meta?.final_url || state.job.url);
            $('detailUrl').textContent = state.data?.meta?.final_url || state.job.url;
            if (url) $('detailUrl').href = url;
            else $('detailUrl').removeAttribute('href');
            $('detailNumber').textContent =
                'Capture ' + state.job.id + ' · ' + date(state.job.created_at, true);
            const active = ['pending', 'running'].includes(state.job.status);
            $('againButton').disabled = active;
            enableExport(Boolean(state.data));
            const error = state.data?.error;
            if (wasActive && !active)
                toast(
                    state.job.status === 'completed' ? 'Page saved' : 'This capture needs attention',
                    state.job.status === 'failed',
                );
            $('detailStatus').hidden = !error;
            $('detailStatus').textContent = error || '';
            $('detailTabs').hidden = !state.data?.meta;
            if (active) {
                $('detailContent').replaceChildren(
                    el(
                        'div',
                        { class: 'progress-view' },
                        el('span', { class: 'spinner' }),
                        el(
                            'h3',
                            {},
                            state.job.status === 'pending'
                                ? 'Your page is in line'
                                : 'Capturing your page',
                        ),
                        el(
                            'p',
                            {},
                            state.job.status === 'pending'
                                ? 'It will start when a capture finishes.'
                                : 'This can take a few moments. You can close this window and come back.',
                        ),
                    ),
                );
            } else if (!state.data?.meta && error) {
                $('detailContent').replaceChildren(
                    el(
                        'div',
                        { class: 'empty-state' },
                        el('span', { class: 'empty-icon' }, icon('info')),
                        el('h3', {}, 'This page couldn’t be saved'),
                        el('p', {}, 'Check the address and try Capture again.'),
                    ),
                );
            } else if (!state.data) {
                $('detailContent').replaceChildren(
                    el(
                        'p',
                        { class: 'empty-content' },
                        'No content was saved for this page. Try Capture again.',
                    ),
                );
            } else renderTab();
        } catch (error) {
            if (error.name === 'AbortError' || state.selected !== id) return;
            $('detailContent').replaceChildren(
                el(
                    'div',
                    { class: 'empty-state' },
                    el('h3', {}, 'This capture couldn’t be loaded'),
                    el('p', {}, error.message),
                    el(
                        'button',
                        { class: 'button secondary', onclick: () => loadDetail(id) },
                        'Try again',
                    ),
                ),
            );
        }
    }

    function closeDetail() {
        $('detailDialog').close();
    }
    $('detailDialog').addEventListener('close', () => {
        detailController?.abort();
        state.selected = null;
        state.job = null;
        state.data = null;
        const url = new URL(location.href);
        url.searchParams.delete('capture');
        history.replaceState(null, '', url);
        positionToast();
    });
    $('closeDetail').addEventListener('click', closeDetail);
    $('detailDialog').addEventListener('click', (event) => {
        if (event.target !== $('detailDialog')) return;
        const rect = $('detailDialog').getBoundingClientRect();
        if (
            event.clientX < rect.left ||
            event.clientX > rect.right ||
            event.clientY < rect.top ||
            event.clientY > rect.bottom
        )
            closeDetail();
    });

    function copyButton(text) {
        return el(
            'button',
            { class: 'button subtle small', type: 'button', onclick: () => copy(text) },
            icon('copy'),
            'Copy',
        );
    }

    async function copy(text) {
        try {
            if (navigator.clipboard) await navigator.clipboard.writeText(text);
            else {
                const previous = document.activeElement;
                const input = el('textarea', { class: 'sr-only', value: text });
                ($('detailDialog').open ? $('detailDialog') : root).append(input);
                input.select();
                const ok = document.execCommand('copy');
                input.remove();
                previous?.focus();
                if (!ok) throw new Error('Copy unavailable');
            }
            toast('Copied to clipboard');
        } catch {
            toast('Couldn’t copy. You can download the data instead.', true);
        }
    }

    function section(title, ...children) {
        return el(
            'section',
            { class: 'content-section' },
            el('div', { class: 'section-top' }, el('h3', {}, title)),
            ...children,
        );
    }

    function sectionWithCopy(title, content, text) {
        const node = section(title, content);
        node.firstChild.append(copyButton(text));
        return node;
    }

    function empty(message) {
        return el('div', { class: 'empty-content' }, message);
    }
    function externalLink(url, text) {
        const safe = safeUrl(url);
        return safe
            ? el('a', { href: safe, target: '_blank', rel: 'noopener noreferrer' }, text || url)
            : el('span', {}, text || url || ' - ');
    }

    function facts(items) {
        return el(
            'dl',
            { class: 'fact-list' },
            items
                .filter(([, value]) => value !== null && value !== undefined && value !== '')
                .map(([label, value]) =>
                    el('div', {}, el('dt', {}, label), el('dd', {}, String(value))),
                ),
        );
    }

    function overview(data) {
        const screenshot = data.screenshot
            ? el(
                  'div',
                  { class: 'screenshot-wrap' },
                  el('img', {
                      src: 'data:image/jpeg;base64,' + data.screenshot,
                      alt: 'Screenshot of ' + (data.meta?.title || 'the saved page'),
                  }),
                  el(
                      'div',
                      { class: 'screenshot-caption' },
                      el('span', {}, 'Page preview'),
                      el('span', {}, 'Saved with this capture'),
                  ),
              )
            : empty('No screenshot was saved.');
        const summary = el(
            'div',
            { class: 'summary-card' },
            el('h3', {}, data.meta?.title || 'Untitled page'),
            el('p', {}, data.meta?.description || 'This page has no description.'),
            el(
                'div',
                { class: 'summary-stats' },
                [
                    ['Words', data.stats?.word_count],
                    ['Links', data.links?.length],
                    ['Images', data.images?.length],
                ].map(([label, value]) =>
                    el(
                        'div',
                        { class: 'summary-stat' },
                        el('strong', {}, number(value)),
                        el('span', {}, label),
                    ),
                ),
            ),
            facts([
                ['Captured', date(state.job.created_at, true)],
                [
                    'Time taken',
                    data.stats?.load_time_seconds != null
                        ? data.stats.load_time_seconds + ' seconds'
                        : null,
                ],
                ['Response', data.meta?.http_status ? 'HTTP ' + data.meta.http_status : null],
                ['Selection', state.job.selector],
            ]),
        );
        const grid = el('div', { class: 'overview-grid' }, screenshot, summary);
        const nodes = [grid];
        if (data.warnings?.length)
            nodes.push(
                section(
                    'Capture notes',
                    el(
                        'ul',
                        {},
                        data.warnings.map((note) => el('li', {}, note)),
                    ),
                ),
            );
        if (data.technologies?.length)
            nodes.push(
                section(
                    'Detected software',
                    el(
                        'div',
                        { class: 'pill-row' },
                        data.technologies.map((tech) =>
                            el('span', { class: 'pill soft', title: tech.source }, tech.name),
                        ),
                    ),
                ),
            );
        if (data.social_links?.length)
            nodes.push(
                section(
                    'Social profiles',
                    el(
                        'ul',
                        { class: 'link-list' },
                        data.social_links.map((item) =>
                            el(
                                'li',
                                {},
                                el('span', { class: 'pill' }, item.platform),
                                el(
                                    'div',
                                    {},
                                    externalLink(item.url, item.text || item.platform),
                                    el('small', {}, item.url),
                                ),
                            ),
                        ),
                    ),
                ),
            );
        return el(
            'div',
            {},
            ...nodes.map((node, i) =>
                i === 0 ? el('section', { class: 'content-section' }, node) : node,
            ),
        );
    }

    function textContent(data) {
        const root = el('div', { class: 'prose' });
        if (data.selector_results !== null && data.selector_results !== undefined) {
            const matches = data.selector_results;
            root.append(
                sectionWithCopy(
                    'Selected content · ' + number(matches.length) + ' matches',
                    matches.length
                        ? el(
                              'div',
                              {},
                              matches.map((item) => el('p', {}, item.text)),
                          )
                        : empty('Nothing matched this selector.'),
                    matches.map((item) => item.text).join('\n\n'),
                ),
            );
        }
        if (data.headings?.length)
            root.append(
                section(
                    'Headings',
                    el(
                        'ul',
                        { class: 'heading-list' },
                        data.headings.map((heading) =>
                            el(
                                'li',
                                {},
                                el('span', { class: 'heading-level' }, 'H' + heading.level),
                                el('span', {}, heading.text),
                            ),
                        ),
                    ),
                ),
            );
        root.append(
            sectionWithCopy(
                'Page text',
                data.text?.length
                    ? el(
                          'div',
                          {},
                          data.text.map((paragraph) => el('p', {}, paragraph)),
                      )
                    : empty('No paragraphs were found on this page.'),
                (data.text || []).join('\n\n'),
            ),
        );
        if (data.lists?.length)
            root.append(
                section(
                    'Lists',
                    ...data.lists.map((list) =>
                        el(
                            list.type === 'ol' ? 'ol' : 'ul',
                            {},
                            list.items.map((item) => el('li', {}, item)),
                        ),
                    ),
                ),
            );
        return root;
    }

    function linksContent(data) {
        const links = data.links || [];
        if (!links.length) return empty('No links were found on this page.');
        const filter = el('input', {
            type: 'search',
            class: 'filter-input',
            placeholder: 'Filter links…',
            'aria-label': 'Filter page links',
        });
        const list = el('ul', { class: 'link-list' });
        const count = el('h3');
        const more = el(
            'button',
            { class: 'button secondary small load-more', type: 'button' },
            'Show more links',
        );
        let shown = 100;
        function render() {
            const query = filter.value.trim().toLowerCase();
            const matches = links.filter((item) =>
                (item.url + ' ' + item.text).toLowerCase().includes(query),
            );
            count.textContent = number(matches.length) + (matches.length === 1 ? ' link' : ' links');
            list.replaceChildren(
                ...matches
                    .slice(0, shown)
                    .map((item) =>
                        el(
                            'li',
                            {},
                            el(
                                'span',
                                { class: 'pill' + (item.internal ? ' soft' : '') },
                                item.internal ? 'Same site' : 'Other site',
                            ),
                            el('div', {}, externalLink(item.url, item.text), el('small', {}, item.url)),
                        ),
                    ),
            );
            if (!matches.length) list.append(empty('No links match this search.'));
            more.hidden = matches.length <= shown;
        }
        filter.addEventListener('input', () => {
            shown = 100;
            render();
        });
        more.addEventListener('click', () => {
            shown += 100;
            render();
        });
        render();
        return el(
            'section',
            { class: 'content-section' },
            el('div', { class: 'section-top' }, count, copyButton(pretty(links))),
            filter,
            list,
            more,
        );
    }

    function imagesContent(data) {
        const images = data.images || [];
        if (!images.length) return empty('No images were found on this page.');
        const id = state.selected;
        const grid = el('div', { class: 'image-grid' });
        const more = el(
            'button',
            { class: 'button secondary small load-more', type: 'button' },
            'Show more images',
        );
        let shown = 0;
        function addImages() {
            images.slice(shown, shown + 40).forEach((image, offset) => {
                const index = shown + offset;
                const src = safeUrl(image.src, true);
                const thumb = el('div', { class: 'image-thumb' });
                if (src) {
                    const img = el('img', {
                        src: `/api/xcrape/jobs/${id}/images/${index}/preview`,
                        alt: image.alt || 'Image ' + (index + 1),
                        loading: 'lazy',
                        referrerPolicy: 'no-referrer',
                    });
                    img.addEventListener(
                        'error',
                        () => thumb.replaceChildren(el('span', {}, 'Preview unavailable. Open the original image to view it.')),
                        { once: true },
                    );
                    thumb.append(img);
                } else thumb.append(el('span', {}, 'Preview unavailable'));
                const button = el(
                    'button',
                    {
                        class: 'button secondary small',
                        type: 'button',
                        'aria-label': 'Download image ' + (index + 1),
                        onclick: () => download(`/api/xcrape/jobs/${id}/images/${index}`, button),
                    },
                    icon('download'),
                    'Save',
                );
                const dims = [image.width, image.height].filter(Boolean).join(' × ');
                grid.append(
                    el(
                        'article',
                        { class: 'image-card' },
                        thumb,
                        el(
                            'div',
                            { class: 'image-info' },
                            el(
                                'p',
                                { title: image.alt || 'Image ' + (index + 1) },
                                image.alt || 'Image ' + (index + 1),
                            ),
                            el(
                                'small',
                                { title: image.src },
                                image.src?.startsWith('data:') ? 'Embedded image' : address(image.src),
                            ),
                            el('div', { class: 'image-actions' }, el('span', {}, dims), button),
                            externalLink(image.src, 'Open original image'),
                        ),
                    ),
                );
            });
            shown += 40;
            more.hidden = shown >= images.length;
        }
        const downloadAll = el(
            'button',
            {
                class: 'button secondary small',
                type: 'button',
                onclick: () => download(`/api/xcrape/jobs/${id}/images/download-all`, downloadAll),
            },
            icon('download'),
            'Download all',
        );
        more.addEventListener('click', addImages);
        addImages();
        return el(
            'section',
            { class: 'content-section' },
            el(
                'div',
                { class: 'section-top' },
                el('h3', {}, number(images.length) + ' images'),
                downloadAll,
            ),
            grid,
            more,
        );
    }

    function detailsContent(data) {
        const root = el('div');
        const names = {
            title: 'Title',
            description: 'Description',
            keywords: 'Keywords',
            og_title: 'Social preview title',
            og_description: 'Social preview text',
            og_image: 'Social preview image',
            favicon: 'Page icon',
            canonical: 'Preferred address',
            final_url: 'Page address',
            http_status: 'HTTP response',
        };
        const rows = Object.entries(data.meta || {})
            .filter(([, value]) => value !== null && value !== '')
            .map(([key, value]) =>
                el(
                    'tr',
                    {},
                    el('th', { scope: 'row' }, names[key] || key),
                    el('td', {}, String(value)),
                ),
            );
        root.append(
            section(
                'Page information',
                el('table', { class: 'data-table metadata-table' }, el('tbody', {}, rows)),
            ),
        );
        const statsNames = {
            word_count: 'Words',
            link_count: 'Links',
            internal_links: 'Links to the same site',
            external_links: 'Links to other sites',
            image_count: 'Images',
            heading_count: 'Headings',
            table_count: 'Tables',
            list_count: 'Lists',
            script_count: 'External scripts',
            inline_script_count: 'Inline scripts',
            style_count: 'Stylesheets',
            html_size_bytes: 'HTML size in bytes',
            tech_count: 'Detected software',
            social_count: 'Social profiles',
            structured_data_count: 'Embedded data blocks',
            load_time_seconds: 'Capture time in seconds',
        };
        root.append(
            section(
                'Page counts',
                el(
                    'table',
                    { class: 'data-table metadata-table' },
                    el(
                        'tbody',
                        {},
                        Object.entries(data.stats || {}).map(([key, value]) =>
                            el(
                                'tr',
                                {},
                                el('th', { scope: 'row' }, statsNames[key] || key),
                                el('td', {}, String(value)),
                            ),
                        ),
                    ),
                ),
            ),
        );
        if (data.tables?.length)
            root.append(
                section(
                    'Tables',
                    ...data.tables.map((table, index) =>
                        section(
                            'Table ' + (index + 1),
                            el(
                                'div',
                                { class: 'table-wrap', tabIndex: 0, 'aria-label': 'Page table' },
                                el(
                                    'table',
                                    { class: 'data-table' },
                                    el(
                                        'tbody',
                                        {},
                                        table.map((row, ri) =>
                                            el(
                                                'tr',
                                                {},
                                                row.map((cell) =>
                                                    el(
                                                        ri === 0 ? 'th' : 'td',
                                                        ri === 0 ? { scope: 'col' } : {},
                                                        cell,
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            );
        if (data.structured_data?.length)
            root.append(
                section(
                    'Embedded page data',
                    ...data.structured_data.map((item) =>
                        sectionWithCopy(
                            item.format,
                            el('pre', {}, pretty(item.data)),
                            pretty(item.data),
                        ),
                    ),
                ),
            );
        return root;
    }

    function renderTab() {
        const data = state.data;
        if (!data) return;
        root.querySelectorAll('[data-tab]').forEach((tab) => {
            const active = tab.dataset.tab === state.tab;
            tab.setAttribute('aria-selected', String(active));
            tab.tabIndex = active ? 0 : -1;
        });
        $('detailContent').setAttribute('aria-labelledby', 'xc-tab-' + state.tab);
        const renderers = {
            overview,
            text: textContent,
            links: linksContent,
            images: imagesContent,
            data: detailsContent,
            raw: (value) =>
                sectionWithCopy(
                    'Saved data',
                    el('pre', {}, pretty(withoutScreenshot(value))),
                    pretty(withoutScreenshot(value)),
                ),
        };
        $('detailContent').replaceChildren(renderers[state.tab](data));
        $('detailContent').scrollTop = 0;
    }

    $('detailTabs').addEventListener('click', (event) => {
        const tab = event.target.closest('[data-tab]');
        if (tab) {
            state.tab = tab.dataset.tab;
            renderTab();
        }
    });
    $('detailTabs').addEventListener('keydown', (event) => {
        const tabs = [...$('detailTabs').querySelectorAll('[data-tab]')];
        const index = tabs.indexOf(document.activeElement);
        let next;
        if (event.key === 'ArrowRight') next = (index + 1) % tabs.length;
        if (event.key === 'ArrowLeft') next = (index - 1 + tabs.length) % tabs.length;
        if (event.key === 'Home') next = 0;
        if (event.key === 'End') next = tabs.length - 1;
        if (next !== undefined) {
            event.preventDefault();
            state.tab = tabs[next].dataset.tab;
            renderTab();
            tabs[next].focus();
            tabs[next].scrollIntoView({ block: 'nearest', inline: 'nearest' });
        }
    });

    async function download(url, button) {
        if (button) button.disabled = true;
        try {
            const response = await fetch(url);
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || error.detail || 'This download couldn’t be prepared.');
            }
            const blob = await response.blob();
            const href = URL.createObjectURL(blob);
            const filename =
                /filename="([^"]+)"/.exec(response.headers.get('content-disposition') || '')?.[1] ||
                'xcrape-download';
            const anchor = el('a', { href, download: filename });
            root.append(anchor);
            anchor.click();
            anchor.remove();
            setTimeout(() => URL.revokeObjectURL(href), 30000);
            $('exportMenu').open = false;
            toast('Download ready');
        } catch (error) {
            toast(error.message || 'Download failed. Please try again.', true);
        } finally {
            if (button) button.disabled = false;
        }
    }

    $('exportJson').addEventListener(
        'click',
        () =>
            state.selected &&
            download(`/api/xcrape/jobs/${state.selected}/export?format=json`, $('exportJson')),
    );
    $('exportCsv').addEventListener(
        'click',
        () =>
            state.selected && download(`/api/xcrape/jobs/${state.selected}/export?format=csv`, $('exportCsv')),
    );
    $('copyData').addEventListener('click', () => {
        if (state.data) copy(pretty(withoutScreenshot(state.data)));
        $('exportMenu').open = false;
    });

    $('captureForm').addEventListener('submit', async (event) => {
        event.preventDefault();
        const button = $('captureButton');
        button.disabled = true;
        button.firstElementChild.textContent = 'Adding page…';
        $('formError').hidden = true;
        try {
            const result = await request('/api/xcrape/scrape', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: $('pageUrl').value.trim(),
                    selector: $('pageSelector').value.trim() || null,
                }),
            });
            $('pageUrl').value = '';
            $('pageSelector').value = '';
            $('advancedOptions').open = false;
            state.page = 1;
            state.query = '';
            state.status = '';
            $('searchInput').value = '';
            $('statusFilter').value = '';
            await refreshJobs();
            await openDetail(result.job_id);
        } catch (error) {
            $('formError').textContent = error.message;
            $('formError').hidden = false;
        } finally {
            button.disabled = false;
            button.firstElementChild.textContent = 'Capture page';
        }
    });

    $('againButton').addEventListener('click', async () => {
        if (!state.selected) return;
        $('againButton').disabled = true;
        try {
            const result = await request(`/api/xcrape/jobs/${state.selected}/rescrape`, { method: 'POST' });
            state.page = 1;
            await refreshJobs();
            await openDetail(result.job_id);
            toast('New capture added');
        } catch (error) {
            toast(error.message, true);
        } finally {
            $('againButton').disabled = state.job && ['pending', 'running'].includes(state.job.status);
        }
    });

    function askDelete(job) {
        deleteTarget = job.id;
        $('deleteDescription').textContent = ['running', 'pending'].includes(job.status)
            ? 'This will stop the capture and remove it from this device.'
            : 'Its saved content will be removed from this device.';
        $('deleteDialog').showModal();
        positionToast();
    }
    $('deleteDialog').addEventListener('close', positionToast);
    $('confirmDelete').addEventListener('click', async () => {
        const id = deleteTarget;
        $('confirmDelete').disabled = true;
        try {
            await request('/api/xcrape/jobs/' + id, { method: 'DELETE' });
            $('deleteDialog').close();
            if (state.selected === id) closeDetail();
            await refreshJobs();
            toast('Capture deleted');
        } catch (error) {
            toast(error.message, true);
        } finally {
            $('confirmDelete').disabled = false;
        }
    });

    $('searchInput').addEventListener('input', () => {
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => {
            state.query = $('searchInput').value.trim();
            state.page = 1;
            refreshJobs();
        }, 250);
    });
    $('statusFilter').addEventListener('change', () => {
        state.status = $('statusFilter').value;
        state.page = 1;
        refreshJobs();
    });
    $('refreshButton').addEventListener('click', refreshJobs);
    $('emptyAction').addEventListener('click', () => {
        if (state.query || state.status) {
            state.query = '';
            state.status = '';
            state.page = 1;
            $('searchInput').value = '';
            $('statusFilter').value = '';
            refreshJobs();
        } else {
            $('pageUrl').focus();
            $('pageUrl').scrollIntoView({ block: 'center', behavior: 'smooth' });
        }
    });
    $('previousPage').addEventListener('click', () => {
        if (state.page > 1) {
            state.page--;
            refreshJobs();
        }
    });
    $('nextPage').addEventListener('click', () => {
        if (state.page * state.pageSize < state.total) {
            state.page++;
            refreshJobs();
        }
    });
    document.addEventListener('keydown', (event) => {
        if (root.classList.contains('hidden')) return;
        if (
            document.getElementById('sidebar')?.classList.contains('open') ||
            document.querySelector('dialog[open]') ||
            event.ctrlKey ||
            event.metaKey ||
            event.altKey ||
            event.target.closest('input, textarea, select, [contenteditable]')
        )
            return;
        if (event.key === '/') {
            event.preventDefault();
            $('searchInput').focus();
        }
        if (event.key.toLowerCase() === 'n') {
            event.preventDefault();
            $('pageUrl').focus();
        }
    });
    document.addEventListener('click', (event) => {
        if (!$('exportMenu').contains(event.target)) $('exportMenu').open = false;
    });

    async function poll() {
        clearTimeout(pollTimer);
        if (!document.hidden && !root.classList.contains('hidden')) await refreshJobs();
        pollTimer = setTimeout(poll, 3000);
    }
    document.addEventListener('visibilitychange', () => {
        if (!document.hidden) poll();
    });

    document.addEventListener('workspace-navigation', (event) => {
        if (event.detail !== 'xcrape' && !root.classList.contains('hidden')) {
            $('deleteDialog').close();
            if ($('detailDialog').open) closeDetail();
        }
    });
    document.addEventListener('workspace-view', (event) => {
        if (event.detail === 'xcrape') {
            poll();
            const capture = new URL(location.href).searchParams.get('capture');
            if (/^\d+$/.test(capture || '')) openDetail(Number(capture));
        }
    });
    poll();
    const initialCapture = new URL(location.href).searchParams.get('capture');
    if (!root.classList.contains('hidden') && /^\d+$/.test(initialCapture || '')) openDetail(Number(initialCapture));
}
