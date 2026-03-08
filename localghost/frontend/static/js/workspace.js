/** Project workspace navigation, recent reports, and explicit local app discovery. */
import { getProjects, getScanDetail, discoverProjects, discoverDocker } from './api.js';
import { projectIdentity } from './projects.js';
import { formatTimestamp } from './utils.js';

const views = {
    home: 'empty-state',
    scan: 'scan-setup',
    reports: 'reports-view',
    report: 'results-dashboard',
    progress: 'scan-progress',
};
const labels = {
    home: 'Projects',
    scan: 'New scan',
    reports: 'Reports',
    report: 'Project report',
    progress: 'Running scan',
};
let callbacks,
    busy = false,
    currentReportId = null,
    currentView = 'home';
let reportController,
    workspaceController,
    workspaceVersion = 0;
let discovering = false;
let loadedProjects = [];

function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
}
function icon(name) {
    const node = element('span', 'material-symbols-outlined', name);
    node.setAttribute('aria-hidden', 'true');
    return node;
}
function button(label, className, onClick) {
    const node = element('button', className, label);
    node.type = 'button';
    node.addEventListener('click', onClick);
    return node;
}
function status(text) {
    document.getElementById('workspace-status').textContent = text;
}

export function initWorkspace(handlers) {
    callbacks = handlers;
    document.querySelectorAll('[data-view]').forEach((control) =>
        control.addEventListener('click', (event) => {
            event.preventDefault();
            showView(control.dataset.view);
        }),
    );
    document.querySelectorAll('[data-example]').forEach((control) =>
        control.addEventListener('click', () => {
            document.getElementById('target-url').value = control.dataset.example;
            document.getElementById('target-url').dispatchEvent(new Event('input', { bubbles: true }));
            document.getElementById('target-url').focus();
        }),
    );
    document.getElementById('discover-btn').addEventListener('click', discover);
    document.getElementById('docker-discover-btn').addEventListener('click', findDocker);
    document.getElementById('projects-more').addEventListener('click', () => refreshWorkspace(true));
    document.addEventListener('history-updated', () => refreshWorkspace());
    window.addEventListener('popstate', route);
    route();
    refreshWorkspace();
}

export function showView(view, { focus = true, push = true, scanId = currentReportId } = {}) {
    reportController?.abort();
    document.dispatchEvent(new Event('workspace-navigation'));
    if (!views[view] || (view === 'report' && !scanId)) view = 'home';
    if (view === 'progress' && document.getElementById('running-scan-nav').classList.contains('hidden')) view = 'home';
    currentView = view;
    for (const [key, id] of Object.entries(views)) document.getElementById(id).classList.toggle('hidden', view !== key);
    document.getElementById('view-label').textContent = labels[view];
    document.querySelectorAll('.nav-item').forEach((item) => {
        const selected = item.dataset.view === view;
        item.classList.toggle('active', selected);
        if (selected) item.setAttribute('aria-current', 'page');
        else item.removeAttribute('aria-current');
    });
    const hash = view === 'report' ? `report/${encodeURIComponent(scanId)}` : view === 'home' ? 'projects' : view;
    if (push && location.hash !== `#${hash}`) history.pushState(null, '', `#${hash}`);
    callbacks?.closeNavigation();
    document.getElementById('main-content').scrollTop = 0;
    if (focus) {
        const target =
            view === 'scan'
                ? document.getElementById('target-url')
                : document.getElementById(views[view]).querySelector('h1, [tabindex="-1"]');
        if (target) {
            if (!target.matches('input, button, select, a[href]')) target.tabIndex = -1;
            target.focus({ preventScroll: true });
        }
    }
}

async function route() {
    reportController?.abort();
    const [name, id] = location.hash.slice(1).split('/');
    const view = name === 'projects' || !name ? 'home' : name;
    if (view === 'report' && id) {
        let scanId;
        try {
            scanId = decodeURIComponent(id);
        } catch {
            showView('home', { push: false });
            return;
        }
        if (scanId !== currentReportId) {
            if (busy) {
                showView('progress');
                return;
            }
            await openSavedReport(scanId);
            return;
        }
    }
    showView(view, { focus: false, push: false });
}

export function setWorkspaceReport(data) {
    currentReportId = data?.scan_id || null;
    document.getElementById('current-report-nav').classList.toggle('hidden', !data);
    if (data) showView('report', { focus: false });
}

export function setWorkspaceBusy(value) {
    busy = value;
    document.querySelectorAll('[data-view="scan"], [data-project-action]').forEach((control) => {
        control.disabled = value;
    });
    document.getElementById('running-scan-nav').classList.toggle('hidden', !value);
    document.getElementById('discover-btn').disabled = value || discovering;
    document.getElementById('docker-discover-btn').disabled = value || discovering;
    if (value) reportController?.abort();
    if (!value && currentView === 'progress') document.getElementById('scan-recovery').classList.remove('hidden');
}

export async function openSavedReport(scanId) {
    if (busy) return;
    reportController?.abort();
    const controller = new AbortController();
    reportController = controller;
    document.getElementById('app-status').textContent = 'Loading project report…';
    try {
        const detail = await getScanDetail(scanId, controller.signal);
        if (!controller.signal.aborted && !busy) callbacks.openReport(detail.results);
    } catch (error) {
        if (error.name === 'AbortError') return;
        showView('home');
        status(error.message);
        document.getElementById('app-status').textContent = error.message;
    }
}

export async function refreshWorkspace(append = false) {
    const version = ++workspaceVersion;
    workspaceController?.abort();
    const controller = new AbortController();
    workspaceController = controller;
    const more = document.getElementById('projects-more');
    more.disabled = true;
    try {
        const data = await getProjects(24, append ? loadedProjects.length : 0, controller.signal);
        if (version !== workspaceVersion) return;
        const projects = append ? [...loadedProjects, ...data.projects] : data.projects;
        loadedProjects = [...new Map(projects.map((project) => [project.key, project])).values()];
        document.getElementById('workspace-project-count').textContent = data.total_projects;
        document.getElementById('projects-count-label').textContent = data.total_projects;
        document.getElementById('workspace-report-count').textContent = data.total_reports;
        document.getElementById('nav-report-count').textContent = data.total_reports;
        const latest = data.latest_timestamp;
        document.getElementById('workspace-last-scan').textContent = latest
            ? new Date(latest).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
            : 'No scans yet';
        document.getElementById('workspace-last-scan').title = latest ? formatTimestamp(latest) : '';
        more.classList.toggle('hidden', loadedProjects.length >= data.total_projects);
        document.getElementById('getting-started').classList.toggle('hidden', Boolean(loadedProjects.length));
        const grid = document.getElementById('project-grid');
        grid.replaceChildren();
        loadedProjects.forEach((project) => grid.appendChild(projectCard(project)));
        const recents = document.getElementById('recent-projects');
        recents.replaceChildren();
        if (!projects.length) recents.appendChild(element('p', 'sidebar-note', 'Scanned projects appear here.'));
        for (const project of loadedProjects.slice(0, 5)) {
            const control = button('', 'recent-project-link', () => openSavedReport(project.latest.scan_id));
            control.append(
                element('span', 'project-initial', project.name.slice(0, 2).toUpperCase()),
                element('span', '', project.name),
            );
            control.dataset.projectAction = '';
            control.disabled = busy;
            recents.appendChild(control);
        }
        status('');
    } catch (error) {
        if (version === workspaceVersion && error.name !== 'AbortError')
            status(`Could not load projects. ${error.message}`);
    } finally {
        if (version === workspaceVersion) more.disabled = false;
    }
}

function projectCard(project) {
    const card = element('article', 'project-card');
    const top = element('div', 'project-card__top');
    const avatar = element('span', 'project-avatar');
    avatar.appendChild(icon('deployed_code'));
    top.append(
        avatar,
        element(
            'small',
            '',
            ['partial', 'error'].includes(project.latest.status) ? 'INCOMPLETE SCAN' : 'LAST SAVED SCAN',
        ),
    );
    const scoreRow = element('div', 'project-card__score');
    const score = element('strong', 'project-score', project.latest.confirmed ?? '—');
    const label = element('span');
    label.append(
        element('b', '', project.latest.confirmed == null ? 'Older report' : 'Confirmed problems'),
        element('small', '', project.latest.review == null ? `${project.reports} saved reports` : `${project.latest.review} need review · ${project.reports} saved report${project.reports === 1 ? '' : 's'}`),
    );
    scoreRow.append(score, label);
    const footer = element('div', 'project-card__footer');
    const open = button('View report', 'text-link', () => openSavedReport(project.latest.scan_id));
    open.appendChild(icon('arrow_forward'));
    const scan = button('New scan', 'md-btn md-btn--outlined', () => chooseProject(project.latest.target, project.latest.scan_id));
    [open, scan].forEach((control) => {
        control.dataset.projectAction = '';
        control.disabled = busy;
    });
    footer.append(open, scan);
    card.append(
        top,
        element('h3', '', project.name),
        element('p', 'project-card__url', project.origin),
        scoreRow,
        footer,
    );
    card.title = `Last scanned ${formatTimestamp(project.latest.timestamp)}`;
    return card;
}

async function chooseProject(target, scanId) {
    if (busy) return;
    try {
        if (scanId) await callbacks.configureProject(scanId);
        else callbacks.chooseTarget(target);
        showView('scan');
    } catch (error) { status(error.message); }
}

async function discover() {
    if (busy || discovering) return;
    discovering = true;
    const control = document.getElementById('discover-btn');
    const message = document.getElementById('discovery-status');
    control.disabled = true;
    document.getElementById('docker-discover-btn').disabled = true;
    control.querySelector('span:last-child').textContent = 'Checking ports…';
    document.getElementById('discovered-projects').replaceChildren();
    message.textContent = 'Checking common development ports on localhost…';
    try {
        const data = await discoverProjects();
        message.textContent = data.projects.length
            ? `${data.projects.length} local address${data.projects.length === 1 ? '' : 'es'} responded across ${data.checked_ports} common ports. Select one to scan.`
            : `No HTTP apps responded on ${data.checked_ports} common ports. Start your app or enter its URL in a new scan.`;
        for (const project of data.projects) {
            const row = element('article', 'discovered-app');
            const body = element('div', 'discovered-app__body');
            body.append(
                element('strong', '', project.name || projectIdentity(project.target).name),
                element('small', '', `${project.target}${project.server ? ` · ${project.server}` : ''}`),
            );
            const scan = button('Scan project', 'md-btn md-btn--outlined', () => chooseProject(project.target));
            scan.dataset.projectAction = '';
            scan.disabled = busy;
            row.append(icon('sensors'), body, element('span', 'discovery-http', `HTTP ${project.http_status}`), scan);
            document.getElementById('discovered-projects').appendChild(row);
        }
    } catch (error) {
        message.textContent = `Discovery could not complete. ${error.message} You can enter a URL manually.`;
    } finally {
        discovering = false;
        control.disabled = busy;
        document.getElementById('docker-discover-btn').disabled = busy;
        control.querySelector('span:last-child').textContent = 'Find apps again';
    }
}

async function findDocker() {
    if (busy || discovering) return;
    discovering = true;
    const control = document.getElementById('docker-discover-btn');
    const message = document.getElementById('docker-status');
    const list = document.getElementById('docker-projects');
    control.disabled = true; document.getElementById('discover-btn').disabled = true;
    list.replaceChildren(); message.textContent = 'Reading local Docker containers and published ports…';
    try {
        const data = await discoverDocker();
        message.textContent = data.containers.length ? `${data.containers.length} running containers${data.truncated ? ' (first 50 shown)' : ''}. Select a published web port to configure a scan.` : 'No running containers found.';
        for (const container of data.containers) {
            const row = element('article', 'discovered-app');
            const body = element('div', 'discovered-app__body');
            body.append(element('strong', '', container.name), element('small', '', `${container.image}${container.compose_service ? ' · Compose: ' + container.compose_service : ''}`));
            if (container.source_path) body.append(element('small', '', `Source: ${container.source_path}`));
            if (container.note) body.append(element('small', '', container.note));
            row.append(icon('deployed_code'), body);
            for (const target of container.targets) {
                const choose = button(target.url, 'md-btn md-btn--outlined', () => {
                    if (busy) return;
                    callbacks.chooseTarget(target.url, container.source_path);
                    showView('scan');
                });
                choose.dataset.projectAction = ''; row.append(choose);
            }
            list.append(row);
        }
    } catch (error) { message.textContent = error.message; }
    finally { discovering = false; control.disabled = busy; document.getElementById('discover-btn').disabled = busy; }
}
