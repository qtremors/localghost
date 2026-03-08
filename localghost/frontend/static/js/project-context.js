/** Optional source metadata and explicit route selection. */
import { inspectSource } from './api.js';

const $ = id => document.getElementById(id);

export function initProjectContext() {
    $('source-path').addEventListener('input', () => {
        $('mod-source').checked = Boolean($('source-path').value.trim());
        $('source-status').textContent = '';
        $('source-route-choices').replaceChildren();
        $('mod-source').dispatchEvent(new Event('change', { bubbles: true }));
    });
    $('inspect-source-btn').addEventListener('click', async () => {
        const path = $('source-path').value.trim();
        if (!path) { $('source-status').textContent = 'Enter a source-folder path first.'; return; }
        const button = $('inspect-source-btn');
        button.disabled = true;
        $('source-status').textContent = 'Reading project details…';
        try {
            const data = await inspectSource(path);
            if ($('source-path').value.trim() !== path) return;
            $('source-status').textContent = `${data.name} · ${data.framework} · ${data.files_considered} files considered${data.docker ? ' · Docker files found' : ''}. ${data.warnings.join(' ')}`;
            const choices = $('source-route-choices'); choices.replaceChildren();
            if (data.routes.length) {
                const heading = document.createElement('p'); heading.className = 'config-note';
                heading.textContent = 'Select routes to check:'; choices.append(heading);
            }
            const selected = new Set($('scan-paths').value.split('\n').map(value => value.trim()).filter(Boolean));
            for (const route of data.routes.slice(0, 30)) {
                const label = document.createElement('label'); label.className = 'route-choice';
                const input = document.createElement('input'); input.type = 'checkbox'; input.checked = selected.has(route.path);
                const name = document.createElement('span'); name.textContent = route.path;
                label.title = route.file;
                input.addEventListener('change', () => {
                    const paths = new Set($('scan-paths').value.split('\n').map(value => value.trim()).filter(Boolean));
                    if (input.checked && paths.size >= 20 && !paths.has(route.path)) {
                        input.checked = false; $('source-status').textContent = 'Choose at most 20 additional paths.'; return;
                    }
                    if (input.checked) paths.add(route.path); else paths.delete(route.path);
                    $('scan-paths').value = [...paths].join('\n');
                });
                label.append(input, name); choices.append(label);
            }
            for (const route of data.dynamic_routes) {
                const row = document.createElement('label'); row.className = 'dynamic-route-field';
                const name = document.createElement('span'); name.textContent = `Example for ${route.route}`;
                const input = document.createElement('input'); input.type = 'text'; input.placeholder = '/items/123'; input.autocomplete = 'off';
                const add = document.createElement('button'); add.type = 'button'; add.className = 'preset-btn'; add.textContent = 'Add path';
                add.addEventListener('click', () => {
                    const path = input.value.trim();
                    if (!path.startsWith('/') || path.startsWith('//')) { $('source-status').textContent = 'Enter a path on this app, such as /items/123.'; return; }
                    const paths = new Set($('scan-paths').value.split('\n').map(value => value.trim()).filter(Boolean));
                    if (paths.size >= 20 && !paths.has(path)) { $('source-status').textContent = 'Choose at most 20 paths.'; return; }
                    paths.add(path); $('scan-paths').value = [...paths].join('\n'); add.textContent = 'Added';
                });
                row.append(name, input, add); choices.append(row);
            }
            if (data.unresolved_routes?.length) {
                const note = document.createElement('p'); note.className = 'config-note';
                note.textContent = `${data.unresolved_routes.length} computed routes could not be read. Enter any missing routes below.`; choices.append(note);
            }
        } catch (error) { $('source-status').textContent = error.message; }
        finally { button.disabled = $('scan-btn').disabled; }
    });
}
