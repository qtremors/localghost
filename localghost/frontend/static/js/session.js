/** Session configuration is kept in form memory only. */
const $ = id => document.getElementById(id);
export function clearSession() {
    $('use-browser-login').checked = false;
    for (const id of ['session-cookie', 'session-authorization', 'login-username', 'login-password', 'session-browser-state']) $(id).value = '';
}
export function buildSession() {
    const session = {
        cookie: $('session-cookie').value, authorization: $('session-authorization').value,
        check_path: $('session-check-path').value.trim() || null,
        check_selector: $('session-check-selector').value.trim() || null,
        refresh_path: $('session-refresh-path').value.trim() || null,
        storage_state: $('session-browser-state').value.trim() || null,
        authorization_storage_key: $('session-token-key').value.trim() || null,
    };
    if ($('use-browser-login').checked) {
        if (!$('login-success-selector').value.trim()) throw new Error('Enter a signed-in element selector to verify the login.');
        session.login = {
            path: $('login-path').value.trim(), username: $('login-username').value, password: $('login-password').value,
            username_selector: $('login-username-selector').value.trim(), password_selector: $('login-password-selector').value.trim(),
            submit_selector: $('login-submit-selector').value.trim(), success_selector: $('login-success-selector').value.trim(),
            allowed_post_paths: $('login-post-paths').value.split(',').map(path => path.trim()).filter(Boolean),
        };
    }
    return Object.values(session).some(Boolean) ? session : null;
}

export function restoreSessionProfile(profile = {}) {
    for (const [field, key] of Object.entries({'session-check-path': 'check_path', 'session-check-selector': 'check_selector', 'session-refresh-path': 'refresh_path', 'session-token-key': 'authorization_storage_key'})) $(field).value = profile?.[key] || '';
    const defaults = {path: '/login', username_selector: 'input[name="username"]', password_selector: 'input[type="password"]', submit_selector: 'button[type="submit"]', success_selector: ''};
    for (const [field, key] of Object.entries({'login-path': 'path', 'login-username-selector': 'username_selector', 'login-password-selector': 'password_selector', 'login-submit-selector': 'submit_selector', 'login-success-selector': 'success_selector'})) $(field).value = profile?.login?.[key] || defaults[key];
    $('login-post-paths').value = (profile?.login?.allowed_post_paths || []).join(', ');
}
