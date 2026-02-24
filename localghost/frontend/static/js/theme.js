/** Theme preferences remain usable when browser storage is unavailable. */
const STORAGE_KEY = 'localghost-theme';
export function initTheme() {
    let saved;
    try { saved = localStorage.getItem(STORAGE_KEY); } catch { /* Storage can be disabled. */ }
    setTheme(saved === 'dark' ? 'dark' : 'light');
    document.getElementById('theme-toggle').addEventListener('click', () => {
        setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    });
}
function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    try { localStorage.setItem(STORAGE_KEY, theme); } catch { /* Theme still applies. */ }
    document.getElementById('theme-icon').textContent = theme === 'dark' ? 'light_mode' : 'dark_mode';
    document.getElementById('theme-toggle').setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
}
