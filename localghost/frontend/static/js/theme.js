/**
 * Theme toggle — dark/light mode switch with localStorage persistence.
 */

const STORAGE_KEY = 'localghost-theme';

export function initTheme() {
    const saved = localStorage.getItem(STORAGE_KEY) || 'dark';
    setTheme(saved);

    const toggle = document.getElementById('theme-toggle');
    toggle?.addEventListener('click', () => {
        const current = document.documentElement.getAttribute('data-theme');
        setTheme(current === 'dark' ? 'light' : 'dark');
    });
}

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(STORAGE_KEY, theme);

    const icon = document.getElementById('theme-icon');
    if (icon) {
        icon.textContent = theme === 'dark' ? 'light_mode' : 'dark_mode';
    }
}
