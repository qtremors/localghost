try {
    document.documentElement.dataset.theme = localStorage.getItem('localghost-theme') === 'light' ? 'light' : 'dark';
} catch { /* Use the default OLED theme when storage is unavailable. */ }
