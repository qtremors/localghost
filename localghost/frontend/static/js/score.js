/**
 * Score gauge rendering — SVG arc animation.
 */

import { getScoreColor } from './utils.js';

export function renderScoreGauge(score, grade) {
    const arc = document.getElementById('score-arc');
    const valueEl = document.getElementById('score-value');
    const gradeEl = document.getElementById('score-grade');

    if (!arc || !valueEl || !gradeEl) return;

    const circumference = 2 * Math.PI * 85; // r=85
    const offset = circumference - (score / 100) * circumference;
    const color = getScoreColor(score);

    // Animate the arc
    arc.style.strokeDasharray = circumference;
    arc.style.strokeDashoffset = circumference; // Start from zero
    arc.style.stroke = color;

    // Trigger reflow then animate
    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            arc.style.strokeDashoffset = offset;
        });
    });

    // Animate the number
    animateCounter(valueEl, 0, score, 1200);
    gradeEl.textContent = grade;
    gradeEl.style.color = color;
}

function animateCounter(el, from, to, duration) {
    const startTime = performance.now();
    function update(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        el.textContent = Math.round(from + (to - from) * eased);
        if (progress < 1) requestAnimationFrame(update);
    }
    requestAnimationFrame(update);
}

export function renderBreakdown(breakdown) {
    const container = document.getElementById('breakdown-bars');
    if (!container) return;

    const maxScores = {
        headers: 30,
        sensitive_files: 25,
        ssl: 20,
        cookies: 10,
        cors: 10,
        ports: 5,
    };

    const labels = {
        headers: 'Security Headers',
        sensitive_files: 'Sensitive Files',
        ssl: 'SSL / TLS',
        cookies: 'Cookies',
        cors: 'CORS',
        ports: 'Open Ports',
    };

    container.innerHTML = '';
    for (const [key, max] of Object.entries(maxScores)) {
        const val = breakdown[key] || 0;
        const pct = Math.round((val / max) * 100);
        const color = getScoreColor(pct);

        const item = document.createElement('div');
        item.className = 'breakdown-item';
        item.innerHTML = `
            <span class="breakdown-item__label">${labels[key] || key}</span>
            <div class="breakdown-item__bar">
                <div class="breakdown-item__fill" style="width: 0%; background: ${color};"></div>
            </div>
            <span class="breakdown-item__score">${val}/${max}</span>
        `;
        container.appendChild(item);

        // Animate bar width
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                item.querySelector('.breakdown-item__fill').style.width = `${pct}%`;
            });
        });
    }
}
