document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('scan-form');
    const scanBtn = document.getElementById('scan-btn');
    const btnText = scanBtn.querySelector('span');
    const loader = document.getElementById('scan-loader');
    const resultsContainer = document.getElementById('results-container');
    
    // Tab switching
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            tabBtns.forEach(b => b.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            document.getElementById(btn.dataset.target).classList.add('active');
        });
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const targetUrl = document.getElementById('target-url').value;
        const runVuln = document.getElementById('run-vuln').checked;
        const runBench = document.getElementById('run-bench').checked;

        // UI update for loading state
        scanBtn.disabled = true;
        btnText.textContent = 'POSSESSING...';
        loader.classList.remove('hidden');
        resultsContainer.classList.add('hidden');

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_url: targetUrl,
                    run_vuln_check: runVuln,
                    run_benchmark: runBench
                })
            });

            if (!response.ok) {
                throw new Error(`Server status: ${response.status}`);
            }

            const data = await response.json();
            renderResults(data);

        } catch (error) {
            alert(`Error initiating possession: ${error.message}`);
        } finally {
            scanBtn.disabled = false;
            btnText.textContent = 'INITIATE_POSSESSION';
            loader.classList.add('hidden');
        }
    });

    function renderResults(data) {
        // Ports
        const portsBox = document.getElementById('ports-res');
        if (data.open_ports && data.open_ports.length > 0) {
            portsBox.innerHTML = `> Open Ports Discovered on ${data.target}:\n\n` + 
                                 data.open_ports.map(p => `[+] Port ${p} - OPEN`).join('\n');
        } else {
            portsBox.innerHTML = `> No open ports found on ${data.target}.`;
        }

        // Vulnerabilities
        const vulnsBox = document.getElementById('vulns-res');
        let vulnHtml = `> Security Analysis for ${data.target}\n\n`;
        
        if (data.vulnerabilities) {
            vulnHtml += `--- SECURITY HEADERS ---\n`;
            for (const [header, isPresent] of Object.entries(data.vulnerabilities.security_headers || {})) {
                if (header === 'Server') {
                    vulnHtml += `[i] Server Fingerprint: ${isPresent}\n`;
                } else {
                    const statusText = isPresent ? '[OK]' : '[WARNING] Missing';
                    // We only want the missing ones to pop out.
                    vulnHtml += `${statusText} - ${header}\n`;
                }
            }
            
            vulnHtml += `\n--- SENSITIVE PATHS ---\n`;
            for (const [path, found] of Object.entries(data.vulnerabilities.sensitive_files || {})) {
                if (found) {
                    vulnHtml += `[DANGER] Exposed path found: ${path}\n`;
                } else {
                    vulnHtml += `[OK] ${path} not exposed.\n`;
                }
            }
        }
        vulnsBox.innerHTML = vulnHtml;

        // Benchmark
        const benchBox = document.getElementById('bench-res');
        benchBox.innerHTML = ''; // clear old
        
        if (data.benchmark && Object.keys(data.benchmark).length > 0) {
            const b = data.benchmark;
            
            const stats = [
                { label: 'Req/Sec', value: b.req_per_sec },
                { label: 'Success', value: b.requests_successful },
                { label: 'Duration (s)', value: b.duration },
                { label: 'Attempted', value: b.requests_attempted }
            ];

            stats.forEach(s => {
                const div = document.createElement('div');
                div.className = 'stat-box';
                div.innerHTML = `
                    <div class="stat-value">${s.value}</div>
                    <div class="stat-label">${s.label}</div>
                `;
                benchBox.appendChild(div);
            });
        } else {
            benchBox.innerHTML = `<div class="stat-box" style="grid-column: 1 / -1;"><div class="stat-label">Load test was not run.</div></div>`;
        }

        // Show results container
        resultsContainer.classList.remove('hidden');
    }
});
