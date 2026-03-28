"""Capture real app screens from two local fixture scans, plus a PDF report.

uv run --with playwright python tests/capture_screenshots.py --output /workspace/artifacts/localghost
The fixture and application use temporary history and loopback ports only.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

from browser_smoke import PROJECT, unused_port
from playwright.sync_api import expect, sync_playwright


class DemoTarget(BaseHTTPRequestHandler):
    server_version = 'LocalDemo/1.0'
    sys_version = ''

    def do_GET(self):
        hardened = self.server.hardened
        body = b'LOCALGHOST_EXAMPLE=true' if self.path == '/.env' and not hardened else b'<html><title>Local demo application</title><body>Local demo application</body></html>'
        self.send_response(404 if self.path == '/.env' and hardened else 200)
        self.send_header('Content-Type', 'text/plain' if self.path == '/.env' else 'text/html')
        self.send_header('Content-Length', str(len(body)))
        if hardened:
            for name, value in {
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff',
                'Referrer-Policy': 'strict-origin-when-cross-origin',
            }.items():
                self.send_header(name, value)
        else:
            self.send_header('X-Powered-By', 'Express/5.0')
        self.send_header('Set-Cookie', 'session=example; SameSite=Lax' + ('; Secure; HttpOnly' if hardened else ''))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


def main(output):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='localghost-capture-') as temporary:
        try:
            target = ThreadingHTTPServer(('127.0.0.1', 3000), DemoTarget)
        except OSError:
            target = ThreadingHTTPServer(('127.0.0.1', 0), DemoTarget)
        target.hardened = False
        threading.Thread(target=target.serve_forever, daemon=True).start()
        target_url = f'http://127.0.0.1:{target.server_port}'
        port = unused_port()
        command = (
            'from backend.database import db; '
            f'db.DB_PATH = {str(Path(temporary) / "history.db")!r}; '
            'from backend.main import app; import uvicorn; '
            f'uvicorn.run(app, host="127.0.0.1", port={port}, log_level="error")'
        )
        process = subprocess.Popen([sys.executable, '-c', command], cwd=PROJECT, stdout=subprocess.DEVNULL)
        try:
            for _ in range(100):
                try:
                    with urlopen(f'http://127.0.0.1:{port}/health', timeout=.5):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('App did not start')
            with sync_playwright() as playwright:
                executable = os.getenv('LOCALGHOST_BROWSER') or ('/usr/bin/chromium' if Path('/usr/bin/chromium').exists() else None)
                browser = playwright.chromium.launch(executable_path=executable, headless=True, args=['--no-sandbox'])
                page = browser.new_page(viewport={'width': 1440, 'height': 1200}, reduced_motion='reduce', device_scale_factor=1)
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))
                page.goto(f'http://127.0.0.1:{port}')
                page.screenshot(path=str(output / 'projects-empty.png'))
                page.locator('#configure-btn').click()
                page.locator('#target-url').fill(target_url)
                page.locator('#custom-ports').fill(str(target.server_port))
                page.evaluate("document.getElementById('main-content').scrollTop = 0")
                page.screenshot(path=str(output / 'scan-setup-light.png'))
                page.locator('#theme-toggle').click()
                page.locator('#scan-btn').click()
                expect(page.locator('#history-status')).to_have_text('1 saved scan', timeout=20000)
                first_confirmed = int(page.locator('#confirmed-count').inner_text())
                expect(page.locator('#attention-title')).to_contain_text('confirmed')
                page.screenshot(path=str(output / 'baseline-dark.png'))
                target.hardened = True
                page.locator('#rescan-btn').click()
                expect(page.locator('#history-status')).to_have_text('2 saved scans', timeout=20000)
                expect(page.locator('#confirmed-count')).not_to_have_text(str(first_confirmed))
                final_confirmed = int(page.locator('#confirmed-count').inner_text())
                page.screenshot(path=str(output / 'desktop-dark.png'))
                # Source and severity controls narrow the actual report.
                page.locator('[data-severity="low"]').click()
                assert page.locator('#findings-list .finding:not(.finding--low)').count() == 0
                expect(page.locator('#findings-list')).to_contain_text('Content-Security-Policy')
                page.locator('[data-severity="low"]').click()
                page.locator('#findings-module').select_option('cookie_scan')
                expect(page.locator('#findings-list')).to_contain_text('No findings match')
                page.locator('#show-passed').check()
                expect(page.locator('#findings-list')).to_contain_text('Properly Secured')
                page.locator('#findings-severity').select_option('pass')
                expect(page.locator('#show-passed')).to_be_checked()
                page.locator('#show-passed').uncheck()
                expect(page.locator('#findings-severity')).to_have_value('all')
                page.locator('#findings-module').select_option('all')
                page.locator('#theme-toggle').click()
                page.screenshot(path=str(output / 'desktop-light.png'))
                page.locator('#theme-toggle').click()
                page.locator('#compare-toggle-btn').click()
                expect(page.locator('#comparison-baseline')).to_be_enabled()
                page.locator('#compare-scans-btn').click()
                expect(page.locator('#comparison-results')).to_contain_text('Resolved issues')
                expect(page.locator('#comparison-results')).to_contain_text('Sensitive File Exposed: /.env')
                resolved_count = int(page.locator('#comparison-results .change-positive strong').first.inner_text())
                assert resolved_count > 0
                page.evaluate("document.getElementById('main-content').scrollTop = 0")
                page.screenshot(path=str(output / 'comparison-dark.png'))
                page.locator('#close-comparison-btn').click()
                # Browser print uses the dedicated report rather than clipped scroll panels.
                page.emulate_media(media='print')
                expect(page.locator('#print-report')).to_be_visible()
                expect(page.locator('#sidebar')).not_to_be_visible()
                page.pdf(path=str(output / 'sample-report.pdf'), format='A4', print_background=True, prefer_css_page_size=True)
                page.emulate_media(media='screen')
                # Intermediate widths must keep statistics inside their cards.
                page.set_viewport_size({'width': 900, 'height': 1100})
                assert page.locator('.stat-chip').evaluate_all("cards => cards.every(card => card.scrollWidth <= card.clientWidth + 1)")
                # A narrow viewport captures both the overview and the findings.
                page.set_viewport_size({'width': 390, 'height': 1100})
                page.evaluate("document.getElementById('main-content').scrollTop = 0")
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.screenshot(path=str(output / 'mobile-dark.png'))
                page.evaluate("const main = document.getElementById('main-content'); const card = document.querySelector('.results-card'); main.scrollTop += card.getBoundingClientRect().top - main.getBoundingClientRect().top - 12;")
                page.screenshot(path=str(output / 'mobile-findings.png'))
                page.locator('#menu-toggle').click()
                page.locator('.primary-nav [data-view="reports"]').click()
                page.locator('#history-search').fill('does-not-exist')
                expect(page.locator('#history-status')).to_have_text('0 matching scans')
                page.locator('#history-search').fill('127.0.0.1')
                expect(page.locator('#history-status')).to_have_text('2 matching scans')
                page.locator('#history-search').fill('')
                expect(page.locator('#history-status')).to_have_text('2 saved scans')
                page.screenshot(path=str(output / 'reports-mobile.png'))
                page.set_viewport_size({'width': 1440, 'height': 1100})
                page.locator('.primary-nav [data-view="home"]').click()
                expect(page.locator('.project-card')).to_have_count(1)
                page.locator('#theme-toggle').click()
                page.locator('#discover-btn').click()
                expect(page.locator('#discover-btn')).to_be_enabled(timeout=15000)
                if target.server_port == 3000:
                    expect(page.locator('.discovered-app')).not_to_have_count(0)
                    expect(page.locator('#discovered-projects')).to_contain_text(target_url)
                page.screenshot(path=str(output / 'projects-light.png'))
                if target.server_port == 3000:
                    page.locator('.discovered-app .md-btn').first.click()
                    expect(page.locator('#target-url')).to_have_value(target_url)
                    page.set_viewport_size({'width': 390, 'height': 1100})
                    expect(page.locator('#mobile-scan-btn')).to_be_in_viewport()
                    page.screenshot(path=str(output / 'scan-setup-mobile.png'))
                    page.set_viewport_size({'width': 1440, 'height': 1100})
                page.locator('.primary-nav [data-view="reports"]').click()
                page.screenshot(path=str(output / 'reports-desktop.png'))
                assert not errors, errors
                browser.close()
            metadata = {'source': 'Real scans of a loopback-only fixture before and after header/cookie/file-access changes', 'baseline_confirmed': first_confirmed, 'final_confirmed': final_confirmed, 'resolved_findings': resolved_count, 'screenshots': sorted(path.name for path in output.glob('*.png') if path.name != 'print-report-preview.png')}
            (output / 'capture-notes.json').write_text(json.dumps(metadata, indent=2))
            print(json.dumps(metadata, indent=2))
        finally:
            process.terminate()
            process.wait(timeout=10)
            target.shutdown()
            target.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path('/workspace/artifacts/localghost'))
    main(parser.parse_args().output)
