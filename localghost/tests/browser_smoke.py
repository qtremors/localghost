"""Browser smoke checks against temporary history and a local fixture server.

Run with: uv run --with playwright python tests/browser_smoke.py
Set LOCALGHOST_BROWSER to a Chromium executable, or install Playwright Chromium.
"""

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import urlopen

from playwright.sync_api import expect, sync_playwright

PROJECT = Path(__file__).resolve().parents[1]


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        if getattr(self.server, 'unavailable', False):
            body = b'Target unavailable'
            self.send_response(503)
            self.send_header('Content-Type', 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path.startswith('/slow'):
            time.sleep(2)
        body = b'<html><title>Fixture</title>Local test application</html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Powered-By', 'Express/5.0')
        self.send_header('Set-Cookie', 'session=example; SameSite=Lax')
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


def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def new_scan(page):
    page.locator('.top-new-scan').click()
    expect(page.locator('#scan-setup')).to_be_visible()


def navigate(page, view):
    if page.locator('#menu-toggle').is_visible():
        page.locator('#menu-toggle').click()
    page.locator(f'.primary-nav [data-view="{view}"]').click()


def main():
    with tempfile.TemporaryDirectory(prefix='localghost-browser-') as temporary:
        target = ThreadingHTTPServer(('127.0.0.1', 0), Target)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        target_url = f'http://127.0.0.1:{target.server_port}'
        port = unused_port()
        database = str(Path(temporary) / 'history.db')
        command = (
            'from backend.database import db; '
            f'db.DB_PATH = {database!r}; '
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
                executable = os.getenv('LOCALGHOST_BROWSER')
                if not executable and Path('/usr/bin/chromium').exists():
                    executable = '/usr/bin/chromium'
                browser = playwright.chromium.launch(executable_path=executable, headless=True, args=['--no-sandbox'])
                page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
                errors = []
                page.on('pageerror', lambda error: (errors.append(str(error)), print('Browser error:', error, flush=True)))
                page.goto(f'http://127.0.0.1:{port}')
                expect(page.locator('#history-status')).to_have_text('0 saved scans')
                expect(page.locator('#empty-state')).to_be_visible()
                page.locator('#configure-btn').click()
                expect(page.locator('#target-url')).to_be_focused()
                assert page.locator('#target-url').evaluate('(input) => input.tabIndex') == 0
                page.locator('#target-url').fill(target_url)
                page.locator('#custom-ports').fill('70000')
                page.locator('#scan-btn').click()
                expect(page.locator('#form-error')).to_contain_text('65535')
                page.locator('#custom-ports').fill(str(target.server_port))
                page.locator('#scan-btn').click()
                expect(page.locator('#results-dashboard')).to_be_visible(timeout=20000)
                expect(page.locator('#completed-count')).to_have_text('8')
                expect(page.locator('#confirmed-count')).to_have_text('0')
                expect(page.locator('#history-status')).to_have_text('1 saved scan')
                page.context.grant_permissions(['clipboard-read', 'clipboard-write'])
                recommendation = page.locator('#findings-list .finding__rec p').first.inner_text()
                page.locator('#findings-list .copy-fix').first.click()
                expect(page.locator('#app-status')).to_have_text('Recommended fix copied.')
                assert page.evaluate('navigator.clipboard.readText()') == recommendation
                page.locator('#findings-search').fill('cannot-match-any-finding')
                expect(page.locator('#findings-count')).to_contain_text('0 of ')
                page.locator('#findings-search').fill('')
                page.locator('#findings-severity').select_option('low')
                assert page.locator('#findings-list .finding').count() > 0
                assert page.locator('#findings-list .finding:not(.finding--low)').count() == 0
                page.locator('#findings-severity').select_option('all')
                page.locator('#tab-all-findings').focus()
                page.keyboard.press('ArrowRight')
                expect(page.locator('#tab-source')).to_have_attribute('aria-selected', 'true')
                page.locator('#tab-ports').click()
                expect(page.locator('#panel-ports')).to_contain_text(str(target.server_port))
                page.locator('#tab-all-findings').click()
                page.screenshot(path=str(Path(temporary) / 'desktop.png'))
                with page.expect_download() as download:
                    page.locator('#export-json-btn').click()
                report = json.loads(Path(download.value.path()).read_text())
                assert report['score'] is None
                assert not any(report['vuln_scan']['sensitive_files'].values())
                page.locator('#rescan-btn').click()
                expect(page.locator('#history-status')).to_have_text('2 saved scans', timeout=20000)
                report_url = page.url
                navigate(page, 'home')
                page.go_back()
                expect(page.locator('#results-dashboard')).to_be_visible()
                assert page.url == report_url
                page.go_forward()
                expect(page.locator('#empty-state')).to_be_visible()
                page.go_back()
                page.reload()
                expect(page.locator('#results-dashboard')).to_be_visible(timeout=20000)
                assert page.url == report_url
                expect(page.locator('#report-name')).to_contain_text('127.0.0.1')
                # A target containing markup must remain inert when recalled from history.
                new_scan(page)
                hostile_target = target_url + '/?<svg/onload=window.PWNED=1>'
                page.locator('#target-url').fill(hostile_target)
                page.locator('[data-preset="quick"]').click()
                page.locator('#scan-btn').click()
                expect(page.locator('#history-status')).to_have_text('3 saved scans', timeout=20000)
                assert page.evaluate('window.PWNED') is None
                assert page.locator('#history-list svg').count() == 0
                # The project overview groups paths under the same app origin.
                navigate(page, 'home')
                expect(page.locator('#workspace-project-count')).to_have_text('1')
                expect(page.locator('.project-card')).to_have_count(1)
                expect(page.locator('#workspace-report-count')).to_have_text('3')
                navigate(page, 'reports')
                # Deletion has an explicit confirmation and leaves other reports intact.
                page.locator('.history-delete').first.click()
                expect(page.locator('#delete-history-dialog')).to_be_visible()
                page.get_by_role('button', name='Keep scan').click()
                expect(page.locator('#history-status')).to_have_text('3 saved scans')
                page.locator('.history-delete').first.click()
                page.get_by_role('button', name='Delete scan', exact=True).click()
                expect(page.locator('#history-status')).to_have_text('2 saved scans')
                # Cancellation disconnects the stream and the next scan can run immediately.
                new_scan(page)
                page.locator('[data-preset="audit"]').click()
                page.locator('#target-url').fill(target_url + '/slow')
                page.locator('#scan-btn').click()
                expect(page.locator('#cancel-scan-btn')).to_be_visible()
                page.locator('#cancel-scan-btn').click()
                expect(page.locator('#progress-text')).to_have_text('Scan cancelled')
                expect(page.locator('#scan-btn')).to_be_enabled()
                new_scan(page)
                page.locator('[data-preset="quick"]').click()
                page.locator('#target-url').fill(target_url)
                page.locator('#scan-btn').click()
                expect(page.locator('#history-status')).to_have_text('3 saved scans', timeout=20000)
                page.locator('#theme-toggle').click()
                expect(page.locator('html')).to_have_attribute('data-theme', 'light')
                page.reload()
                expect(page.locator('html')).to_have_attribute('data-theme', 'light')
                # Narrow viewport navigation, focus containment, and report layout.
                page.set_viewport_size({'width': 390, 'height': 844})
                new_scan(page)
                expect(page.locator('#mobile-scan-btn')).to_be_in_viewport()
                page.locator('[data-preset="audit"]').click()
                expect(page.locator('#mobile-plan-count')).to_have_text('8 checks selected')
                page.locator('[data-preset="quick"]').click()
                expect(page.locator('#mobile-plan-count')).to_have_text('3 checks selected')
                expect(page.locator('#mobile-scan-btn')).to_be_in_viewport()
                page.locator('#target-url').fill(target_url)
                page.locator('#custom-ports').fill(str(target.server_port))
                page.locator('#mobile-scan-btn').click()
                expect(page.locator('#results-dashboard')).to_be_visible(timeout=20000)
                page.locator('#menu-toggle').click()
                expect(page.locator('#sidebar')).to_have_class('sidebar open')
                expect(page.locator('.primary-nav [data-view="home"]')).to_be_focused()
                page.keyboard.press('Shift+Tab')
                assert page.locator('#sidebar').evaluate('(sidebar) => sidebar.contains(document.activeElement)')
                page.keyboard.press('Escape')
                expect(page.locator('#menu-toggle')).to_have_attribute('aria-expanded', 'false')
                assert page.locator('#sidebar').evaluate('(sidebar) => sidebar.inert')
                navigate(page, 'reports')
                page.locator('.history-open').first.click()
                expect(page.locator('#results-dashboard')).to_be_visible()
                expect(page.locator('#sidebar')).not_to_have_class('sidebar open')
                assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
                page.screenshot(path='/tmp/localghost-mobile.png')
                page.set_viewport_size({'width': 1440, 'height': 1000})
                page.screenshot(path='/tmp/localghost-desktop.png')
                # DNS-only reports show the checks completed without a security grade.
                new_scan(page)
                page.locator('[data-preset="quick"]').click()
                page.locator('#mod-ports').uncheck()
                page.locator('#mod-tech').uncheck()
                page.locator('#scan-btn').click()
                expect(page.locator('#completed-count')).to_have_text('1', timeout=20000)
                expect(page.locator('#confirmed-count')).to_have_text('0')
                assert page.locator('#score-value').count() == 0
                # Exercise real pagination without running dozens of scans.
                with sqlite3.connect(database) as connection:
                    for number in range(22):
                        fixture = dict(report, scan_id=f'fixture-{number}', timestamp=f'2026-01-01T00:00:{number:02d}+00:00')
                        connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)',
                            (fixture['scan_id'], fixture['target'], fixture['timestamp'], 50, 'D', json.dumps(fixture)))
                    for number in range(28):
                        fixture = dict(report, scan_id=f'project-{number}', target=f'http://localhost:{6000 + number}', timestamp=f'2025-01-01T00:00:{number:02d}+00:00')
                        connection.execute('INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?)',
                            (fixture['scan_id'], fixture['target'], fixture['timestamp'], 50, 'D', json.dumps(fixture)))
                navigate(page, 'reports')
                page.locator('#history-refresh').click()
                expect(page.locator('#history-status')).to_have_text('55 saved scans')
                expect(page.locator('.history-item')).to_have_count(20)
                page.locator('#history-more').click()
                expect(page.locator('.history-item')).to_have_count(40)
                page.locator('#history-more').click()
                expect(page.locator('.history-item')).to_have_count(55)
                expect(page.locator('#history-more')).not_to_be_visible()
                navigate(page, 'home')
                expect(page.locator('#workspace-project-count')).to_have_text('29')
                expect(page.locator('.project-card')).to_have_count(24)
                page.locator('#projects-more').click()
                expect(page.locator('.project-card')).to_have_count(29)
                expect(page.locator('#projects-more')).not_to_be_visible()
                # Older reports have no saved request. Rescan opens the inferred
                # settings for review instead of silently using unrelated settings.
                with sqlite3.connect(database) as connection:
                    legacy = dict(report)
                    legacy.pop('request', None)
                    connection.execute('UPDATE scans SET results_json = ? WHERE scan_id = ?', (json.dumps(legacy), 'fixture-0'))
                navigate(page, 'reports')
                page.locator('.history-item[data-scan-id="fixture-0"] .history-open').click()
                expect(page.locator('#results-dashboard')).to_be_visible()
                page.locator('#rescan-btn').click()
                expect(page.locator('#scan-setup')).to_be_visible()
                expect(page.locator('#scan-settings-note')).to_contain_text('no saved scan settings')
                expect(page.locator('#plan-check-count')).to_have_text('8')
                # Storage-denied browsers must still initialize and toggle themes.
                restricted = browser.new_page()
                restricted.on('pageerror', lambda error: errors.append(str(error)))
                restricted.add_init_script("Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('Storage denied'); }});")
                restricted.goto(f'http://127.0.0.1:{port}')
                restricted.locator('#theme-toggle').click()
                expect(restricted.locator('html')).to_have_attribute('data-theme', 'light')
                restricted.close()
                # Inconclusive active tests retain diagnostics and never render a pass.
                target.unavailable = True
                new_scan(page)
                page.locator('#target-url').fill(target_url)
                for module in ('ports', 'vulns', 'ssl', 'cors', 'cookies', 'tech', 'dns', 'bench', 'ddos', 'ratelimit', 'xss', 'browser', 'source'):
                    page.locator(f'#mod-{module}').set_checked(module == 'xss')
                page.locator('#scan-btn').click()
                expect(page.locator('#history-status')).to_have_text('56 saved scans', timeout=20000)
                page.locator('#tab-xss').click()
                expect(page.locator('#panel-xss .probe-coverage')).to_be_visible()
                expect(page.locator('#panel-xss')).to_contain_text('Not assessed')
                expect(page.locator('#panel-xss')).not_to_contain_text('No Reflected XSS Detected')
                expect(page.locator('#panel-xss')).not_to_contain_text('undefined')
                new_scan(page)
                page.locator('#mod-xss').uncheck()
                page.locator('#mod-ddos').check()
                page.locator('#mod-ratelimit').check()
                page.locator('#scan-btn').click()
                expect(page.locator('#history-status')).to_have_text('57 saved scans', timeout=20000)
                page.locator('#tab-ddos').click()
                expect(page.locator('#panel-ddos')).to_contain_text('Not assessed')
                expect(page.locator('#panel-ddos')).not_to_contain_text('null/100')
                expect(page.locator('#panel-ddos .probe-coverage')).to_be_visible()
                page.locator('#tab-ratelimit').click()
                expect(page.locator('#panel-ratelimit .probe-coverage')).to_be_visible()
                expect(page.locator('#panel-ratelimit')).to_contain_text('Not assessed')
                expect(page.locator('#panel-ratelimit')).not_to_contain_text('undefined')
                expect(page.locator('#report-connection')).to_contain_text('127.0.0.1')
                assert not errors, errors
                browser.close()
            print('Browser smoke passed: desktop workspace, project grouping, report deep links, copyable fixes, scanning, filters, keyboard navigation, export, history, cancellation, themes, pagination, coverage, compatibility, and incomplete-test diagnostics.')
        finally:
            process.terminate()
            process.wait(timeout=10)
            target.shutdown()
            target.server_close()


if __name__ == '__main__':
    main()
