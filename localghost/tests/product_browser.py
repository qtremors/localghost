"""Exercise project context, sessions, evidence, and rechecks in the desktop UI.

All targets and source files are temporary test fixtures. No user history is changed.
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

SESSION = 'localghost-test-session-value'


class Target(BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path.split('?', 1)[0]
        fixed = self.server.fixed
        status, content_type, body = 200, 'text/html', b''
        if path == '/.env':
            status, content_type, body = (404, 'text/plain', b'') if fixed else (200, 'text/plain', b'EXAMPLE_PASSWORD=not-a-real-secret')
        elif path == '/app.js':
            content_type = 'application/javascript'
            body = b"console.log('app loaded');" if fixed else b"throw new Error('Example page failure');"
        elif path == '/data':
            status, content_type, body = (200 if fixed else 500), 'application/json', b'{"example":true}'
        elif path in ('/', '/account'):
            if path == '/account' and SESSION not in self.headers.get('Cookie', ''):
                status, body = 401, b'Login required'
            else:
                body = b'<html lang="en"><head><title>Local test app</title></head><body><main><h1>Local test app</h1><script src="/app.js"></script><script>fetch("/data")</script></main></body></html>'
        else:
            status = 404
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
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


def run(output, axe_path=None):
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='localghost-product-') as temporary:
        source = Path(temporary) / 'source'
        source.mkdir()
        (source / 'package.json').write_text(json.dumps({'name': 'local-test-app', 'dependencies': {'next': '16'}, 'scripts': {'build': 'next build', 'start': 'next start'}}))
        (source / 'next.config.mjs').write_text('export default { typescript: { ignoreBuildErrors: true } };')
        for name in ('app/page.tsx', 'app/account/page.tsx'):
            file = source / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text('export default function Page() { return null; }')
        server = ThreadingHTTPServer(('127.0.0.1', 0), Target)
        server.fixed = False
        threading.Thread(target=server.serve_forever, daemon=True).start()
        target = f'http://127.0.0.1:{server.server_port}'
        port = unused_port()
        process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', str(port), '--log-level', 'error'],
                                   cwd=PROJECT, env={**os.environ, 'LOCALGHOST_DB_PATH': str(Path(temporary) / 'history.db')}, stdout=subprocess.DEVNULL)
        a11y = {}
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
                browser = playwright.chromium.launch(headless=True, executable_path=executable)
                page = browser.new_page(viewport={'width': 1536, 'height': 1152}, reduced_motion='reduce')
                errors = []
                page.on('pageerror', lambda error: errors.append(str(error)))

                def accessibility(name):
                    if axe_path:
                        if not page.evaluate('Boolean(window.axe)'):
                            page.evaluate(axe_path.read_text())
                        violations = page.evaluate('async () => (await axe.run(document, {runOnly:{type:"tag",values:["wcag2a","wcag2aa","wcag21aa"]}})).violations')
                        a11y[name] = violations
                        assert not violations, [(item['id'], [node['target'] for node in item['nodes']]) for item in violations]

                page.goto(f'http://127.0.0.1:{port}')
                page.locator('#configure-btn').click()
                page.locator('#target-url').fill(target)
                page.locator('#custom-ports').fill(str(server.server_port))
                page.locator('#source-path').fill(str(source))
                page.locator('#inspect-source-btn').click()
                expect(page.locator('#source-status')).to_contain_text('Next.js')
                page.locator('.route-choice').filter(has_text='/account').locator('input').check()
                expect(page.locator('#scan-paths')).to_have_value('/account')
                page.locator('#session-cookie').locator('..').locator('..').evaluate('(details) => details.open = true')
                page.locator('#session-cookie').fill(f'login={SESSION}')
                page.evaluate("document.getElementById('main-content').scrollTop = 0")
                accessibility('setup-light')
                page.screenshot(path=str(output / 'setup-source.png'))
                page.locator('#scan-btn').click()
                expect(page.locator('#results-dashboard')).to_be_visible(timeout=30000)
                expect(page.locator('#history-status')).to_have_text('1 saved scan')
                assert int(page.locator('#confirmed-count').inner_text()) >= 3
                assert page.locator('#score-value').count() == 0
                assert SESSION not in page.locator('#results-dashboard').inner_text()
                page.locator('[data-verification="confirmed"]').click()
                assert page.locator('#findings-list .verification-label').all_inner_texts() and all(label == 'Confirmed' for label in page.locator('#findings-list .verification-label').all_inner_texts())
                card = page.locator('#findings-list .finding').filter(has_text='Sensitive File Exposed: /.env')
                card.locator('summary').click()
                expect(card).to_contain_text('GET')
                expect(card).to_contain_text('200')
                accessibility('findings-light')
                page.screenshot(path=str(output / 'report-evidence.png'))
                with page.expect_download() as download:
                    page.locator('#export-json-btn').click()
                report = json.loads(Path(download.value.path()).read_text())
                assert report['authentication_used']
                assert report['browser_check']['pages'][1]['status'] == 200
                assert SESSION not in json.dumps(report)
                (output / 'before.json').write_text(json.dumps(report, indent=2))
                server.fixed = True
                card.locator('[data-recheck]').click()
                expect(page.locator('#recheck-session-dialog')).to_be_visible()
                accessibility('session-dialog')
                page.locator('#recheck-cookie').fill(f'login={SESSION}')
                page.locator('#recheck-session-dialog button[value="check"]').click()
                expect(card.locator('.finding__recheck-status')).to_contain_text('Resolved', timeout=20000)
                expect(page.locator('#history-status')).to_have_text('2 saved scans')
                page.screenshot(path=str(output / 'fix-rechecked.png'))
                card.locator('[data-evidence-report]').click()
                expect(page.locator('#confirmed-count')).to_have_text('0')
                # Return to original evidence and check the page error independently.
                page.go_back()
                expect(page.locator('#results-dashboard')).to_be_visible()
                expect(page.locator('#confirmed-count')).not_to_have_text('0')
                page.locator('[data-verification="confirmed"]').click()
                script_error = page.locator('#findings-list .finding').filter(has_text='JavaScript error on page').first
                script_error.locator('[data-recheck]').click()
                page.locator('#recheck-cookie').fill(f'login={SESSION}')
                page.locator('#recheck-session-dialog button[value="check"]').click()
                expect(script_error.locator('.finding__recheck-status')).to_contain_text('Resolved', timeout=20000)
                page.locator('#tab-source').click()
                expect(page.locator('#panel-source')).to_contain_text('app/account/page.tsx')
                accessibility('source-light')
                page.screenshot(path=str(output / 'project-details.png'))
                page.locator('#tab-browser').click()
                expect(page.locator('#panel-browser')).to_contain_text('/account')
                accessibility('pages-light')
                page.screenshot(path=str(output / 'pages.png'))
                page.locator('#theme-toggle').click()
                accessibility('pages-dark')
                page.locator('#tab-all-findings').click()
                accessibility('findings-dark')
                page.screenshot(path=str(output / 'report-dark.png'))
                with page.expect_download() as download:
                    page.locator('#export-json-btn').click()
                final = json.loads(Path(download.value.path()).read_text())
                assert len(final['rechecks']) == 2
                assert all(item['state'] == 'resolved' for item in final['rechecks'])
                (output / 'original-with-rechecks.json').write_text(json.dumps(final, indent=2))
                # A project keeps the original full-scan settings after an individual recheck.
                page.locator('.primary-nav [data-view="home"]').click()
                expect(page.locator('.project-card h3')).to_have_text('local-test-app')
                page.locator('.project-card .md-btn').click()
                expect(page.locator('#scan-setup')).to_be_visible()
                expect(page.locator('#source-path')).to_have_value(str(source))
                expect(page.locator('#scan-paths')).to_have_value('/account')
                expect(page.locator('#plan-check-count')).to_have_text('9')
                expect(page.locator('#session-cookie')).to_have_value('')
                assert not errors, errors
                browser.close()
            (output / 'accessibility.json').write_text(json.dumps(a11y, indent=2))
            (output / 'results.json').write_text(json.dumps({'source': 'Temporary loopback test app and source metadata; not a Next.js runtime',
                                                          'confirmed_before': report['summary']['confirmed'], 'rechecks': final['rechecks'],
                                                          'session_redacted': True, 'browser_errors': errors,
                                                          'accessibility': {name: len(items) for name, items in a11y.items()}}, indent=2))
            print('Product browser checks passed: source routes, logged-in page, evidence, file fix, JavaScript fix, preserved history, credential redaction, and desktop themes.')
        finally:
            process.terminate()
            process.wait(timeout=10)
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--axe', type=Path)
    args = parser.parse_args()
    run(args.output, args.axe)
