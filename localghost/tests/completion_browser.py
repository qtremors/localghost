"""Exercise real Docker login, evidence, source edits, and rechecks on desktop.

Requires a locally available Node image (or an image with a node entry point).
All source, containers, and history belong to this disposable test.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

from browser_smoke import PROJECT, unused_port
from playwright.sync_api import expect, sync_playwright

NODE_APP = r'''
const http=require('http'), fs=require('fs');
const token='localghost-fixture-session';
const password='localghost-fixture-password';
http.createServer((req,res)=>{
 const path=new URL(req.url,'http://localhost').pathname;
 const fixed=fs.existsSync('/review/fixed');
 const signed=(req.headers.cookie||'').includes('sid='+token);
 if(req.method==='POST'&&path==='/session'){
  let data=''; req.on('data',chunk=>data+=chunk);req.on('end',()=>{
   const form=new URLSearchParams(data);
   if(form.get('username')!=='review-user'||form.get('password')!==password){res.writeHead(401);res.end();return;}
   res.writeHead(303,{'Location':'/account.html','Set-Cookie':'sid='+token+'; Path=/'+(fixed?'; HttpOnly; SameSite=Lax':'')});res.end();
  });return;
 }
 const headers={'Content-Type':'text/html; charset=utf-8'};
 let status=200, body='';
 if(path==='/login.html') body='<html><title>Sign in</title><form method="POST" action="/session"><input name="username"><input name="password" type="password"><button type="submit">Sign in</button></form></html>';
 else if(path==='/.env') {headers['Content-Type']='text/plain';status=fixed?404:200;body=fixed?'':'SERVICE_SECRET=localghost-fixture-config-value';}
 else if(path==='/app.js') {headers['Content-Type']='application/javascript';body="fetch('/api/notes');"+(fixed?'':"throw new Error('Notes view could not load');");}
 else if(path==='/api/notes') {
  headers['Content-Type']='application/json';status=signed?(fixed?200:500):401;body=JSON.stringify({notes:[],error:fixed?null:'Local fixture error'});
  if(!fixed){headers['Access-Control-Allow-Origin']=req.headers.origin||'';headers['Access-Control-Allow-Credentials']='true';}
 }
 else if(path==='/account.html') {status=signed?200:401;body=signed?'<html><title>Notes</title><main id="account">Your notes</main><script src="/app.js"></script></html>':'Sign in';}
 else if(path==='/'||path==='/index.html') body='<html><title>Local notes</title><main>Notes</main><script src="/app.js"></script></html>';
 else {status=404;body='Not found';}
 res.writeHead(status,headers);res.end(body);
}).listen(3000,'0.0.0.0');
'''


def run(output, image, axe, node_executable):
    output.mkdir(parents=True, exist_ok=True)
    environment = {key: value for key, value in os.environ.items() if key not in ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}
    docker = ['docker', '--host=unix:///var/run/docker.sock']
    with tempfile.TemporaryDirectory(prefix='localghost-docker-acceptance-') as temporary:
        source = Path(temporary) / 'app'
        source.mkdir()
        (source / 'server.cjs').write_text(NODE_APP)
        (source / 'package.json').write_text('{"name":"local-notes","scripts":{"start":"node server.cjs"}}')
        for name in ('index.html', 'account.html', 'login.html'):
            (source / name).write_text('<main>Disposable local test page</main>')
        compose = Path(temporary) / 'compose.json'
        compose.write_text(json.dumps({'services': {'web': {'image': image, 'entrypoint': [node_executable, '/review/server.cjs'],
                                        'working_dir': '/review', 'user': f'{os.getuid()}:{os.getgid()}', 'ports': ['127.0.0.1::3000'],
                                        'volumes': [str(source) + ':/review:ro']}}}))
        compose_command = [*docker, 'compose', '-p', 'localghost-completion-' + str(os.getpid()), '-f', str(compose)]
        process = None
        try:
            subprocess.run([*compose_command, 'up', '-d', '--pull', 'never'], env=environment, check=True, stdout=subprocess.DEVNULL)
            binding = subprocess.check_output([*compose_command, 'port', 'web', '3000'], env=environment, text=True).strip()
            target = 'http://' + binding
            for _ in range(100):
                try:
                    urlopen(target, timeout=.5).close()
                    break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Docker app did not start')
            port = unused_port()
            api = f'http://127.0.0.1:{port}'
            process = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', str(port), '--log-level', 'error'],
                                       cwd=PROJECT, env={**os.environ, 'LOCALGHOST_DB_PATH': str(Path(temporary) / 'history.db')}, stdout=subprocess.DEVNULL)
            for _ in range(100):
                try:
                    urlopen(api + '/health', timeout=.5).close()
                    break
                except OSError:
                    time.sleep(.1)
            accessibility, browser_errors = {}, []
            with sync_playwright() as playwright:
                executable = os.getenv('LOCALGHOST_BROWSER') or ('/usr/bin/chromium' if Path('/usr/bin/chromium').exists() else None)
                browser = playwright.chromium.launch(headless=True, executable_path=executable)
                page = browser.new_page(viewport={'width': 1600, 'height': 1150}, reduced_motion='reduce')
                page.on('pageerror', lambda error: browser_errors.append(str(error)))

                def capture(name):
                    if axe:
                        page.evaluate(axe.read_text())
                        violations = page.evaluate('async () => (await axe.run(document, {runOnly:{type:"tag", values:["wcag2a","wcag2aa","wcag21aa"]}})).violations')
                        accessibility[name] = violations
                        assert not violations, [(item['id'], [node['target'] for node in item['nodes']]) for item in violations]
                    page.screenshot(path=str(output / (name + '.png')))

                page.goto(api)
                page.locator('#docker-discover-btn').click()
                row = page.locator('#docker-projects .discovered-app').filter(has_text=target)
                expect(row).to_contain_text('Compose: web', timeout=30000)
                expect(row).to_contain_text(str(source))
                capture('docker-apps')
                row.get_by_role('button', name=target, exact=True).click()
                expect(page.locator('#source-path')).to_have_value(str(source))
                expect(page.locator('#mod-source')).to_be_checked()
                page.locator('#inspect-source-btn').click()
                expect(page.locator('#source-status')).to_contain_text('HTML/JavaScript')
                page.locator('.route-choice').filter(has_text='/account.html').locator('input').check()
                page.locator('#custom-ports').fill(binding.rsplit(':', 1)[1])
                page.locator('#session-cookie').evaluate('(input) => input.closest("details").open = true')
                page.locator('#use-browser-login').evaluate('(input) => input.closest("details").open = true')
                page.locator('#use-browser-login').check()
                page.locator('#login-path').fill('/login.html')
                page.locator('#login-username').fill('review-user')
                page.locator('#login-password').fill('localghost-fixture-password')
                page.locator('#login-post-paths').fill('/session')
                page.locator('#login-success-selector').fill('#account')
                page.locator('#main-content').evaluate('(node) => node.scrollTop = 0')
                capture('desktop-setup')
                page.locator('#scan-btn').click()
                expect(page.locator('#results-dashboard')).to_be_visible(timeout=60000)
                expect(page.locator('#report-notices')).to_contain_text('login/session check passed')
                assert not page.locator('#login-password').input_value()
                with page.expect_download() as download:
                    page.locator('#export-json-btn').click()
                before = json.loads(Path(download.value.path()).read_text())
                assert before['authentication']['status'] == 'verified'
                assert target + '/api/notes' in before['route_results']
                assert before['score'] is None
                for value in ('localghost-fixture-session', 'localghost-fixture-password', 'localghost-fixture-config-value'):
                    assert value not in json.dumps(before)
                (output / 'docker-before.json').write_text(json.dumps(before, indent=2))
                page.locator('#main-content').evaluate('(node) => node.scrollTop = 0')
                capture('desktop-report')
                card = page.locator('#findings-list .finding').filter(has_text="Cookie 'sid' Missing HttpOnly Flag")
                card.locator('summary').click()
                expect(card).to_contain_text('POST')
                expect(card).to_contain_text('303')
                expect(card).to_contain_text('sid=[redacted]')
                card.scroll_into_view_if_needed()
                capture('login-cookie-evidence')
                (source / 'fixed').write_text('fixed')
                card.locator('[data-recheck]').click()
                expect(page.locator('#recheck-session-dialog')).to_be_visible()
                expect(page.locator('#recheck-login-note')).to_contain_text('/login.html')
                page.locator('#recheck-username').fill('review-user')
                page.locator('#recheck-password').fill('localghost-fixture-password')
                capture('recheck-login')
                page.locator('#recheck-session-dialog button[value="check"]').click()
                expect(card.locator('.finding__recheck-status')).to_contain_text('Resolved', timeout=30000)
                capture('login-fix-verified')
                # The same immutable report can recheck a different issue with a current session.
                exposed = page.locator('#findings-list .finding').filter(has_text='Sensitive File Exposed: /.env')
                exposed.locator('[data-recheck]').click()
                page.locator('#recheck-cookie').fill('sid=localghost-fixture-session')
                page.locator('#recheck-session-dialog button[value="check"]').click()
                expect(exposed.locator('.finding__recheck-status')).to_contain_text('Resolved', timeout=30000)
                page.locator('#report-scope-details').evaluate('(node) => node.open = true')
                page.locator('#report-scope-details').scroll_into_view_if_needed()
                expect(page.locator('#route-check-results')).to_contain_text('/account.html')
                expect(page.locator('#route-check-results')).to_contain_text('/api/notes')
                capture('tested-routes')
                with page.expect_download() as download:
                    page.locator('#export-json-btn').click()
                final = json.loads(Path(download.value.path()).read_text())
                assert final['findings'] == before['findings']
                assert len(final['rechecks']) == 2 and all(item['state'] == 'resolved' for item in final['rechecks'])
                (output / 'docker-original-with-rechecks.json').write_text(json.dumps(final, indent=2))
                page.locator('#theme-toggle').click()
                page.locator('#tab-browser').click()
                capture('desktop-pages-dark')
                assert not browser_errors, browser_errors
                browser.close()
            (output / 'results.json').write_text(json.dumps({'target': target, 'source': 'Disposable HTML/JS app in a real Docker Compose container with a read-only source bind mount',
                                                            'authentication': 'Form login followed by a signed-in element assertion',
                                                            'confirmed': before['summary']['confirmed'], 'rechecks': [item['state'] for item in final['rechecks']],
                                                            'original_evidence_preserved': True, 'credentials_redacted': True,
                                                            'browser_errors': browser_errors, 'accessibility': {name: len(items) for name, items in accessibility.items()}}, indent=2))
            (output / 'accessibility.json').write_text(json.dumps(accessibility, indent=2))
            print('Docker desktop acceptance passed: published port, Compose identity, source mount, form login, API route audits, exact redacted evidence, and verified fixes.')
        finally:
            if process:
                process.terminate()
                process.wait(timeout=10)
            subprocess.run([*compose_command, 'down', '--remove-orphans'], env=environment, check=True, stdout=subprocess.DEVNULL)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--image', required=True, help='Locally available image with Node; never pulled by this script')
    parser.add_argument('--axe', type=Path)
    parser.add_argument('--node-executable', default='node')
    args = parser.parse_args()
    run(args.output, args.image, args.axe, args.node_executable)
