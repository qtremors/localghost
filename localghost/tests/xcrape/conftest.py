import asyncio
import base64
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

from backend.main import app
from backend.modules.xcrape import db

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/5ioAAAAASUVORK5CYII=")
ARTICLE = """<!doctype html><html><head><title>The kitchen garden</title>
<meta name="description" content="A few herbs, a sunny windowsill, and something good to grow.">
<style>body{margin:0;background:#f3f0e6;color:#2f4736;font:19px/1.6 Georgia,serif}main{max-width:900px;margin:80px auto;padding:40px}header{font:13px sans-serif;letter-spacing:3px}h1{font-size:72px;line-height:1.05;font-weight:400}p{max-width:560px}a{color:#355e46}section{border-top:1px solid #b9c8ad;margin-top:48px;padding-top:28px}</style>
<script type="application/ld+json">{"@type":"Article","name":"The kitchen garden"}</script></head>
<body><main><header>FIELD NOTES / 001</header><h2>A slower kind of morning</h2><h1>The kitchen garden</h1>
<p class="lead">A few herbs, a sunny windowsill, and something good to grow. Start small, pay attention, and enjoy what follows.</p>
<p>Basil likes the light. Mint prefers a pot of its own. Rosemary asks for less water than you might think.</p>
<section><a href="child">Read the growing guide</a><img src="image.png" alt="Basil on the windowsill" width="120" height="80">
<ul><li>Basil</li><li>Mint</li><li>Rosemary</li></ul><table><tr><th>Herb</th><th>Light</th></tr><tr><td>Basil</td><td>Bright</td></tr></table></section></main></body></html>"""


@pytest.fixture
async def database(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "data" / "test.db")
    await db.init_db()
    return db.DB_PATH


@pytest.fixture
async def api(database):
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            yield client


@pytest.fixture(scope="session")
def page_server():
    visits = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            visits[self.path] = visits.get(self.path, 0) + 1
            if self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/nested/article")
                self.end_headers()
                return
            if self.path == "/slow":
                time.sleep(8)
            content, status, mime = ARTICLE.encode(), 200, "text/html; charset=utf-8"
            if self.path.endswith(".png"):
                content, mime = PNG, "image/png"
            elif self.path == "/missing":
                status = 404
                content = b"<html><title>Missing page</title><body>Not found.</body></html>"
            elif self.path == "/base":
                content = ARTICLE.replace("<head>", '<head><base href="/assets/">').encode()
            elif self.path == "/unsafe":
                content = b"""<html><title>Attribute checks</title><body><img src="/image.png" alt='&quot; onload=&quot;window.__xssAlt=1' width='&lt;img src=x onerror=window.__xssDims=1&gt;' height="1"></body></html>"""
            elif self.path == "/dynamic":
                content = b"""<html><title>Dynamic page</title><body><script>setTimeout(()=>{let p=document.createElement('p');p.textContent='This content arrived after the page opened.';document.body.append(p)},100)</script></body></html>"""
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.end_headers()
            try:
                self.wfile.write(content)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}", visits
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


@pytest.fixture
def live_server(tmp_path):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    url = f"http://127.0.0.1:{port}"
    log = (tmp_path / "server.log").open("w+")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "backend.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=Path(__file__).resolve().parents[2],
        env={
            **os.environ,
            "LOCALGHOST_DB_PATH": str(tmp_path / "scans.db"),
            "LOCALGHOST_CAPTURE_DB_PATH": str(tmp_path / "browser.db"),
        },
        stdout=log,
        stderr=log,
    )
    try:
        for _ in range(150):
            try:
                if httpx.get(url, timeout=0.2, trust_env=False).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        else:
            log.seek(0)
            pytest.fail("Server did not start: " + log.read())
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        log.close()


async def finished(client, job_id):
    for _ in range(300):
        job = (await client.get(f"/api/xcrape/jobs/{job_id}")).json()["job"]
        if job["status"] in ("completed", "failed"):
            return job
        await asyncio.sleep(0.1)
    pytest.fail("Capture did not finish")
