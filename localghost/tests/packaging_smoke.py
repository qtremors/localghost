"""Build and verify an installed wheel outside the checkout.

Run with: uv run python tests/packaging_smoke.py
Uses locked dependencies, temporary storage, a local page, and one browser at a time.
"""

import hashlib
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from contextlib import closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx

PROJECT = Path(__file__).resolve().parents[1]


def run(arguments, *, cwd, env=None):
    result = subprocess.run(arguments, cwd=cwd, env=env, capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise AssertionError(f"Command failed: {arguments[0]}\n{result.stdout[-2000:]}\n{result.stderr[-4000:]}")
    return result.stdout


class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (
            b"<html><title>Installed capture</title><body><article>Saved outside the checkout</article></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main():
    with tempfile.TemporaryDirectory(prefix="localghost-package-") as temporary:
        root = Path(temporary)
        dist, venv, outside = root / "dist", root / "venv", root / "outside"
        outside.mkdir()
        run(["uv", "build", "--out-dir", str(dist)], cwd=PROJECT)
        wheel = next(dist.glob("*.whl"))
        run(["uv", "venv", "--python", sys.executable, str(venv)], cwd=outside)
        scripts = venv / ("Scripts" if os.name == "nt" else "bin")
        python = scripts / ("python.exe" if os.name == "nt" else "python")
        packages = tomllib.loads((PROJECT / "uv.lock").read_text(encoding="utf-8"))["package"]
        constraints = root / "constraints.txt"
        constraints.write_text("\n".join(f"{p['name']}=={p['version']}" for p in packages if p["name"] != "localghost"))
        run(
            [
                "uv",
                "pip",
                "install",
                "--constraint",
                str(constraints),
                "--python",
                str(python),
                str(wheel) + "[browser]",
            ],
            cwd=outside,
        )
        env = {**os.environ, "XDG_DATA_HOME": str(root / "data"), "XCRAPE_ENV_FILE": str(root / "empty.env")}
        for name in ("PYTHONPATH", "LOCALGHOST_DB_PATH", "LOCALGHOST_CAPTURE_DB_PATH", "DATABASE_URL"):
            env.pop(name, None)
        location = run([str(python), "-c", "import backend; print(backend.__file__)"], cwd=outside, env=env).strip()
        assert Path(location).resolve().is_relative_to(venv.resolve()), location
        command = scripts / ("localghost.exe" if os.name == "nt" else "localghost")
        assert "--port" in run([str(command), "--help"], cwd=outside, env=env)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        env["PORT"] = str(port)
        legacy = scripts / ("xcrape.exe" if os.name == "nt" else "xcrape")
        log = (root / "server.log").open("w+", encoding="utf-8")
        server = subprocess.Popen(
            [str(legacy)],
            cwd=outside,
            env=env,
            stdout=log,
            stderr=log,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        target = ThreadingHTTPServer(("127.0.0.1", 0), Page)
        threading.Thread(target=target.serve_forever, daemon=True).start()
        try:
            url = f"http://127.0.0.1:{port}"
            with httpx.Client(trust_env=False, timeout=3) as client:
                for _ in range(150):
                    try:
                        if client.get(url + "/health").status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.05)
                else:
                    log.seek(0)
                    raise AssertionError(log.read()[-4000:])
                for asset in (
                    "/",
                    "/static/js/app.js",
                    "/static/localghost.svg",
                    "/static/fonts/inter-latin-variable.woff2",
                    "/static/xcrape/view.html",
                    "/static/xcrape/script.js",
                    "/static/xcrape/style.css",
                ):
                    response = client.get(url + asset)
                    assert response.status_code == 200 and response.content, asset
                page = f"http://127.0.0.1:{target.server_port}"
                response = client.post(url + "/api/scrape", json={"url": page, "selector": "article"})
                assert response.status_code == 202, response.text
                job_id = response.json()["job_id"]
                for _ in range(300):
                    job = client.get(url + f"/api/jobs/{job_id}").json()["job"]
                    if job["status"] in ("completed", "failed"):
                        break
                    time.sleep(0.1)
                assert job["status"] == "completed", job
                data = client.get(url + f"/api/xcrape/jobs/{job_id}/export").json()
                assert data["meta"]["title"] == "Installed capture" and data["screenshot"]
                assert data["selector_results"][0]["text"] == "Saved outside the checkout"
                output = outside / "capture.json"
                run(
                    [str(python), "-m", "backend.modules.xcrape", "capture", page, "--output", str(output)],
                    cwd=outside,
                    env=env,
                )
                assert json.loads(output.read_text(encoding="utf-8"))["meta"]["title"] == "Installed capture"
                assert (root / "data/localghost/captures.db").is_file()
                assert (root / "data/localghost/localghost.db").is_file()
                assert not (outside / "captures.db").exists()
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
            log.close()
            target.shutdown()
            target.server_close()
        source = root / "data/localghost/captures.db"
        copied = root / "imported/captures.db"
        digest = hashlib.sha256(source.read_bytes()).digest()
        run(
            [str(python), "-m", "backend.modules.xcrape", "import-db", str(source), "--destination", str(copied)],
            cwd=outside,
            env=env,
        )
        with closing(sqlite3.connect(copied)) as connection:
            saved = json.loads(connection.execute("SELECT data FROM jobs").fetchone()[0])
        assert saved["meta"]["title"] == "Installed capture" and saved["screenshot"]
        assert hashlib.sha256(source.read_bytes()).digest() == digest
        print(
            "Wheel, installed assets, both commands, capture worker, exports, standalone capture, writable paths, and history copy passed."
        )


if __name__ == "__main__":
    main()
