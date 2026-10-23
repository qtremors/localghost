import hashlib
import io
import json
import os
import sqlite3
import subprocess
import sys

import pytest

from backend.modules.xcrape import db
from backend.modules.xcrape.__main__ import import_database


async def test_import_preserves_source_and_upgrades_the_copy(tmp_path, monkeypatch):
    original = tmp_path / "old.db"
    copied = tmp_path / "new.db"
    with sqlite3.connect(original) as connection:
        connection.execute("CREATE TABLE jobs (id INTEGER PRIMARY KEY, url TEXT, status TEXT, data TEXT)")
        connection.execute(
            "INSERT INTO jobs VALUES (1, ?, 'completed', ?)",
            ("https://example.test/article", json.dumps({"meta": {"title": "Saved"}, "text": ["keep"]})),
        )
    digest = hashlib.sha256(original.read_bytes()).digest()
    assert import_database(original, copied) == 1
    monkeypatch.setattr(db, "DB_PATH", copied)
    await db.init_db()
    assert json.loads((await db.get_job(1))["data"])["text"] == ["keep"]
    assert (await db.get_jobs(q="Saved"))["total"] == 1
    assert hashlib.sha256(original.read_bytes()).digest() == digest
    with pytest.raises(FileExistsError):
        import_database(original, copied)


def test_invalid_import_never_creates_destination(tmp_path):
    source, destination = tmp_path / "unrelated.db", tmp_path / "captures.db"
    with sqlite3.connect(source) as connection:
        connection.execute("CREATE TABLE other (id INTEGER)")
    with pytest.raises(ValueError, match="compatible"):
        import_database(source, destination)
    assert not destination.exists()


def test_standalone_capture_without_dashboard(tmp_path, page_server):
    from backend.modules.xcrape.settings import PROJECT_DIR

    output = tmp_path / "capture.json"
    env = {**os.environ, "LOCALGHOST_DB_PATH": str(tmp_path / "unused.db")}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "backend.modules.xcrape",
            "capture",
            page_server[0] + "/article",
            "--selector",
            ".lead",
            "--output",
            str(output),
        ],
        cwd=PROJECT_DIR,
        env=env,
        capture_output=True,
        text=True,
        timeout=70,
    )
    assert result.returncode == 0, result.stderr
    saved = json.loads(output.read_text(encoding="utf-8"))
    assert saved["screenshot"] and saved["selector_results"]
    assert not (tmp_path / "unused.db").exists()


def test_missing_browser_support_has_install_instructions(monkeypatch, capsys):
    import builtins

    from backend.modules.xcrape import worker

    original = builtins.__import__

    def without_browser(name, *args, **kwargs):
        if name.startswith("playwright"):
            raise ImportError("Browser extra not installed")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", without_browser)
    monkeypatch.setattr(sys, "stdin", io.StringIO('{"url":"http://localhost"}'))
    worker.main()
    result = json.loads(capsys.readouterr().out)
    assert result["error_type"] == "BrowserUnavailable"
    assert "uv sync --extra browser" in result["error"]


def test_host_starts_without_optional_browser_package(tmp_path):
    from backend.modules.xcrape.settings import PROJECT_DIR

    code = """
import asyncio
import builtins
original = builtins.__import__
def without_browser(name, *args, **kwargs):
    if name.startswith('playwright'):
        raise ImportError('Browser extra not installed')
    return original(name, *args, **kwargs)
builtins.__import__ = without_browser
from backend.main import app
async def start():
    async with app.router.lifespan_context(app):
        print('ready without browser')
asyncio.run(start())
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT_DIR,
        env={
            **os.environ,
            "LOCALGHOST_DB_PATH": str(tmp_path / "scans.db"),
            "LOCALGHOST_CAPTURE_DB_PATH": str(tmp_path / "captures.db"),
        },
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "ready without browser" in result.stdout


@pytest.mark.parametrize("failure", ["directory", "corrupt", "setting"])
def test_capture_failure_leaves_host_and_history_available(tmp_path, failure):
    from backend.modules.xcrape.settings import PROJECT_DIR

    capture = tmp_path if failure == "directory" else tmp_path / "captures.db"
    if failure == "corrupt":
        capture.write_text("not a database")
    env = {
        **os.environ,
        "LOCALGHOST_DB_PATH": str(tmp_path / "scans.db"),
        "LOCALGHOST_CAPTURE_DB_PATH": str(capture),
        "XCRAPE_ENV_FILE": str(tmp_path / ".env"),
    }
    if failure == "setting":
        env["XCRAPE_WORKERS"] = "bad"
    code = """
import asyncio
import httpx
from backend.main import app
async def check():
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost') as client:
            assert (await client.get('/health')).status_code == 200
            assert (await client.get('/api/history')).status_code == 200
            result = await client.get('/api/xcrape/jobs')
            assert result.status_code == 503 and result.json()['detail']
            legacy = await client.get('/api/jobs')
            assert legacy.status_code == 503 and legacy.json()['error']
        print('host available')
asyncio.run(check())
"""
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=PROJECT_DIR, env=env, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, result.stderr
    assert "host available" in result.stdout
