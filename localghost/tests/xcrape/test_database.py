import json
import sqlite3

from backend.modules.xcrape import db


async def test_populated_legacy_migration_keeps_data_and_accepts_new_jobs(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, status TEXT NOT NULL, data TEXT)"
        )
        connection.execute(
            "INSERT INTO jobs (url,status,data) VALUES (?,?,?)",
            (
                "http://localhost/old",
                "completed",
                '{"text":["keep me"],"meta":{"title":"An older garden"}}',
            ),
        )
    monkeypatch.setattr(db, "DB_PATH", path)
    await db.init_db()
    await db.init_db()
    old = await db.get_job(1)
    assert json.loads(old["data"])["text"] == ["keep me"]
    assert old["created_at"]
    assert (await db.get_jobs(q="older garden"))["jobs"][0]["id"] == 1
    new_id = await db.create_job("http://localhost/new", ".article")
    new = await db.get_job(new_id)
    assert new["created_at"] and new["selector"] == ".article"


async def test_restart_only_reconciles_unfinished_jobs(database):
    pending = await db.create_job("http://localhost/pending")
    running = await db.create_job("http://localhost/running")
    saved = await db.create_job("http://localhost/saved")
    await db.update_job(running, "running")
    await db.update_job(saved, "completed", {"text": ["keep"]})
    await db.recover_interrupted()
    for job_id in (pending, running):
        job = await db.get_job(job_id)
        assert job["status"] == "failed" and job["finished_at"]
        assert json.loads(job["data"])["error_type"] == "Interrupted"
    assert json.loads((await db.get_job(saved))["data"]) == {"text": ["keep"]}


async def test_history_is_paginated_searchable_and_has_no_result_payload(database):
    for i in range(56):
        job_id = await db.create_job(f"http://localhost/page/{i}")
        await db.update_job(job_id, "completed", {"meta": {"title": f"Page {i}"}, "screenshot": "X" * 10000})
    first = await db.get_jobs(page_size=20)
    last = await db.get_jobs(page=3, page_size=20)
    assert len(first["jobs"]) == 20 and len(last["jobs"]) == 16
    assert first["total"] == 56 and first["counts"]["completed"] == 56
    assert "data" not in first["jobs"][0] and "screenshot" not in json.dumps(first)
    assert (await db.get_jobs(q="page/0"))["jobs"][0]["url"].endswith("/0")
    assert (await db.get_jobs(q="Page 55"))["jobs"][0]["title"] == "Page 55"
    assert (await db.get_jobs(status="failed"))["total"] == 0
    assert (await db.get_jobs(q="%"))["total"] == 0
