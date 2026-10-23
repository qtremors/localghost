import asyncio
import json
import subprocess
import sys
import threading
import time
from dataclasses import replace

import pytest

from backend.modules.xcrape import db, jobs
from backend.modules.xcrape.jobs import JobManager, QueueFull


async def test_concurrency_queue_backpressure_and_deleted_waiting_job(database, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    calls = []

    def execute(self, job_id, url, selector):
        calls.append(job_id)
        entered.set()
        assert release.wait(5)
        return {"meta": {"title": "Done"}}

    monkeypatch.setattr(JobManager, "_execute", execute)
    manager = JobManager(workers=1, capacity=1)
    await manager.start()
    try:
        first = await manager.submit("http://localhost/first")
        assert await asyncio.to_thread(entered.wait, 2)
        second = await manager.submit("http://localhost/second")
        with pytest.raises(QueueFull):
            await manager.submit("http://localhost/third")
        assert (await db.get_jobs())["total"] == 2
        await manager.cancel(second)
        release.set()
        await asyncio.wait_for(manager.queue.join(), 3)
        assert calls == [first]
        assert (await db.get_job(first))["status"] == "completed"
        assert await db.get_job(second) is None
    finally:
        release.set()
        await manager.close()
    with pytest.raises(QueueFull):
        await manager.submit("http://localhost/closed")


async def test_worker_process_timeout_is_enforced_and_reaped(database, monkeypatch):
    original = subprocess.Popen
    processes = []

    def sleeper(*args, **kwargs):
        process = original([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(jobs.subprocess, "Popen", sleeper)
    monkeypatch.setattr(jobs, "settings", replace(jobs.settings, scrape_timeout=0.1))
    manager = JobManager()
    start = time.monotonic()
    with pytest.raises(TimeoutError):
        await asyncio.to_thread(manager._execute, 1, "http://localhost", None)
    # Windows process-tree cleanup may spend up to 5 seconds in taskkill.
    assert time.monotonic() - start < 8
    assert processes[0].poll() is not None and not manager.active


async def test_shutdown_stops_active_process_and_marks_unfinished_jobs(database, page_server):
    base, visits = page_server
    manager = JobManager(workers=1, capacity=2)
    await manager.start()
    first = await manager.submit(base + "/slow")
    second = await manager.submit(base + "/article")
    before = visits.get("/slow", 0)
    for _ in range(200):
        if visits.get("/slow", 0) > before:
            break
        await asyncio.sleep(0.02)
    processes = list(manager.active.values())
    assert processes
    await manager.close()
    assert all(process.poll() is not None for process in processes)
    assert (await db.get_job(first))["status"] == "failed"
    assert (await db.get_job(second))["status"] == "failed"
    assert json.loads((await db.get_job(first))["data"])["error_type"] == "Interrupted"


async def test_deleted_job_cannot_spawn_during_start_race(database, monkeypatch):
    manager = JobManager()
    job_id = await manager.submit("http://localhost")
    await manager.cancel(job_id)

    def forbidden(*args, **kwargs):
        pytest.fail("Deleted job spawned a process")

    monkeypatch.setattr(jobs.subprocess, "Popen", forbidden)
    with pytest.raises(RuntimeError):
        manager._execute(job_id, "http://localhost", None)
