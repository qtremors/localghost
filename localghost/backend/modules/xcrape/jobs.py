"""A bounded queue with a separate, time-limited process for each capture."""

import asyncio
import json
import logging
import os
import signal
import subprocess
import sys
import threading

from . import db
from .settings import PROJECT_DIR, settings

logger = logging.getLogger(__name__)


class QueueFull(Exception):
    pass


def stop_process(process: subprocess.Popen) -> None:
    if os.name == "nt" and process.poll() is not None:
        return
    try:
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
        else:
            os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        pass
    finally:
        if process.poll() is None:
            process.kill()


class JobManager:
    def __init__(self, workers: int | None = None, capacity: int | None = None):
        self.queue = asyncio.Queue(maxsize=settings.queue_size if capacity is None else capacity)
        self.worker_count = settings.workers if workers is None else workers
        self.tasks = []
        self.active = {}
        self.process_lock = threading.Lock()
        self.submit_lock = asyncio.Lock()
        self.closing = False
        self.outstanding = set()
        self.cancelled = set()

    async def start(self) -> None:
        await db.recover_interrupted()
        self.tasks = [asyncio.create_task(self._worker(), name=f"capture-{i}") for i in range(self.worker_count)]

    async def submit(self, url: str, selector: str | None = None) -> int:
        async with self.submit_lock:
            if self.closing or self.queue.full():
                raise QueueFull("The queue is full. Wait for a capture to finish and try again.")
            job_id = await db.create_job(url, selector)
            with self.process_lock:
                self.outstanding.add(job_id)
            self.queue.put_nowait((job_id, url, selector))
            return job_id

    def _execute(self, job_id: int, url: str, selector: str | None) -> dict:
        env = {
            **os.environ,
            "PYTHONPATH": str(PROJECT_DIR) + os.pathsep + os.environ.get("PYTHONPATH", ""),
        }
        with self.process_lock:
            if self.closing or job_id in self.cancelled:
                raise RuntimeError("Capture interrupted.")
            process = subprocess.Popen(
                [sys.executable, "-m", "backend.modules.xcrape.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=os.name != "nt",
                creationflags=(subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW)
                if os.name == "nt"
                else 0,
            )
            self.active[job_id] = process
        try:
            try:
                output, error = process.communicate(
                    json.dumps({"url": url, "selector": selector}).encode(),
                    timeout=settings.scrape_timeout,
                )
            except subprocess.TimeoutExpired as exc:
                stop_process(process)
                process.communicate()
                raise TimeoutError(f"The page took longer than {settings.scrape_timeout} seconds. Try again.") from exc
            if process.returncode:
                logger.warning("Capture %s process failed: %s", job_id, error.decode(errors="replace")[:1000])
                raise RuntimeError("The capture stopped unexpectedly. Try again.")
            if error:
                logger.warning("Capture %s diagnostics: %s", job_id, error.decode(errors="replace")[:3000])
            return json.loads(output)
        finally:
            stop_process(process)
            process.wait()
            with self.process_lock:
                self.active.pop(job_id, None)

    async def _worker(self) -> None:
        while True:
            job_id, url, selector = await self.queue.get()
            try:
                if not await db.get_job(job_id):
                    continue
                await db.update_job(job_id, "running")
                result = await asyncio.to_thread(self._execute, job_id, url, selector)
                if not self.closing:
                    await db.update_job(job_id, "failed" if result.get("error") else "completed", result)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not self.closing and await db.get_job(job_id):
                    logger.exception("Capture %s failed", job_id)
                    await db.update_job(job_id, "failed", {"error": str(exc), "error_type": type(exc).__name__})
            finally:
                with self.process_lock:
                    self.outstanding.discard(job_id)
                    self.cancelled.discard(job_id)
                self.queue.task_done()

    async def cancel(self, job_id: int) -> None:
        with self.process_lock:
            if job_id in self.outstanding:
                self.cancelled.add(job_id)
            process = self.active.get(job_id)
        await db.delete_job(job_id)
        if process:
            await asyncio.to_thread(stop_process, process)

    async def close(self) -> None:
        async with self.submit_lock:
            with self.process_lock:
                self.closing = True
                processes = list(self.active.values())
        await asyncio.gather(*(asyncio.to_thread(stop_process, p) for p in processes))
        await asyncio.gather(*(asyncio.to_thread(p.wait, timeout=5) for p in processes))
        for task in self.tasks:
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await db.recover_interrupted()
