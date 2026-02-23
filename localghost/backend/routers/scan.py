"""Blocking and streaming scan APIs sharing the same orchestration service."""

import asyncio
import json
import logging
from contextlib import suppress

from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse

from backend.models.scan import ScanRequest, ScanResponse
from backend.services.admission import workload_lock
from backend.services.scanner import execute_scan

router = APIRouter(prefix="/api", tags=["scan"])
logger = logging.getLogger(__name__)
# One scan at a time per process prevents overlapping benchmark workloads.
_scan_lock = workload_lock


class _ScanStreamResponse(StreamingResponse):
    """Release admission even if disconnect happens before iteration starts."""

    def __init__(self, *args, release, **kwargs):
        super().__init__(*args, **kwargs)
        self.release = release

    async def __call__(self, scope, receive, send):
        try:
            await super().__call__(scope, receive, send)
        finally:
            self.release()


def reserve_scan():
    if _scan_lock.locked():
        raise HTTPException(status_code=429, detail="A scan is already running. Wait for it to finish or cancel it.", headers={"Retry-After": "5"})


@router.post("/scan", response_model=ScanResponse)
async def perform_scan(request: ScanRequest):
    """Execute a scan and return the full report."""
    reserve_scan()
    async with _scan_lock:
        try:
            return await execute_scan(request)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:
            logger.exception("Scan failed")
            raise HTTPException(status_code=500, detail="Scan failed. See the server logs for details.") from exc


@router.post("/scan/stream")
async def stream_scan(request: ScanRequest):
    """Stream newline-delimited JSON progress; disconnecting cancels the scan."""
    reserve_scan()
    await _scan_lock.acquire()
    released = False

    def release():
        nonlocal released
        if not released:
            released = True
            _scan_lock.release()

    async def events():
        queue = asyncio.Queue()

        async def run():
            try:
                result = await execute_scan(request, queue.put)
                await queue.put({"type": "complete", "result": result.model_dump()})
            except ValueError as exc:
                await queue.put({"type": "error", "message": str(exc)})
            except Exception:
                logger.exception("Streaming scan failed")
                await queue.put({"type": "error", "message": "Scan failed. See the server logs for details."})

        task = asyncio.create_task(run())
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=10)
                except TimeoutError:
                    yield json.dumps({"type": "heartbeat"}) + "\n"
                    continue
                yield json.dumps(event) + "\n"
                if event["type"] in ("complete", "error"):
                    break
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
            release()

    return _ScanStreamResponse(events(), release=release, media_type="application/x-ndjson", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
