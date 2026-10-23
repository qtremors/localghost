"""Attach independent capture resources to the host application's lifecycle."""

import asyncio
import logging
import sqlite3
from contextlib import asynccontextmanager
from types import SimpleNamespace

from . import db
from .jobs import JobManager
from .settings import load_settings

logger = logging.getLogger(__name__)


@asynccontextmanager
async def capture_lifespan(app):
    manager = None
    state = SimpleNamespace(jobs=None, downloads=asyncio.Semaphore(2), error=None)
    app.state.xcrape = state
    try:
        load_settings()
        await db.init_db()
        manager = JobManager()
        await manager.start()
        state.jobs = manager
    except ValueError as exc:
        state.error = f"Captures are unavailable: {exc} Fix the capture settings and restart Localghost."
        logger.warning("Capture setup failed: %s", exc)
    except (OSError, sqlite3.Error):
        state.error = "Capture history could not be opened. Check LOCALGHOST_CAPTURE_DB_PATH and restart Localghost."
        logger.exception("Capture storage could not be initialized")
    try:
        yield
    finally:
        if manager is not None:
            await manager.close()
