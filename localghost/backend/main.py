"""Localghost — FastAPI application entry point."""

import os
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.routers import scan, history, report
from backend.database.db import init_db

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("localghost")

# Localghost's own port — other scanners should exclude this
LOCALGHOST_PORT = 13666

# Resolve paths relative to this file
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
STATIC_DIR = os.path.join(FRONTEND_DIR, "static")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifecycle: initialize DB on startup."""
    logger.info("Initializing database...")
    await init_db()
    logger.info("Localghost is ready. 👻")
    yield
    logger.info("Localghost shutting down.")


app = FastAPI(
    title="Localghost",
    description="Localhost Pentesting & Benchmarking Toolkit",
    version="0.2.0",
    lifespan=lifespan,
)

# Register routers
app.include_router(scan.router)
app.include_router(history.router)
app.include_router(report.router)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def serve_index():
    """Serve the frontend dashboard."""
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "alive", "version": "0.2.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=LOCALGHOST_PORT, reload=True)
