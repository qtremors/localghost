"""Localghost — FastAPI application entry point."""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.database.db import init_db
from backend.middleware import LocalAccessMiddleware
from backend.routers import history, projects, rechecks, report, scan

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
    logger.info("Localghost is ready.")
    yield
    logger.info("Localghost shutting down.")


app = FastAPI(
    title="Localghost",
    description="Check running web apps, inspect findings, and verify fixes.",
    version="0.0.8",
    lifespan=lifespan,
)
app.add_middleware(LocalAccessMiddleware)


@app.exception_handler(RequestValidationError)
async def private_validation_error(request, exc):
    # FastAPI's default error includes raw input, potentially the whole session.
    errors = [{key: error[key] for key in ('type', 'loc', 'msg') if key in error} for error in exc.errors()]
    return JSONResponse(status_code=422, content={'detail': errors})

# Register routers
app.include_router(scan.router)
app.include_router(history.router)
app.include_router(report.router)
app.include_router(projects.router)
app.include_router(rechecks.router)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def serve_index():
    """Serve the frontend dashboard."""
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


@app.get("/health")
async def health_check():
    """Simple health check endpoint."""
    return {"status": "alive", "version": "0.0.8"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=LOCALGHOST_PORT, reload=True)
