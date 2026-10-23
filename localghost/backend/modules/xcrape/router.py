"""Capture API. Target rules and results are independent of scan findings."""

import csv
import io
import json
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field, HttpUrl, field_validator
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import db, downloads
from .jobs import QueueFull
from .settings import settings


class CaptureRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()

        async def legacy_errors(request):
            legacy = request.url.path == "/api/scrape" or request.url.path.startswith("/api/jobs")
            try:
                return await handler(request)
            except RequestValidationError as exc:
                if not legacy:
                    raise
                field = str(exc.errors()[0]["loc"][-1])
                message = {
                    "url": "Enter a complete http:// or https:// address (up to 2,048 characters).",
                    "selector": "Keep the selector under 500 characters.",
                    "format": "Choose JSON or CSV for your export.",
                }.get(field, "Check the request and try again.")
                return JSONResponse({"error": message}, status_code=422)
            except StarletteHTTPException as exc:
                if not legacy:
                    raise
                return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code, headers=exc.headers)

        return legacy_errors


async def require_available(request: Request):
    state = getattr(request.app.state, "xcrape", None)
    if state is None or state.jobs is None:
        raise HTTPException(503, (state.error if state else None) or "Captures have not started. Restart Localghost.")


router = APIRouter(tags=["Captures"], route_class=CaptureRoute, dependencies=[Depends(require_available)])


class ScrapeRequest(BaseModel):
    url: HttpUrl = Field(max_length=2048)
    selector: str | None = Field(default=None, max_length=settings.selector_limit)

    @field_validator("selector", mode="before")
    @classmethod
    def trim_selector(cls, value):
        return value.strip() or None if isinstance(value, str) else value

    @field_validator("url")
    @classmethod
    def no_credentials(cls, value):
        if value.username or value.password:
            raise ValueError("Use an address without a username or password.")
        return value


async def submit(request: Request, url: str, selector: str | None):
    try:
        job_id = await request.app.state.xcrape.jobs.submit(url, selector)
    except QueueFull as exc:
        raise HTTPException(429, str(exc), headers={"Retry-After": "5"}) from exc
    return {"message": "Capture queued", "job_id": job_id}


@router.post("/scrape", status_code=202)
async def trigger_scrape(req: ScrapeRequest, request: Request):
    return await submit(request, str(req.url), req.selector)


@router.get("/jobs")
async def list_jobs(
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=50)] = 20,
    q: Annotated[str, Query(max_length=200)] = "",
    status: Literal["pending", "running", "completed", "failed"] | None = None,
):
    return await db.get_jobs(page, page_size, q.strip(), status)


async def require_job(job_id: int) -> dict:
    job = await db.get_job(job_id)
    if not job:
        raise HTTPException(404, "Capture not found.")
    return job


async def require_data(job_id: int) -> dict:
    job = await require_job(job_id)
    try:
        data = json.loads(job["data"]) if job["data"] else None
    except (TypeError, json.JSONDecodeError):
        data = None
    if not isinstance(data, dict):
        raise HTTPException(400, "No saved content is available for this capture.")
    return data


def require_images(data: dict) -> list:
    images = data.get("images", [])
    if not isinstance(images, list) or any(
        not isinstance(image, dict) or not isinstance(image.get("src"), str) for image in images
    ):
        raise HTTPException(400, "The saved image information could not be read. Try capturing the page again.")
    return images


@router.get("/jobs/{job_id}")
async def get_job_detail(job_id: int):
    return {"job": await require_job(job_id)}


@router.delete("/jobs/{job_id}")
async def remove_job(job_id: int, request: Request):
    await require_job(job_id)
    await request.app.state.xcrape.jobs.cancel(job_id)
    return {"message": "Capture deleted"}


@router.post("/jobs/{job_id}/rescrape", status_code=202)
async def rescrape_job(job_id: int, request: Request):
    job = await require_job(job_id)
    # Validate legacy URLs too; older versions allowed arbitrary schemes.
    try:
        req = ScrapeRequest(url=job["url"], selector=job.get("selector"))
    except ValueError as exc:
        raise HTTPException(
            400,
            "This saved address is not supported. Start a new capture with an http:// or https:// address.",
        ) from exc
    return await submit(request, str(req.url), req.selector)


@router.get("/jobs/{job_id}/images/download-all")
async def download_all_images(job_id: int, request: Request):
    data = await require_data(job_id)
    async with request.app.state.xcrape.downloads:
        return await downloads.archive_response(require_images(data), job_id)


@router.get("/jobs/{job_id}/images/{image_index}")
async def download_single_image(job_id: int, image_index: int, request: Request):
    data = await require_data(job_id)
    async with request.app.state.xcrape.downloads:
        return await downloads.image_response(require_images(data), image_index)


@router.get("/jobs/{job_id}/images/{image_index}/preview")
async def preview_image(job_id: int, image_index: int, request: Request):
    data = await require_data(job_id)
    async with request.app.state.xcrape.downloads:
        return await downloads.image_response(require_images(data), image_index, preview=True)


def csv_cell(value):
    if isinstance(value, str) and (
        value.startswith(("\t", "\r", "\n")) or value.lstrip().startswith(("=", "+", "-", "@"))
    ):
        return "'" + value
    return value


def csv_content(data: dict) -> str:
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["Section", "Field", "Value"])

    def flatten(value, section, path=""):
        if isinstance(value, dict):
            for key, child in value.items():
                flatten(child, section, f"{path}.{key}" if path else str(key))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                flatten(child, section, f"{path}[{index}]")
        else:
            writer.writerow([csv_cell(section), csv_cell(path), csv_cell(value)])

    for section, value in data.items():
        if section != "screenshot":
            flatten(value, section)
    return output.getvalue()


@router.get("/jobs/{job_id}/export")
async def export_job(job_id: int, format: Literal["json", "csv"] = "json"):
    data = await require_data(job_id)
    content = csv_content(data) if format == "csv" else json.dumps(data, indent=2, ensure_ascii=False)
    return Response(
        content,
        media_type="text/csv" if format == "csv" else "application/json",
        headers={"Content-Disposition": f'attachment; filename="xcrape_{job_id}.{format}"'},
    )
