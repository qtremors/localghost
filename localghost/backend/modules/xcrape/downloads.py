"""Download images with strict byte, time and archive limits."""

import asyncio
import base64
import binascii
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from typing import BinaryIO
from urllib.parse import urlparse

import httpx
from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from .settings import settings

IMAGE_TYPES = {
    "image/jpeg": "jpg",
    "image/png": "png",
    "image/webp": "webp",
    "image/gif": "gif",
    "image/avif": "avif",
    "image/svg+xml": "svg",
    "image/bmp": "bmp",
    "image/x-icon": "ico",
    "image/vnd.microsoft.icon": "ico",
}


@dataclass
class Image:
    file: BinaryIO
    size: int
    content_type: str
    extension: str


def spool():
    return tempfile.SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b")


async def fetch_image(client: httpx.AsyncClient, url: str, limit: int) -> Image:
    file = spool()
    size = 0
    try:
        async with asyncio.timeout(15):
            if url.startswith("data:"):
                if len(url) > limit * 4 // 3 + 200:
                    raise HTTPException(413, "This image is too large to download.")
                header, encoded = url.split(",", 1)
                content_type = header[5:].split(";", 1)[0].lower()
                if content_type not in IMAGE_TYPES or not header.endswith(";base64"):
                    raise HTTPException(400, "This image format is not supported.")
                body = base64.b64decode(encoded, validate=True)
                size = len(body)
                if size > limit:
                    raise HTTPException(413, "This image is too large to download.")
                file.write(body)
            else:
                if urlparse(url).scheme.lower() not in ("http", "https"):
                    raise HTTPException(400, "This image address is not supported.")
                async with client.stream("GET", url) as response:
                    response.raise_for_status()
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].lower().strip()
                    if content_type not in IMAGE_TYPES:
                        raise HTTPException(502, "The address did not return a supported image.")
                    if int(response.headers.get("content-length", "0")) > limit:
                        raise HTTPException(413, "This image is too large to download.")
                    async for chunk in response.aiter_bytes(64 * 1024):
                        size += len(chunk)
                        if size > limit:
                            raise HTTPException(413, "This image is too large to download.")
                        file.write(chunk)
            if not size:
                raise HTTPException(502, "The image is empty.")
        file.seek(0)
        return Image(file, size, content_type, IMAGE_TYPES[content_type])
    except HTTPException:
        file.close()
        raise
    except (httpx.HTTPError, TimeoutError, ValueError, binascii.Error) as exc:
        file.close()
        raise HTTPException(502, "The image could not be downloaded. Try again.") from exc
    except BaseException:
        file.close()
        raise


def file_response(file, media_type: str, filename: str, *, preview: bool = False) -> StreamingResponse:
    def chunks():
        try:
            while chunk := file.read(64 * 1024):
                yield chunk
        finally:
            file.close()

    return StreamingResponse(
        chunks(),
        media_type=media_type,
        headers={
            "Content-Disposition": f'{"inline" if preview else "attachment"}; filename="{filename}"',
            "Content-Security-Policy": "sandbox; default-src 'none'",
        },
        background=BackgroundTask(file.close),
    )


def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(follow_redirects=True, max_redirects=5, timeout=httpx.Timeout(10, connect=5))


async def image_response(images: list, index: int, *, preview: bool = False):
    if not 0 <= index < len(images):
        raise HTTPException(404, "Image not found.")
    async with client() as http:
        image = await fetch_image(
            http, images[index].get("src", ""), settings.preview_bytes if preview else settings.image_bytes
        )
    return file_response(image.file, image.content_type, f"image_{index}.{image.extension}", preview=preview)


async def archive_response(images: list, job_id: int):
    if not images:
        raise HTTPException(400, "This capture has no images.")
    if len(images) > settings.archive_images:
        raise HTTPException(
            413,
            f"Download up to {settings.archive_images} images together. This page has more; download them individually.",
        )
    archive = spool()
    total, saved, skipped = 0, 0, []
    try:
        async with asyncio.timeout(30), client() as http:
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as zf:
                for index, item in enumerate(images):
                    try:
                        image = await fetch_image(
                            http,
                            item.get("src", ""),
                            min(settings.image_bytes, settings.archive_bytes - total),
                        )
                    except HTTPException as exc:
                        if exc.status_code == 413:
                            if settings.archive_bytes - total < settings.image_bytes:
                                raise HTTPException(
                                    413,
                                    "These images exceed the archive size limit. Download them individually.",
                                ) from exc
                            raise
                        skipped.append(f"Image {index + 1}: {exc.detail}")
                        continue
                    try:
                        total += image.size
                        with zf.open(f"image_{index}.{image.extension}", "w") as target:
                            # Each copy is capped at 5 MB; keep file ownership in this task.
                            shutil.copyfileobj(image.file, target, 64 * 1024)
                        saved += 1
                    finally:
                        image.file.close()
                if skipped:
                    zf.writestr("skipped.txt", "\n".join(skipped))
        if not saved:
            raise HTTPException(502, "None of this page's images could be downloaded.")
        archive.seek(0)
        return file_response(archive, "application/zip", f"xcrape_{job_id}_images.zip")
    except TimeoutError as exc:
        archive.close()
        raise HTTPException(504, "The image download took too long. Try downloading images individually.") from exc
    except BaseException:
        archive.close()
        raise
