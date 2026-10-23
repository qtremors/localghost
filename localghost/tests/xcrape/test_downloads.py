import base64
import io
import zipfile

import httpx
import pytest
from fastapi import HTTPException

from backend.modules.xcrape import downloads

from .conftest import PNG


async def test_preview_supports_images_larger_than_download_limit(monkeypatch):
    content = (
        b'<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><!--' + b"x" * (5 * 1024 * 1024) + b"--></svg>"
    )
    monkeypatch.setattr(
        downloads,
        "client",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, content=content, headers={"content-type": "image/svg+xml"})
            )
        ),
    )
    images = [{"src": "http://localhost/large.svg"}]
    preview = await downloads.image_response(images, 0, preview=True)
    assert b"".join([part async for part in preview.body_iterator]) == content
    assert "sandbox" in preview.headers["content-security-policy"]
    with pytest.raises(HTTPException) as rejected:
        await downloads.image_response(images, 0)
    assert rejected.value.status_code == 413
    from dataclasses import replace

    monkeypatch.setattr(downloads, "settings", replace(downloads.settings, preview_bytes=1024))
    with pytest.raises(HTTPException) as bounded:
        await downloads.image_response(images, 0, preview=True)
    assert bounded.value.status_code == 413


async def test_image_download_is_bounded_and_closes_oversized_stream():
    consumed = []

    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):
            for _ in range(100):
                consumed.append(True)
                yield b"x" * 1024

    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, headers={"content-type": "image/png"}, stream=Body())
        )
    ) as client:
        with pytest.raises(HTTPException) as error:
            await downloads.fetch_image(client, "http://localhost/image", 2048)
    assert error.value.status_code == 413
    assert len(consumed) < 100


@pytest.mark.parametrize("mime", ["text/html", "application/json", "image/png/../../bad"])
async def test_non_image_types_are_rejected(mime):
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"bad", headers={"content-type": mime}))
    ) as client:
        with pytest.raises(HTTPException) as error:
            await downloads.fetch_image(client, "http://localhost/image", 100)
    assert error.value.status_code == 502


async def test_embedded_images_and_stream_cleanup():
    async with httpx.AsyncClient() as client:
        image = await downloads.fetch_image(client, "data:image/png;base64," + base64.b64encode(PNG).decode(), 1000)
    assert image.file.read() == PNG
    image.file.seek(0)
    response = downloads.file_response(image.file, image.content_type, "image.png")
    content = b"".join([part async for part in response.body_iterator])
    assert content == PNG and image.file.closed


async def test_archive_contains_images_and_explains_skipped_files(monkeypatch):
    def handler(request):
        if request.url.path == "/bad":
            return httpx.Response(404)
        return httpx.Response(200, content=PNG, headers={"content-type": "image/png"})

    monkeypatch.setattr(downloads, "client", lambda: httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    response = await downloads.archive_response([{"src": "http://localhost/good"}, {"src": "http://localhost/bad"}], 1)
    content = b"".join([part async for part in response.body_iterator])
    with zipfile.ZipFile(io.BytesIO(content)) as archive:
        assert archive.read("image_0.png") == PNG
        assert "Image 2" in archive.read("skipped.txt").decode()
    with pytest.raises(HTTPException) as error:
        await downloads.archive_response([{"src": "http://localhost/bad"}], 1)
    assert error.value.status_code == 502


async def test_archive_count_and_total_byte_limits(monkeypatch):
    with pytest.raises(HTTPException) as error:
        await downloads.archive_response([{}] * 51, 1)
    assert error.value.status_code == 413
    from dataclasses import replace

    monkeypatch.setattr(downloads, "settings", replace(downloads.settings, archive_bytes=len(PNG) + 1))
    monkeypatch.setattr(
        downloads,
        "client",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(
                lambda r: httpx.Response(200, content=PNG, headers={"content-type": "image/png"})
            )
        ),
    )
    with pytest.raises(HTTPException) as error:
        await downloads.archive_response([{"src": "http://localhost/a"}, {"src": "http://localhost/b"}], 1)
    assert error.value.status_code == 413
