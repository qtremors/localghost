import csv
import io
import json

import pytest

from backend.main import app
from backend.modules.xcrape import db
from backend.modules.xcrape.jobs import QueueFull
from backend.modules.xcrape.router import csv_content

from .conftest import finished


@pytest.mark.parametrize(
    "payload",
    [
        {"url": "file:///etc/hosts"},
        {"url": "javascript:alert(1)"},
        {"url": "not a url"},
        {"url": "http://user:password@localhost"},
        {"url": "http://localhost", "selector": "a" * 501},
    ],
)
async def test_reject_invalid_capture_input(api, payload):
    response = await api.post("/api/xcrape/scrape", json=payload)
    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"][0] == "body"
    assert (await db.get_jobs())["total"] == 0


async def test_rescrape_keeps_selector_and_uses_shared_queue(api, monkeypatch):
    original = await db.create_job("http://localhost/article", ".lead")
    seen = []

    async def submit(url, selector):
        seen.append((url, selector))
        return 42

    monkeypatch.setattr(app.state.xcrape.jobs, "submit", submit)
    response = await api.post(f"/api/xcrape/jobs/{original}/rescrape")
    assert response.status_code == 202 and response.json()["job_id"] == 42
    assert seen == [("http://localhost/article", ".lead")]

    async def full(url, selector):
        raise QueueFull("Queue full")

    monkeypatch.setattr(app.state.xcrape.jobs, "submit", full)
    assert (await api.post("/api/xcrape/scrape", json={"url": "http://localhost"})).status_code == 429
    assert (await api.post(f"/api/xcrape/jobs/{original}/rescrape")).status_code == 429


async def test_errors_deletion_and_same_origin_writes(api):
    assert (await api.get("/api/xcrape/jobs/100000")).status_code == 404
    assert (await api.get("/api/xcrape/jobs?page=0")).status_code == 422
    assert (await api.get("/api/xcrape/jobs?status=made-up")).status_code == 422
    blocked = await api.post(
        "/api/xcrape/scrape", json={"url": "http://localhost"}, headers={"Origin": "http://elsewhere.test"}
    )
    assert blocked.status_code == 403
    job = await db.create_job("http://localhost")
    assert (await api.get(f"/api/xcrape/jobs/{job}/export")).status_code == 400
    assert (await api.get(f"/api/xcrape/jobs/{job}/export?format=html")).status_code == 422
    assert (await api.delete(f"/api/xcrape/jobs/{job}")).status_code == 200
    assert (await api.delete(f"/api/xcrape/jobs/{job}")).status_code == 404
    home = await api.get("/")
    assert home.status_code == 200 and "Captures" in home.text
    assert "script-src 'self'" in home.headers["content-security-policy"]
    assert home.headers["x-content-type-options"] == "nosniff"


async def test_unreadable_legacy_image_data_has_a_useful_error(api):
    job = await db.create_job("http://localhost")
    await db.update_job(job, "completed", {"images": ["old or corrupt data"]})
    result = await api.get(f"/api/xcrape/jobs/{job}/images/0")
    assert result.status_code == 400
    assert "capturing the page again" in result.json()["detail"]


@pytest.mark.parametrize("value", ["=1+1", "+SUM(A1:A2)", "-1+1", "@SUM(1)", "\t=1", "\r=1", "  =1"])
def test_csv_neutralizes_formulas_in_every_section(value):
    output = csv_content(
        {
            "meta": {"title": value},
            "tables": [[value]],
            "text": [value],
            "images": [{"width": value}],
            "screenshot": "omitted",
        }
    )
    rows = list(csv.reader(io.StringIO(output)))
    assert len(rows) == 5
    assert all(row[2] == "'" + value for row in rows[1:])
    assert "omitted" not in output


async def test_real_capture_http_error_exports_and_images(api, page_server):
    base, _ = page_server
    response = await api.post("/api/xcrape/scrape", json={"url": base + "/article", "selector": ".lead"})
    assert response.status_code == 202
    job = await finished(api, response.json()["job_id"])
    assert job["status"] == "completed", job
    data = json.loads(job["data"])
    assert data["meta"]["http_status"] == 200
    assert data["selector_results"][0]["text"].startswith("A few herbs")
    assert data["screenshot"] and data["lists"] and data["tables"]
    export = await api.get(f"/api/xcrape/jobs/{job['id']}/export")
    assert export.json() == data
    assert (await api.get(f"/api/xcrape/jobs/{job['id']}/export?format=csv")).status_code == 200
    image = await api.get(f"/api/xcrape/jobs/{job['id']}/images/0")
    assert image.status_code == 200 and image.headers["content-type"] == "image/png"
    preview = await api.get(f"/api/xcrape/jobs/{job['id']}/images/0/preview")
    assert preview.content == image.content
    assert preview.headers["content-disposition"].startswith("inline;")
    assert "sandbox" in preview.headers["content-security-policy"]
    assert (await api.get(f"/api/xcrape/jobs/{job['id']}/images/-1")).status_code == 404
    missing = await api.post("/api/xcrape/scrape", json={"url": base + "/missing"})
    failed = await finished(api, missing.json()["job_id"])
    saved_error = json.loads(failed["data"])
    assert failed["status"] == "failed" and saved_error["meta"]["http_status"] == 404
    assert saved_error["screenshot"] and "HTTP 404" in saved_error["error"]


async def test_capture_public_target_rules_are_independent_of_scanning(api, monkeypatch):
    seen = []

    async def submit(url, selector):
        seen.append((url, selector))
        return 42

    monkeypatch.setattr(app.state.xcrape.jobs, "submit", submit)
    url = "https://93.184.215.14/article"
    response = await api.post("/api/xcrape/scrape", json={"url": url})
    assert response.status_code == 202 and seen == [(url, None)]
    scan = await api.post("/api/scan", json={"target_url": url})
    assert scan.status_code == 422
    assert (await api.get("/api/history")).json()["total"] == 0


async def test_shared_host_origin_and_body_limits_apply_to_captures(api):
    for headers, status in [
        ({"Host": "public.example"}, 400),
        ({"Origin": "http://elsewhere.test"}, 403),
        ({"Sec-Fetch-Site": "cross-site"}, 403),
    ]:
        result = await api.post("/api/xcrape/scrape", json={"url": "http://localhost"}, headers=headers)
        assert result.status_code == status
    large = await api.post("/api/xcrape/scrape", content=b"x" * 65537)
    assert large.status_code == 413


async def test_legacy_endpoints_and_errors_remain_compatible(api, monkeypatch):
    job = await db.create_job("https://example.test/page", ".lead")
    await db.update_job(job, "completed", {"meta": {"title": "Saved"}, "text": ["kept"]})
    assert (await api.get("/api/jobs")).json() == (await api.get("/api/xcrape/jobs")).json()
    assert (await api.get(f"/api/jobs/{job}/export")).json()["text"] == ["kept"]
    assert (await api.get("/api/jobs/999999")).json() == {"error": "Capture not found."}
    assert (
        (await api.post("/api/scrape", json={"url": "file:///etc/hosts"}))
        .json()["error"]
        .startswith("Enter a complete")
    )

    async def submit(url, selector):
        return 100

    monkeypatch.setattr(app.state.xcrape.jobs, "submit", submit)
    assert (await api.post("/api/scrape", json={"url": "https://example.test"})).json()["job_id"] == 100
    assert (await api.post(f"/api/jobs/{job}/rescrape")).status_code == 202
    assert (await api.delete(f"/api/jobs/{job}")).status_code == 200
    blocked = await api.post(
        "/api/scrape", json={"url": "http://localhost"}, headers={"Origin": "http://elsewhere.test"}
    )
    assert blocked.status_code == 403 and blocked.json()["error"]
    oversized = await api.post("/api/scrape", content=b"x" * 65537)
    assert oversized.status_code == 413 and oversized.json()["error"]
