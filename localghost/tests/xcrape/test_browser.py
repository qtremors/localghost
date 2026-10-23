import json
import time

import httpx
import pytest
from playwright.sync_api import expect, sync_playwright


@pytest.mark.parametrize("during_load", ["stay", "move_focus", "leave", "direct"])
def test_heading_focus_survives_template_loading(live_server, during_load):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        pending = []
        page.route("**/static/xcrape/view.html", lambda route: pending.append(route))
        if during_load != "direct":
            page.goto(live_server)
        with page.expect_request("**/static/xcrape/view.html"):
            if during_load == "direct":
                page.goto(live_server + "/#xcrape")
            else:
                page.locator('.primary-nav [data-view="xcrape"]').click()
        heading = page.locator("#xcrape-heading")
        if during_load == "direct":
            expect(heading).not_to_be_focused()
            expected_focus = page.evaluate("document.activeElement.id")
        else:
            expect(heading).to_be_focused()
            expected_focus = "xcrape-heading"
        if during_load == "move_focus":
            page.locator("#theme-toggle").focus()
            expected_focus = "theme-toggle"
        elif during_load == "leave":
            page.locator('.primary-nav [data-view="home"]').click()
            expected_focus = "projects-heading"
        pending.pop().continue_()
        expect(page.locator("#xc-captureForm")).to_be_attached()
        assert page.evaluate("document.activeElement.id") == expected_focus
        page.locator('.primary-nav [data-view="home"]').click()
        page.locator('.primary-nav [data-view="xcrape"]').click()
        expect(heading).to_be_focused()
        browser.close()


def wait_for_capture(base, job_id):
    for _ in range(300):
        job = httpx.get(f"{base}/api/xcrape/jobs/{job_id}", trust_env=False).json()["job"]
        if job["status"] in ("completed", "failed"):
            return job
        time.sleep(0.1)
    raise AssertionError("Capture did not finish")


def test_full_browser_flow_and_mobile_layout(live_server, page_server, tmp_path):
    target, _ = page_server
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(live_server + "/#xcrape")
        expect(page.get_by_text("Your first page starts here", exact=True)).to_be_visible()
        page.locator("#xc-pageUrl").fill(target + "/article")
        page.locator("#xc-advancedOptions summary").click()
        page.locator("#xc-pageSelector").fill(".lead")
        page.get_by_role("button", name="Capture page", exact=True).click()
        expect(page.locator("#xc-detailTabs")).to_be_visible(timeout=30000)
        expect(page.locator("#xc-detailTitle")).to_have_text("The kitchen garden")
        bounds = page.locator("#xc-detailDialog").bounding_box()
        assert abs(bounds["x"] - (1440 - bounds["width"]) / 2) < 2
        expect(page.locator(".screenshot-wrap img")).to_be_visible()
        page.locator("#xc-exportMenu summary").click()
        with page.expect_download() as export:
            page.locator("#xc-exportJson").click()
        assert export.value.suggested_filename.endswith(".json")
        for tab in ("Text", "Links", "Images", "Page details", "All data", "Overview"):
            page.get_by_role("tab", name=tab, exact=True).click()
            expect(page.locator("#xc-detailContent")).not_to_be_empty()
            if tab == "All data":
                assert page.locator("#xc-detailContent pre").get_attribute("tabindex") == "0"
        page.get_by_role("tab", name="Overview", exact=True).focus()
        page.keyboard.press("ArrowRight")
        expect(page.get_by_role("tab", name="Text", exact=True)).to_have_attribute("aria-selected", "true")
        expect(page.get_by_text("Selected content · 1 matches", exact=True)).to_be_visible()
        page.get_by_role("tab", name="Overview", exact=True).click()
        page.screenshot(path=str(tmp_path / "desktop-details.png"))
        for width in (768, 375, 320):
            page.set_viewport_size({"width": width, "height": 812})
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            assert page.locator(".detail-actions").evaluate("e => e.getBoundingClientRect().right <= innerWidth")
            for name in ("Text", "Images", "Page details", "All data"):
                page.get_by_role("tab", name=name, exact=True).click()
                assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
        page.locator("#xc-closeDetail").click()
        expect(page.locator("#xc-detailDialog")).not_to_be_visible()
        page.set_viewport_size({"width": 1440, "height": 1000})
        page.locator("#xc-searchInput").fill("no-such-page")
        expect(page.get_by_text("No pages found", exact=True)).to_be_visible()
        page.get_by_role("button", name="Clear filters", exact=True).click()
        expect(page.locator(".page-cell")).to_be_visible()
        page.locator(".page-cell").click()
        original_id = page.url.split("capture=")[-1]
        page.locator("#xc-againButton").click()
        page.wait_for_function("old => new URL(location.href).searchParams.get('capture') !== old", arg=original_id)
        expect(page.locator("#xc-detailTabs")).to_be_visible(timeout=30000)
        page.get_by_role("tab", name="Text", exact=True).click()
        expect(page.get_by_text("Selected content · 1 matches", exact=True)).to_be_visible()
        page.locator("#xc-closeDetail").click()
        page.locator('.primary-nav [data-view="home"]').click()
        expect(page.locator("#empty-state")).to_be_visible()
        page.locator('.primary-nav [data-view="xcrape"]').click()
        expect(page.locator("#xcrape-view")).to_be_visible()
        page.locator("#theme-toggle").click()
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        page.reload()
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        page.locator("#theme-toggle").click()
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        page.screenshot(path=str(tmp_path / "dark-library.png"))
        page.locator(".page-cell").first.click()
        expect(page.locator("#xc-detailTabs")).to_be_visible()
        page.screenshot(path=str(tmp_path / "dark-details.png"))
        page.locator("#xc-closeDetail").click()
        page.set_viewport_size({"width": 375, "height": 812})
        page.wait_for_function("() => matchMedia('(max-width: 768px)').matches")
        page.wait_for_function("() => document.getElementById('sidebar').getBoundingClientRect().right <= 0")
        expect(page.locator("#menu-toggle")).to_be_visible()
        page.screenshot(path=str(tmp_path / "mobile-library.png"))
        assert not errors
        browser.close()


def test_scraped_attributes_cannot_execute_in_dashboard(live_server, page_server):
    target, _ = page_server
    response = httpx.post(live_server + "/api/xcrape/scrape", json={"url": target + "/unsafe"}, trust_env=False)
    job_id = response.json()["job_id"]
    job = wait_for_capture(live_server, job_id)
    assert job["status"] == "completed", job
    assert json.loads(job["data"])["images"]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.goto(live_server + f"/?capture={job_id}#xcrape")
        page.get_by_role("tab", name="Images", exact=True).click()
        expect(page.locator(".image-card")).to_have_count(1)
        assert page.evaluate("window.__xssAlt === undefined && window.__xssDims === undefined")
        assert page.locator("#xc-detailContent [onload], #xc-detailContent [onerror]").count() == 0
        assert page.locator(".image-actions").inner_text().startswith("<img src=x onerror=")
        page.locator("#xc-closeDetail").click()
        page.get_by_role("button", name="Delete Attribute checks", exact=True).click()
        page.get_by_role("button", name="Keep it", exact=True).click()
        expect(page.locator(".page-cell")).to_be_visible()
        page.get_by_role("button", name="Delete Attribute checks", exact=True).click()
        page.get_by_role("button", name="Delete capture", exact=True).click()
        expect(page.get_by_text("Your first page starts here", exact=True)).to_be_visible()
        assert not errors
        browser.close()


def test_shortcuts_respect_navigation_and_validation_keeps_details(live_server):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page(viewport={"width": 375, "height": 812})
        page.goto(live_server + "/#xcrape")
        expect(page.locator("#xc-captureForm")).to_be_visible()
        page.locator("#menu-toggle").click()
        for key in ("n", "/"):
            page.keyboard.press(key)
            assert page.evaluate("document.getElementById('sidebar').contains(document.activeElement)")
        page.keyboard.press("Escape")
        page.keyboard.press("n")
        expect(page.locator("#xc-pageUrl")).to_be_focused()
        page.locator("#xc-pageUrl").fill("file:///audit.txt")
        page.locator("#xc-captureButton").click()
        expect(page.locator("#xc-formError")).to_contain_text("http")
        expect(page.locator("#xc-formError")).to_contain_text("https")
        page.locator("#xc-pageUrl").blur()
        page.keyboard.press("/")
        expect(page.locator("#xc-searchInput")).to_be_focused()
        browser.close()
