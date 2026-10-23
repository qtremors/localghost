"""Check the shared workspace at native desktop sizes, without browser zoom."""

from playwright.sync_api import expect, sync_playwright


def test_desktop_workspace_fits_and_long_content_remains_accessible(live_server):
    project = {
        "key": "http://localhost:3000",
        "name": "localhost:3000",
        "origin": "http://localhost:3000",
        "reports": 2,
        "latest": {
            "scan_id": "layout-report",
            "status": "partial",
            "confirmed": 2,
            "review": 6,
            "target": "http://localhost:3000",
            "timestamp": "2026-10-23T12:00:00Z",
        },
    }
    projects = {"projects": [project], "total_projects": 1, "total_reports": 2, "latest_timestamp": project["latest"]["timestamp"]}
    sizes = [(1024, 640), (1024, 768), (1280, 720), (1366, 768), (1440, 900), (1536, 864), (1920, 1080), (2560, 1440), (3440, 1440)]
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        errors = []
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.route("**/api/projects?*", lambda route: route.fulfill(json=projects))
        page.goto(live_server)
        expect(page.locator(".project-card")).to_have_count(1)
        for width, height in sizes:
            page.set_viewport_size({"width": width, "height": height})
            for view in ("home", "reports", "xcrape", "scan"):
                page.locator(".sidebar-new" if view == "scan" else f'.primary-nav [data-view="{view}"]').click()
                if view == "xcrape":
                    expect(page.locator("#xc-captureForm")).to_be_visible()
                    expect(page.locator("#xc-emptyTitle")).to_have_text("Your first page starts here")
                geometry = page.evaluate("""() => {
                    const main = document.getElementById('main-content');
                    const sidebar = document.getElementById('sidebar');
                    return {
                        horizontal: main.scrollWidth - main.clientWidth,
                        vertical: main.scrollHeight - main.clientHeight,
                        sidebar: sidebar.scrollHeight - sidebar.clientHeight,
                        document: document.documentElement.scrollWidth - innerWidth,
                    };
                }""")
                assert geometry["horizontal"] <= 1 and geometry["document"] <= 1, (width, height, view, geometry)
                assert geometry["sidebar"] <= 1, (width, height, view, geometry)
                if view != "scan" and height >= 720:
                    assert geometry["vertical"] <= 1, (width, height, view, geometry)
                elif view == "scan":
                    expect(page.locator("#scan-btn")).to_be_in_viewport()
                    page.locator("#custom-ports").scroll_into_view_if_needed()
                    expect(page.locator("#custom-ports")).to_be_in_viewport()
        # A longer collection should scroll naturally instead of being clipped.
        project["name"] = "a-long-project-name-" * 12
        projects["projects"] = [dict(project, key=f"project-{index}") for index in range(12)]
        projects["total_projects"] = 12
        page.set_viewport_size({"width": 1024, "height": 640})
        page.reload()
        page.locator('.primary-nav [data-view="home"]').click()
        expect(page.locator(".project-card")).to_have_count(12)
        page.locator(".project-card").last.scroll_into_view_if_needed()
        expect(page.locator(".project-card").last).to_be_in_viewport()
        assert page.locator("#main-content").evaluate("e => e.scrollWidth <= e.clientWidth + 1")
        assert not errors
        browser.close()


def test_oled_default_theme_preferences_and_storage_denial(live_server):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        page = browser.new_page()
        page.goto(live_server)
        expect(page.locator("html")).to_have_attribute("data-theme", "dark")
        assert page.locator("body").evaluate("e => getComputedStyle(e).backgroundColor") == "rgb(0, 0, 0)"
        assert page.locator('meta[name="theme-color"]').get_attribute("content") == "#000000"
        page.locator("#theme-toggle").click()
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        page.reload()
        expect(page.locator("html")).to_have_attribute("data-theme", "light")
        assert page.locator('meta[name="theme-color"]').get_attribute("content") == "#ffffff"
        restricted = browser.new_page()
        errors = []
        restricted.on("pageerror", lambda error: errors.append(str(error)))
        restricted.add_init_script("Object.defineProperty(window, 'localStorage', {get() { throw new DOMException('Storage denied'); }});")
        restricted.goto(live_server)
        expect(restricted.locator("html")).to_have_attribute("data-theme", "dark")
        restricted.locator("#theme-toggle").click()
        expect(restricted.locator("html")).to_have_attribute("data-theme", "light")
        assert not errors
        browser.close()
