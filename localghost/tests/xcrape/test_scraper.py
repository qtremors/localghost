import pytest

from backend.modules.xcrape.scraper import _extract_social_links, extract_page, scrape_page

from .conftest import ARTICLE


def test_document_order_effective_base_safe_urls_and_unicode_size():
    html = ARTICLE.replace("<head>", '<head><base href="/assets/">').replace(
        "</main>",
        '<a href="JaVaScRiPt:alert(1)">No</a><a href="mailto:test@example.com">Mail</a><p>雪</p></main>',
    )
    result = extract_page(html, "http://localhost/nested/article", ".lead")
    assert result["links"][0]["url"] == "http://localhost/assets/child"
    assert result["images"][0]["src"] == "http://localhost/assets/image.png"
    assert len(result["links"]) == 1
    assert [heading["level"] for heading in result["headings"]] == [2, 1]
    assert result["stats"]["html_size_bytes"] == len(html.encode())
    assert result["structured_data"][0]["data"]["@type"] == "Article"
    assert result["selector_results"]


async def test_redirects_and_dynamic_content(page_server):
    base, visits = page_server
    before = visits.get("/redirect", 0)
    result = await scrape_page(base + "/redirect")
    assert result["meta"]["final_url"] == base + "/nested/article"
    assert result["links"][0]["url"] == base + "/nested/child"
    assert result["images"][0]["src"] == base + "/nested/image.png"
    assert visits["/redirect"] == before + 1
    dynamic = await scrape_page(base + "/dynamic")
    assert dynamic["text"] == ["This content arrived after the page opened."]


@pytest.mark.parametrize("selector", ["[invalid", "x" * 501])
async def test_invalid_selector_fails_before_navigation(selector):
    with pytest.raises(ValueError):
        await scrape_page("http://localhost:1", selector)


def test_social_domain_matching_does_not_strip_arbitrary_prefixes():
    links = [{"url": "http://wgithub.com/no"}, {"url": "http://www.github.com/yes"}]
    assert _extract_social_links(links)[0]["url"] == "http://www.github.com/yes"


def test_text_mentions_are_not_software_evidence():
    assert extract_page("<p>I react to a ghost story.</p>", "http://localhost")["technologies"] == []
