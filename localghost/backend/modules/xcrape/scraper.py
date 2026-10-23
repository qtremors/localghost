import base64
import json
import re
import time
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
from playwright.async_api import TimeoutError as BrowserTimeout
from playwright.async_api import async_playwright
from soupsieve import SelectorSyntaxError
from soupsieve import compile as compile_selector

from backend.utils.browser import launch_chromium

from .settings import settings

# Known social media domains
SOCIAL_DOMAINS = {
    "twitter.com": "Twitter/X",
    "x.com": "Twitter/X",
    "facebook.com": "Facebook",
    "fb.com": "Facebook",
    "instagram.com": "Instagram",
    "linkedin.com": "LinkedIn",
    "github.com": "GitHub",
    "youtube.com": "YouTube",
    "youtu.be": "YouTube",
    "tiktok.com": "TikTok",
    "reddit.com": "Reddit",
    "discord.gg": "Discord",
    "discord.com": "Discord",
    "pinterest.com": "Pinterest",
    "mastodon.social": "Mastodon",
    "threads.net": "Threads",
    "twitch.tv": "Twitch",
    "medium.com": "Medium",
}

# Technology detection patterns
TECH_PATTERNS = {
    "meta_generator": {},  # filled dynamically from <meta name="generator">
    "scripts": {
        "react": ["react", "react-dom", "reactjs"],
        "vue": ["vue.js", "vuejs", "vue.min"],
        "angular": ["angular", "ng-"],
        "svelte": ["svelte"],
        "next.js": ["_next/", "__next"],
        "nuxt.js": ["_nuxt/", "__nuxt"],
        "jquery": ["jquery"],
        "bootstrap": ["bootstrap"],
        "tailwind": ["tailwindcss", "tailwind"],
        "webpack": ["webpack", "__webpack"],
        "vite": ["vite", "@vite"],
        "gatsby": ["gatsby"],
        "remix": ["remix"],
        "astro": ["astro"],
    },
    "headers": {
        "wordpress": ["wp-content", "wp-includes", "wordpress"],
        "shopify": ["shopify", "cdn.shopify"],
        "wix": ["wix.com", "parastorage"],
        "squarespace": ["squarespace"],
        "drupal": ["drupal"],
        "ghost": ["ghost"],
    },
}


def _detect_technologies(soup: BeautifulSoup, html: str, runtime: list[str] | None = None) -> list[dict]:
    """Detect technologies used on the page."""
    detected = []
    seen = set()
    html_lower = " ".join(str(tag) for tag in soup.find_all(["script", "link"])).lower()
    for name in runtime or []:
        detected.append({"name": name, "source": "browser runtime"})
        seen.add(name.lower())

    # Meta generator tag
    gen = soup.find("meta", attrs={"name": "generator"})
    if gen and gen.get("content"):
        val = gen["content"].strip()
        if val and val.lower() not in seen:
            detected.append({"name": val, "source": "meta generator"})
            seen.add(val.lower())

    # Script-based detection
    for tech, keywords in TECH_PATTERNS["scripts"].items():
        if tech.lower() in seen:
            continue
        for kw in keywords:
            if kw in html_lower:
                detected.append({"name": tech, "source": "script/markup"})
                seen.add(tech.lower())
                break

    # HTML pattern detection
    for tech, keywords in TECH_PATTERNS["headers"].items():
        if tech.lower() in seen:
            continue
        for kw in keywords:
            if kw in html_lower:
                detected.append({"name": tech, "source": "markup pattern"})
                seen.add(tech.lower())
                break

    # Common framework indicators
    if soup.find("div", id="__next"):
        if "next.js" not in seen:
            detected.append({"name": "Next.js", "source": "DOM element"})
    if soup.find("div", id="__nuxt"):
        if "nuxt.js" not in seen:
            detected.append({"name": "Nuxt.js", "source": "DOM element"})
    if soup.find("div", id="app") and any("vue" in str(s) for s in soup.find_all("script")):
        if "vue" not in seen:
            detected.append({"name": "Vue.js", "source": "DOM element"})

    return detected


def _extract_social_links(links: list[dict]) -> list[dict]:
    """Identify social media links from the scraped links."""
    seen_platforms = {}
    for link in links:
        try:
            parsed = urlparse(link["url"])
            domain = (parsed.hostname or "").lower().removeprefix("www.")
            for social_domain, platform in SOCIAL_DOMAINS.items():
                if domain == social_domain or domain.endswith("." + social_domain):
                    if platform not in seen_platforms:
                        seen_platforms[platform] = {
                            "platform": platform,
                            "url": link["url"],
                            "text": link.get("text", ""),
                        }
                    break
        except Exception:
            continue
    return list(seen_platforms.values())


def _extract_structured_data(soup: BeautifulSoup) -> list[dict]:
    """Extract JSON-LD and other structured data from the page."""
    structured = []

    # JSON-LD
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string)
            if isinstance(data, list):
                for item in data:
                    structured.append({"format": "JSON-LD", "data": item})
            else:
                structured.append({"format": "JSON-LD", "data": data})
        except (json.JSONDecodeError, TypeError):
            continue

    # OpenGraph (collected as a group)
    og_tags = {}
    for tag in soup.find_all("meta", property=re.compile(r"^og:")):
        prop = tag.get("property", "")
        content = tag.get("content", "")
        if prop and content:
            og_tags[prop] = content
    if og_tags:
        structured.append({"format": "OpenGraph", "data": og_tags})

    # Twitter Cards
    tc_tags = {}
    for tag in soup.find_all("meta", attrs={"name": re.compile(r"^twitter:")}):
        name = tag.get("name", "")
        content = tag.get("content", "")
        if name and content:
            tc_tags[name] = content
    if tc_tags:
        structured.append({"format": "Twitter Card", "data": tc_tags})

    return structured


def web_url(base: str, value: str | None) -> str | None:
    if not value:
        return None
    try:
        result = urljoin(base, value.strip())
        parsed = urlparse(result)
        return result if parsed.scheme.lower() in ("http", "https") and parsed.hostname else None
    except ValueError:
        return None


def extract_page(
    content: str,
    final_url: str,
    selector: str | None = None,
    *,
    rendered_images: list[dict] | None = None,
    visible_text: str | None = None,
    runtime: list[str] | None = None,
) -> dict:
    """Parse rendered HTML in the isolated worker, never in the server's event loop."""
    soup = BeautifulSoup(content, "html.parser")
    if visible_text is not None:
        for fallback in soup.find_all("noscript"):
            fallback.decompose()
    base_tag = soup.find("base", href=True)
    base = web_url(final_url, base_tag["href"]) if base_tag else final_url
    base = base or final_url
    origin = urlparse(final_url).netloc.lower()
    warnings = []

    def capped(items, limit, label):
        if len(items) > limit:
            warnings.append(f"Only the first {limit:,} {label} were saved.")
        return items[:limit]

    meta_tags = {}
    for tag in soup.find_all("meta"):
        name = tag.get("name") or tag.get("property") or tag.get("http-equiv")
        if name and tag.get("content"):
            meta_tags[name.lower()] = tag["content"][:5000]
    icon = soup.find("link", rel=lambda r: r and "icon" in r)
    canonical = soup.find("link", rel="canonical")
    headings = [
        {"level": int(tag.name[1]), "text": tag.get_text(" ", strip=True)[:500]}
        for tag in soup.find_all(re.compile(r"^h[1-6]$"))
        if tag.get_text(strip=True)
    ]
    headings = capped(headings, 2000, "headings")
    links = []
    for tag in capped(soup.find_all("a", href=True), 5000, "links"):
        if tag["href"].strip().startswith("#"):
            continue
        url = web_url(base, tag["href"])
        if url:
            links.append(
                {
                    "url": url,
                    "text": tag.get_text(" ", strip=True)[:300] or url,
                    "internal": urlparse(url).netloc.lower() == origin,
                }
            )
    images = []
    image_nodes = rendered_images if rendered_images is not None else soup.find_all("img")
    for tag in capped(image_nodes, 1000, "images"):
        src = tag.get("data-src") or tag.get("src")
        resolved = web_url(base, src)
        if src and src.lower().startswith("data:image/"):
            resolved = src
        if resolved:
            # Dimensions are display text only, never HTML or style values.
            images.append(
                {
                    "src": resolved,
                    "alt": tag.get("alt", "")[:500],
                    "width": str(tag.get("width", ""))[:100],
                    "height": str(tag.get("height", ""))[:100],
                }
            )
    tables = []
    for table in capped(soup.find_all("table"), 20, "tables"):
        rows = [
            [cell.get_text(" ", strip=True)[:500] for cell in row.find_all(["th", "td"], recursive=False)[:50]]
            for row in [row for row in table.find_all("tr") if row.find_parent("table") is table][:100]
        ]
        if rows:
            tables.append(rows)
    lists = [
        {
            "type": tag.name,
            "items": [li.get_text(" ", strip=True)[:500] for li in tag.find_all("li", recursive=False)[:100]],
        }
        for tag in capped(soup.find_all(["ul", "ol"]), 50, "lists")
    ]
    text = [tag.get_text(" ", strip=True)[:2000] for tag in soup.find_all("p") if tag.get_text(strip=True)]
    if visible_text is not None:
        text = [block.strip()[:2000] for block in re.split(r"\n\s*\n", visible_text) if block.strip()]
    text = capped(text, 200, "text blocks")
    selected = None
    if selector:
        selected = [
            {"tag": tag.name, "text": tag.get_text(" ", strip=True)[:2000], "html": str(tag)[:2000]}
            for tag in capped(soup.select(selector), 200, "selector matches")
        ]
    technologies = _detect_technologies(soup, content, runtime)
    social = _extract_social_links(links)
    structured = _extract_structured_data(soup)
    internal = sum(link["internal"] for link in links)
    return {
        "meta": {
            "title": soup.title.get_text(" ", strip=True)[:500] if soup.title else "Untitled page",
            "description": meta_tags.get("description", ""),
            "keywords": meta_tags.get("keywords", ""),
            "og_title": meta_tags.get("og:title", ""),
            "og_description": meta_tags.get("og:description", ""),
            "og_image": web_url(base, meta_tags.get("og:image")),
            "favicon": web_url(base, icon.get("href")) if icon else None,
            "canonical": web_url(base, canonical.get("href")) if canonical else None,
            "final_url": final_url,
        },
        "headings": headings,
        "links": links,
        "images": images,
        "tables": tables,
        "lists": lists,
        "text": text,
        "selector_results": selected,
        "technologies": technologies,
        "social_links": social,
        "structured_data": structured,
        "warnings": warnings,
        "stats": {
            "word_count": len((visible_text if visible_text is not None else soup.get_text(" ", strip=True)).split()),
            "link_count": len(links),
            "internal_links": internal,
            "external_links": len(links) - internal,
            "image_count": len(images),
            "heading_count": len(headings),
            "table_count": len(tables),
            "list_count": len(lists),
            "script_count": len(soup.find_all("script", src=True)),
            "inline_script_count": len(soup.find_all("script", src=False)),
            "style_count": len(soup.find_all("link", rel="stylesheet")),
            "html_size_bytes": len(content.encode("utf-8")),
            "tech_count": len(technologies),
            "social_count": len(social),
            "structured_data_count": len(structured),
        },
    }


async def scrape_page(url: str, selector: str | None = None) -> dict:
    start = time.monotonic()
    if not web_url(url, url):
        raise ValueError("Enter a complete http:// or https:// address.")
    if selector:
        if len(selector) > settings.selector_limit:
            raise ValueError(f"Keep the selector under {settings.selector_limit} characters.")
        try:
            compile_selector(selector)
        except SelectorSyntaxError as exc:
            raise ValueError("That selector is not valid. Check it and try again.") from exc
    screenshot = None
    loading_notes = []
    async with async_playwright() as playwright:
        browser = await launch_chromium(playwright)
        try:
            page = await browser.new_page(viewport={"width": 1440, "height": 900}, locale="en-US")
            response = await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            # Wait briefly for dynamic content without re-requesting the page on timeout.
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except BrowserTimeout:
                pass
            # Network quiet can occur before an app starts a deferred request.
            # Honor visible loading regions, with a bound for broken/live applications.
            try:
                await page.wait_for_function(
                    """() => ![...document.querySelectorAll('[aria-busy="true"]')]
                    .some(node => node.getClientRects().length && getComputedStyle(node).visibility !== 'hidden')""",
                    timeout=10000,
                )
            except BrowserTimeout:
                loading_notes.append("Some content was still loading when this page was saved.")
            if selector and await page.evaluate(
                """selector => {
                try { document.querySelector(selector); return true; } catch { return false; }
            }""",
                selector,
            ):
                try:
                    await page.wait_for_selector(selector, state="attached", timeout=5000)
                except BrowserTimeout:
                    loading_notes.append("No elements matched the selector within 5 seconds.")
            if await page.evaluate("document.documentElement.outerHTML.length") > 4 * 1024 * 1024:
                raise ValueError("This page is too large to capture (4 MB limit).")
            if not web_url(page.url, page.url):
                raise ValueError("The page redirected to an unsupported address.")
            try:
                image = await page.screenshot(type="jpeg", quality=70, timeout=5000)
                screenshot = base64.b64encode(image).decode("ascii")
            except Exception:
                pass
            # Read HTML and browser-selected images/text in one DOM snapshot.
            snapshot = await page.evaluate("""() => {
                const roots = [...document.querySelectorAll('*')].slice(0, 1000);
                const frameworks = [];
                if (roots.some(node => Object.keys(node).some(key => /^(__reactFiber\\$|__reactContainer\\$|_reactRootContainer)/.test(key)))) frameworks.push('React');
                if (roots.some(node => '__vue_app__' in node || '__vue__' in node)) frameworks.push('Vue.js');
                return {
                    html: (document.doctype ? new XMLSerializer().serializeToString(document.doctype) : '') + document.documentElement.outerHTML,
                    text: document.body?.innerText || '',
                    images: [...document.images].slice(0, 1001).map(img => ({
                        src: img.currentSrc || img.dataset.src || img.getAttribute('src') || '',
                        alt: img.alt, width: img.getAttribute('width') || '', height: img.getAttribute('height') || ''
                    })),
                    frameworks
                };
            }""")
            content, final_url = snapshot["html"], page.url
            if len(content.encode("utf-8")) > 4 * 1024 * 1024:
                raise ValueError("This page is too large to capture (4 MB limit).")
            status = response.status if response else None
        finally:
            await browser.close()
    result = extract_page(
        content,
        final_url,
        selector,
        rendered_images=snapshot["images"],
        visible_text=snapshot["text"],
        runtime=snapshot["frameworks"],
    )
    result["warnings"].extend(loading_notes)
    result["screenshot"] = screenshot
    result["meta"]["http_status"] = status
    result["stats"]["load_time_seconds"] = round(time.monotonic() - start, 2)
    if not screenshot:
        result["warnings"].append("A screenshot could not be saved for this page.")
    if status and status >= 400:
        result.update(
            error=f"The page returned HTTP {status}. Its response was saved below.",
            error_type="HttpError",
        )
    return result
