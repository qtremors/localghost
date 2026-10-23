"""One capture per process; stdout is reserved for the result."""

import asyncio
import json
import logging
import sys

from .settings import load_settings


def main() -> None:
    request = json.load(sys.stdin)
    try:
        from playwright.async_api import Error as BrowserError
        from playwright.async_api import TimeoutError as BrowserTimeout

        from .scraper import scrape_page
    except ImportError:
        json.dump(
            {
                "error": "Captures need Playwright. Run 'uv sync --extra browser', then 'uv run playwright install chromium'.",
                "error_type": "BrowserUnavailable",
            },
            sys.stdout,
        )
        return
    try:
        load_settings()
        result = asyncio.run(scrape_page(request["url"], request.get("selector")))
    except BrowserTimeout:
        result = {
            "error": "The page did not open in time. Check that it is running and try again.",
            "error_type": "Timeout",
        }
    except BrowserError as exc:
        logging.exception("Browser capture failed")
        message = "The page could not be opened. Check the address and make sure it is reachable."
        if "Executable doesn't exist" in str(exc):
            message = "The browser is missing. Run 'uv run playwright install chromium' in the project folder, then try again."
        result = {"error": message, "error_type": "BrowserError"}
    except ValueError as exc:
        result = {"error": str(exc), "error_type": "InvalidInput"}
    except Exception as exc:
        logging.exception("Capture failed")
        result = {
            "error": "This page could not be captured. Please try again.",
            "error_type": type(exc).__name__,
        }
    json.dump(result, sys.stdout, ensure_ascii=True)


if __name__ == "__main__":
    main()
