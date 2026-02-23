# Localghost Developer Guide

## Setup

Run commands from the inner `localghost/` directory with Python 3.12+ and uv.

```sh
uv sync --extra browser
uv run playwright install chromium
uv run python -m backend.main
```

Use one backend worker and keep the server bound to loopback. The API is served at `http://127.0.0.1:13666`; `/docs` describes request and response schemas.

## CLI

`uv run python -m backend.cli scan --help` lists scan options. The CLI shares the API's engine and supports text, JSON, and HTML reports, Docker discovery, and individual finding rechecks.

## Login sessions

Supply temporary Cookie/Authorization headers, browser storage state, or an explicitly configured login form. Set an asserted page and visible signed-in selector. Credentials are not saved in reports and must be supplied again for rechecks.

## Verification

```sh
uv run pytest -q
```
