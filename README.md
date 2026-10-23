<p align="center">
  <img src="assets/localghost.svg" alt="Localghost logo" width="120">
</p>

<h1 align="center">Localghost</h1>

<p align="center">
  Inspect web apps. Capture web pages.
</p>

<p align="center">
  <a href="#getting-started">Getting started</a> ·
  <a href="PRIVACY.md">Privacy</a> ·
  <a href="DEVELOPMENT.md">Developer guide</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="LICENSE.md">License</a>
</p>

## Why Localghost

Localghost is a local-first workspace for inspecting web apps and saving rendered web pages. Its two modules share one dashboard, local storage locations, and browser setup:

- **Scans** check local/private apps, collect evidence, and help verify fixes.
- **Captures** save local or public pages as screenshots and structured content you can search and export.

> [!NOTE]
> Reports and captures are stored on your machine. Scans contact the selected app, and captures can load public websites and their external resources. Read the [privacy and data-handling guide](PRIVACY.md) for storage and network details.

## Features

### Scans

- **App discovery:** Find local web servers and published Docker or Compose ports, or enter a local/private URL.
- **Source context:** Connect a Next.js, Vite/React, or HTML/JavaScript project to discover routes, inspect supported configuration, and identify possible credentials without executing project code.
- **Server checks:** Inspect private-file exposure, credential material, debug output, headers, cookies, CORS, TLS certificates, open TCP ports, and resolved addresses.
- **Browser checks:** Catch JavaScript errors, failed requests, and broken initial page loads on selected routes.
- **Login sessions:** Check private pages with session headers, browser storage state, or an explicitly configured sign-in form.
- **Evidence and fixes:** Review redacted HTTP exchanges, source excerpts, relevant files, and supported configuration diffs. Recheck findings while preserving the original evidence.
- **Optional traffic tests:** Run load, burst, slow-connection, rate-limit, or reflected-HTML checks when selected. These are off in the recommended workflow.

### Captures

- **Rendered pages:** Save a Chromium viewport screenshot and extract visible text, headings, links, responsive images, tables, lists, forms, and page metadata.
- **Selected content:** Use an optional CSS selector to extract a particular part of a page alongside the page capture.
- **Capture history:** Search and filter saved pages, inspect their content, and capture a page again.
- **Exports:** Download JSON, spreadsheet-safe CSV, individual images, or an image archive. JSON includes the saved screenshot; image downloads fetch the source images again.
- **Standalone use:** Capture a page from the command line or copy compatible capture history into Localghost. See the [capture guide](DEVELOPMENT.md#capture-module).

### Shared workspace

- **Local history:** Keep scan reports and captures in separate SQLite databases. Compare compatible scan reports without mixing them with capture history.
- **Exports and presentation:** Export scan reports as JSON or printable reports, or use text and standalone HTML from the scan CLI. Both modules share an OLED black theme with cyan and blue accents, an optional light theme, and responsive navigation.
- **One installation:** Run the dashboard, scan CLI, and capture CLI from the same package. Browser checks and captures use the same optional Chromium setup.

## Getting started

Requires **Python 3.12+** and [uv](https://docs.astral.sh/uv/). Browser checks and captures also require Chromium, installed below through Playwright. The dashboard needs no Node.js installation or frontend build.

```sh
git clone https://github.com/qtremors/localghost.git
cd localghost/localghost
uv sync --extra browser
uv run playwright install chromium
uv run localghost
```

Open [Localghost](http://127.0.0.1:13666). To use an existing Chromium installation, set `LOCALGHOST_CHROMIUM_PATH` to its executable. For configuration, installed packages, and development reload, see [setup](DEVELOPMENT.md#setup).

### Check an app

1. Start your web app, then choose **Find apps**, **Find Docker apps**, or enter its URL.
2. Optionally connect its source folder and choose **Read project details**.
3. Select routes and enter real examples for dynamic paths, such as `/items/123`. Choose development or production checks.
4. If pages require login, open **Options → Use a login session** and configure credentials and a session assertion.
5. Run the checks, inspect the evidence, and apply the relevant changes in your project.
6. Choose **Check again** on a finding to verify the change.

A recheck reports **resolved**, **still present**, or **could not verify**, with separate saved evidence. An unavailable page, missing cookie, or expired login does not establish that a finding is fixed.

Reports separate **confirmed observations**, **items needing review**, and **checks that could not finish**. There is no overall security grade.

### Capture a page

1. Open **Captures** in the sidebar.
2. Enter a complete local or public `http://` or `https://` address.
3. Optionally open **Choose part of a page** and enter a CSS selector, such as `article`.
4. Choose **Capture page**, then open the saved result to explore its screenshot, text, links, images, and page details.
5. Search saved captures, repeat a capture, or export the content you need.

Captures use a fresh browser and do not reuse scan login sessions or your personal browser profile. Loading warnings and HTTP error pages remain visible in the saved result.

### Use the CLI

Run these commands from the inner `localghost/` directory:

```sh
uv run python -m backend.cli scan http://localhost:3000 --browser --path /account --format json --output report.json
uv run python -m backend.cli recheck report.json FINDING_ID --format html --output recheck.html
uv run python -m backend.cli projects --docker
uv run python -m backend.modules.xcrape capture https://example.com --selector article --output capture.json
```

These commands run without starting the dashboard. Standalone captures write JSON and do not add a record to dashboard history; output files must be new. See the [scan CLI reference](DEVELOPMENT.md#cli) and [capture guide](DEVELOPMENT.md#capture-module) for configuration, history import, and exit codes.

## Supported projects

The following source recognition applies to **Scans**. Captures accept local or public HTTP/HTTPS pages independently of the site's framework, subject to rendering and extraction limits.

| Project | Source context |
| --- | --- |
| Next.js | App Router and Pages Router pages/API routes, supported configuration, and source/build credentials |
| Vite / React | Vite settings, React Router JSX and literal route arrays, and source/build credentials |
| HTML / JavaScript | HTML paths, scripts, credential patterns, and private files |
| Other HTTP frameworks and JSON APIs | Limited source recognition; use server checks and manually selected paths |

Server checks work independently of source recognition. Browser checks visit selected pages rather than crawling the app. Computed routes and settings that cannot be resolved remain explicit omissions.

Localghost does not start or build your app. To check production behavior, run the production build locally. Selecting production mode alone does not prove which build was tested.

For Docker apps, select a published web port reachable from Localghost, such as `127.0.0.1:3000:3000`. A matching bind mount can suggest a source folder, which must exist on the machine running Localghost. Discovery requires local Docker CLI/socket access and does not read container environment variables.

## Privacy and limits

The dashboard binds to loopback. Scan targets must resolve to local/private addresses; captures can visit local or public sites and load their scripts and external resources. Source inspection is read-only, and suggested patches are never applied automatically.

Scan session credentials and private environment values used for matching stay in memory for the run. Recognized credential values are redacted from scan reports and evidence previews. Supply credentials again for authenticated rechecks. See [login sessions](DEVELOPMENT.md#login-sessions) for assertions and supported sign-in flows.

Scan redaction does not sanitize captured pages, screenshots, or capture exports. Saved content can include private information. The databases and exported files are not encrypted by Localghost. See [PRIVACY.md](PRIVACY.md) for storage locations, outbound requests, and deletion guidance.

Checks have file, response, and page limits. Blocked requests, failed authentication, and unavailable checks remain visible in the report. Findings describe the selected checks and observed behavior; they do not certify app security. Dependency vulnerabilities, SQL injection, stored/DOM XSS, general code correctness, and comparisons between users' permissions are outside the current coverage.

## Support

- Report bugs or request features through [GitHub Issues](https://github.com/qtremors/localghost/issues).
- Review changes in the [changelog](CHANGELOG.md).
- See the [task backlog](TASKS.md) for unfinished work.
- Read the [privacy and data-handling guide](PRIVACY.md).

## Credits

Localghost is built by [Tremors](https://github.com/qtremors) with:

- FastAPI, Starlette, and Uvicorn for the application and API.
- aiohttp and HTTPX for HTTP work, and Playwright for Chromium automation.
- Tree-sitter for source parsing, and Beautiful Soup and Soup Sieve for captured HTML and selectors.
- SQLite and aiosqlite for local history, and plain HTML, CSS, and JavaScript for the dashboard.

Interface fonts are served locally; their sources and licenses are listed in [font credits](CREDITS.md). Each dependency remains subject to its own license.

## For developers

Architecture, module ownership, configuration, CLI/API references, authentication, packaging, verification, and troubleshooting live in [DEVELOPMENT.md](DEVELOPMENT.md).

## License

Localghost is source-available under the **Tremors Source License (TSL) Version 2.0**. Read [LICENSE.md](LICENSE.md) for the terms of use.

---

<p align="center">
  Made by <a href="https://github.com/qtremors">Tremors</a>
</p>
