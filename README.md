<p align="center">
  <img src="assets/localghost.svg" alt="Localghost logo" width="120">
</p>

<h1 align="center">Localghost</h1>

<p align="center">
  Check your web app. Inspect the evidence. Verify the fix.
</p>

<p align="center">
  <a href="#getting-started">Getting started</a> ·
  <a href="DEVELOPMENT.md">Developer guide</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="LICENSE.md">License</a>
</p>

## Why Localghost

Localghost helps you check a running web app before sharing or deploying it. It looks for exposed files and credentials, checks cookies and CORS, and visits selected pages in Chromium. Each finding includes evidence and suggested changes, with a recheck to verify your fix.

Reports separate **confirmed observations**, **items needing review**, and **checks that could not finish**. There is no overall security grade.

## Features

- **App discovery:** Find local web servers and published Docker or Compose ports, or enter a local/private URL.
- **Source context:** Connect a Next.js, Vite/React, or HTML/JavaScript project to discover routes, inspect supported configuration, and identify possible credentials without executing project code.
- **Server checks:** Inspect private-file exposure, credential material, debug output, headers, cookies, CORS, TLS certificates, open TCP ports, and resolved addresses.
- **Browser checks:** Catch JavaScript errors, failed requests, and broken initial page loads on selected routes.
- **Login sessions:** Check private pages with session headers, browser storage state, or an explicitly configured sign-in form.
- **Evidence and fixes:** Review redacted HTTP exchanges, source excerpts, relevant files, and supported configuration diffs. Recheck findings while preserving the original evidence.
- **Reports and history:** Keep reports in local SQLite history, compare compatible runs, and export JSON or printable reports. The CLI also produces text and standalone HTML.
- **Optional traffic tests:** Run load, burst, slow-connection, rate-limit, or reflected-HTML checks when selected. These are off in the recommended workflow.

## Getting started

Requires **Python 3.12+** and [uv](https://docs.astral.sh/uv/). Chromium is installed through Playwright for browser checks.

```sh
git clone https://github.com/qtremors/localghost.git
cd localghost/localghost
uv sync --extra browser
uv run playwright install chromium
uv run python -m backend.main
```

Open [Localghost](http://127.0.0.1:13666). To use an existing Chromium installation, set `LOCALGHOST_CHROMIUM_PATH` to its executable.

### Check an app

1. Start your web app, then choose **Find apps**, **Find Docker apps**, or enter its URL.
2. Optionally connect its source folder and choose **Read project details**.
3. Select routes and enter real examples for dynamic paths, such as `/items/123`. Choose development or production checks.
4. If pages require login, open **Options → Use a login session** and configure credentials and a session assertion.
5. Run the checks, inspect the evidence, and apply the relevant changes in your project.
6. Choose **Check again** on a finding to verify the change.

A recheck reports **resolved**, **still present**, or **could not verify**, with separate saved evidence. An unavailable page, missing cookie, or expired login does not establish that a finding is fixed.

### Use the CLI

Run these commands from the inner `localghost/` directory:

```sh
uv run python -m backend.cli scan http://localhost:3000 --browser --path /account --format json --output report.json
uv run python -m backend.cli recheck report.json FINDING_ID --format html --output recheck.html
uv run python -m backend.cli projects --docker
```

The CLI uses the same engine without starting the dashboard. See the [CLI reference](DEVELOPMENT.md#cli) for source inspection, session files, configuration, and exit codes.

## Supported projects

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

The dashboard binds to loopback, and scan targets must resolve to local/private addresses. Reports stay in local SQLite history. Source inspection is read-only; suggested patches are never applied automatically.

Session credentials and private environment values used for matching stay in memory for the run. Credential values are redacted from reports and previews. Supply credentials again for authenticated rechecks. See [login sessions](DEVELOPMENT.md#login-sessions) for assertions and supported sign-in flows.

Checks have file, response, and page limits. Blocked requests, failed authentication, and unavailable checks remain visible in the report. Findings describe the selected checks and observed behavior; they do not certify app security. Dependency vulnerabilities, SQL injection, stored/DOM XSS, general code correctness, and comparisons between users' permissions are outside the current coverage.

## Support

- Report bugs or request features through [GitHub Issues](https://github.com/qtremors/localghost/issues).
- Review changes in the [changelog](CHANGELOG.md).
- Read the [developer guide](DEVELOPMENT.md) for architecture, configuration, API details, and verification.
- See the [task backlog](TASKS.md) for unfinished work.

## Credits

Localghost is built by [Tremors](https://github.com/qtremors) with FastAPI, aiohttp, SQLite, Tree-sitter, Playwright, and plain HTML, CSS, and JavaScript. Interface fonts are served locally; their sources and licenses are listed in [font credits](CREDITS.md).

## License

Localghost is source-available under the **Tremors Source License (TSL)**. Read [LICENSE.md](LICENSE.md) for the terms of use.

---

<p align="center">
  Made by <a href="https://github.com/qtremors">Tremors</a>
</p>

## Page captures

Open **Captures** in the sidebar to save local or public pages, search history, and export captured content.

Capture a rendered page without starting the dashboard:

```sh
uv run python -m backend.modules.xcrape capture https://example.com --output capture.json
```

Captures can load external page resources and save private content. They do not reuse scan sessions. See the [capture guide](DEVELOPMENT.md#capture-module) for configuration, history import, and limits.

The dashboard uses an OLED black default theme with cyan and blue accents. A light theme is also available.
