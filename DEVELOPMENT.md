# Localghost Developer Guide

Setup, architecture, interfaces, and verification for working on Localghost. For an overview and the dashboard workflow, start with the [README](README.md).

**Version:** 0.1.4 | **Last Updated:** 2026-10-23

## Contents

- [Setup](#setup)
- [Project structure](#project-structure)
- [Architecture](#architecture)
- [Configuration and storage](#configuration-and-storage)
- [CLI](#cli)
- [Login sessions](#login-sessions)
- [API](#api)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)

## Setup

Run commands from the inner `localghost/` directory. Python 3.12+ and uv are required. Node.js runs the frontend tests; no npm installation or frontend build is needed.

```sh
uv sync --extra browser
uv run playwright install chromium
uv run python -m backend.main
```

The dashboard is served at `http://127.0.0.1:13666`. The module entry point enables development reload. To run without reload:

```sh
uv run uvicorn backend.main:app --host 127.0.0.1 --port 13666
```

Use one backend worker. Admission is process-local, so coordinate separate CLI processes when running traffic tests.

## Project structure

```text
localghost/
├── assets/                     # Repository branding
├── localghost/
│   ├── backend/
│   │   ├── main.py             # FastAPI application and loopback entry point
│   │   ├── cli.py              # Scan, export, discovery, and recheck commands
│   │   ├── middleware.py       # Local UI access and request-size checks
│   │   ├── models/             # Scan, session, finding, and report schemas
│   │   ├── routers/            # Scan, project, history, recheck, and export APIs
│   │   ├── services/           # Orchestration, source inspection, sessions, fixes
│   │   ├── scanners/           # Individual server, browser, and traffic checks
│   │   ├── database/           # SQLite history and migrations
│   │   └── utils/              # Networking, evidence, validation, and redaction
│   ├── frontend/               # Directly served HTML, CSS, JavaScript, and fonts
│   ├── tests/                  # Python, Node, browser, and live-app checks
│   ├── pyproject.toml          # Python dependencies and tool configuration
│   └── package.json            # Node test command
├── README.md                   # User overview and quick start
├── DEVELOPMENT.md              # This guide
├── CHANGELOG.md                # Unreleased changes and version history
├── TASKS.md                    # Unfinished work
└── LICENSE.md                  # Project license
```

## Architecture

FastAPI serves the API and frontend. aiohttp handles server probes, Playwright runs Chromium, Tree-sitter parses JavaScript/TypeScript, and aiosqlite stores report history. Dashboard and CLI scans share the same orchestration.

### Scan flow

1. `models/scan.py` validates `ScanRequest`, including the target, modules, routes, environment, source folder, and optional `ScanSession`.
2. `services/scanner.py` validates and pins target addresses, prepares and verifies the session, and reads source context without executing project code.
3. Independent diagnostics and browser checks run, followed by route-level HTTP audits. These include selected server paths and up to 20 observed same-origin GET API URLs. Optional active checks run sequentially.
4. `services/findings.py` assigns stable IDs and prepares verification status, evidence, relevant files, and fix guidance. Captured credentials are redacted before the report is saved.

Browser checks visit selected pages on the target origin. Other origins and WebSockets are blocked. GET, HEAD, and OPTIONS are allowed; only explicitly configured sign-in or refresh POSTs are allowed in their respective phases. Blocked or unavailable requests leave coverage incomplete.

### Findings and rechecks

Current reports use scanner version `4` and `score: null`. Confirmed observations, review items, and incomplete checks remain separate. Generic missing-header findings have low priority and require review. TLS/DNS evidence is identified as transport/resolution evidence rather than an HTTP exchange.

Evidence comes from the actual probe and includes bounded, redacted headers and body excerpts or source file/line excerpts. Configuration diffs are reviewable suggestions; examples need adaptation to the target project. Source files are never edited automatically. Provider-shaped credentials are reported as credential material without contacting providers to validate them.

Rechecks repeat the relevant module, reload connected source context, and save separate evidence linked to the original finding. Explicitly selected traffic modules are repeated only when relevant to that finding. Missing cookies, unavailable responses, unobserved browser resources, changed scanner versions, or incomplete checks cannot establish resolution.

Comparisons require compatible scanner versions and scope, including source paths, server/browser routes, discovered audit targets, environment, session assertion profiles, session presence, and checked ports. Changed scope must not appear as a verified fix.

### Inspection limits

| Area | Bound |
| --- | --- |
| Source traversal | 1,500 considered files and 500 folders |
| Source text | 400 files / 16 MiB total; 256 KiB per file |
| Client build output | 150 files / 32 MiB total; 2 MiB per file; 500 folders |
| Served scripts | Up to 20 same-origin scripts, 2 MiB each, per selected server route |
| Browser pages | Target page plus up to 20 additional selected paths |
| Observed API routes | Up to 20 same-origin GET API URLs |

Limits and shortened evidence do not imply full content coverage. Reaching an inspection limit makes the relevant coverage incomplete. Credential matching must remain bounded on generated JavaScript.

## Configuration and storage

| Variable | Purpose |
| --- | --- |
| `LOCALGHOST_DB_PATH` | SQLite file; defaults to `localghost/localghost.db` relative to the repository root. The parent directory must exist. |
| `LOCALGHOST_CHROMIUM_PATH` | Optional Chromium executable for scan browser checks |
| `LOCALGHOST_ALLOWED_HOSTS` | Comma-separated additional UI proxy hostnames; does not expand permitted scan targets |
| `LOCALGHOST_BROWSER` | Chromium executable used by UI test scripts |

Set variables before starting the process. In PowerShell, use `$env:LOCALGHOST_DB_PATH = 'C:/path/to/review.db'`. In a POSIX shell, use `export LOCALGHOST_DB_PATH=/path/to/review.db`.

SQLite stores report JSON in `scans`. The `rechecks` table links original scans and findings to repeat evidence, state, and timestamp. Removing either report removes its recheck link. Legacy score/grade columns remain for compatibility; new records use placeholders, and old reports remain readable without showing grades in the interface. Cookie-prefix redaction migration runs once under `PRAGMA user_version = 1`.

### Security boundaries

- Preserve local/private target restrictions, DNS pinning, the original Host header and TLS SNI, and server probes that do not follow redirects.
- Keep credentials and the credential comparison inventory in task-local memory. Do not use shared mutable session headers. Saved requests exclude session credentials; rechecks require them again.
- Redact report bodies, headers, exports, history URLs, and validation errors without altering schema enum values. Omit sign-in request bodies from evidence.
- Treat target and source strings as untrusted. Render text or escape HTML, and retain the 64 KiB API request-body cap.
- Keep the backend on loopback. Host/Origin checks restrict browser access but do not authenticate other local programs.

## CLI

The CLI runs independently of the dashboard. Replace the source path below with an absolute path on the machine running Localghost.

```sh
uv run python -m backend.cli scan http://localhost:3000 --source /absolute/path/to/app --environment production --browser --path /account --path /settings --format json --output report.json
uv run python -m backend.cli scan --config localghost.json --session-file /private/session.json --format html --output report.html
uv run python -m backend.cli recheck report.json FINDING_ID --session-file /private/session.json --format html --output recheck.html
uv run python -m backend.cli projects --docker
```

`--config` accepts a `ScanRequest` JSON object. Command options override corresponding settings. For example:

```json
{
  "target_url": "http://localhost:3000",
  "environment": "production",
  "paths": ["/account", "/settings"],
  "modules": {
    "browser_check": true,
    "load_test": false
  }
}
```

Unspecified modules retain their defaults. Source and browser checks are opt-in through the API/config; `--source` enables source inspection, and `--browser` enables browser checks. `--checks vuln_scan,cookie_scan,cors_scan,browser_check` replaces the entire module selection. Use `scan --help` for all options and `/docs` on the running dashboard for schemas, benchmark settings, and custom ports.

Exports support `--format text`, `json`, and standalone `html`, with finding IDs, evidence, scope, routes, and fix guidance. `--no-save` leaves local history unchanged. A recheck accepts an exported report JSON file or a saved scan ID, and requires a separate output path to preserve the original file.

| Exit | Scan | Individual recheck |
| --- | --- | --- |
| `0` | Completed with no confirmed finding at the threshold | Resolved or check completed |
| `1` | Confirmed finding meets `--fail-on` (default: `high`) | Still present |
| `2` | Incomplete checks, invalid setup, or unavailable target | Could not verify |
| `130` | Interrupted | Interrupted |

`--include-review` also fails on items needing investigation. A threshold finding takes precedence over incomplete checks in scan exit codes; both remain visible in the report. A successful exit applies only to the selected checks.

## Login sessions

In the dashboard, open **Options → Use a login session**. In the CLI, supply a private `ScanSession` JSON file with `--session-file`. Keep the file outside version control.

| Method | Configuration |
| --- | --- |
| Headers | Supply `cookie` and/or `authorization` header values. |
| Form sign-in | Supply a `login` object with `path`, `username`, `password`, and `success_selector`. Override field/button selectors when needed and add separate sign-in POST paths to `allowed_post_paths`. |
| Browser state | Supply `storage_state` as a JSON-encoded Playwright storage-state string containing cookies/localStorage for the selected host and origin. |

For example, a header session file:

```json
{
  "cookie": "sid=YOUR_SESSION_VALUE",
  "check_path": "/account",
  "check_selector": "[data-user-menu]"
}
```

Set `check_path` to a page requiring login. A header-only assertion requires a 2xx response; browser assertions also require the configured visible element. Choose a selector absent from the logged-out page. Supplied headers/state without an assertion are labeled unverified. Failed assertions stop authenticated HTTP checks with no anonymous fallback.

Form sign-in uses the page's own CSRF fields and same-origin redirects. `refresh_path` permits an explicit refresh POST during page checks. `authorization_storage_key` names a localStorage token to reuse as a Bearer header for later server checks. After browser pages run, asserted sessions are checked again using current cookies/storage without another sign-in. Removed cookies or tokens are cleared from server headers.

Cookie observations from initial login GETs, sign-in POSTs, authenticated pages, and refresh responses feed cookie checks. Reports retain nonsecret selectors and assertions so a recheck can repeat the scope after credentials are supplied again. External OAuth, MFA, arbitrary form workflows, and comparisons between users' permissions are outside the supported session flow.

## API

The running dashboard exposes interactive request schemas at `/docs`.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/api/scan` | Run a scan and return the complete report |
| POST | `/api/scan/stream` | Stream NDJSON progress and the report; disconnect cancels |
| POST | `/api/projects/inspect` | Read metadata from `{ "source_path": "/absolute/path" }` |
| POST | `/api/projects/discover` | Find loopback HTTP apps on common ports |
| POST | `/api/projects/docker` | Discover local published container ports, Compose names, and source bind mounts |
| GET | `/api/projects` | Read paginated project summaries |
| GET | `/api/history` | Read paginated, searchable report summaries |
| GET / DELETE | `/api/history/{id}` | Read or delete a saved report |
| GET | `/api/history/{id}/comparison/{baseline}` | Compare compatible evidence |
| POST | `/api/history/{id}/findings/{finding_id}/recheck` | Repeat a relevant check; accepts optional `{ "session": { ... } }` |
| GET | `/api/report/{id}` | Download report JSON |
| GET | `/health` | Read liveness and app version |

Unknown scan fields are rejected. Routes must be paths on the selected app, with at most 20 additional paths. The desktop recommended preset includes browser checks even though the API default does not. Streaming emits `started`, `module`, `heartbeat`, `complete`, and `error` records. API workloads share a process-local admission lock.

## Verification

Choose checks relevant to the change. Backend tests can be narrowed by file or test name; browser and Docker checks are separate acceptance runs.

```sh
uv run ruff check backend tests main.py
uv run pytest -q tests/test_product_completion.py
npm test
```

For the full backend suite, use `uv run pytest -q`. Browser-dependent tests require the Playwright Chromium installation from setup.

### Browser and live-app checks

```sh
uv run python tests/product_browser.py --output ../../localghost-artifacts/product
uv run python tests/capture_screenshots.py --output ../../localghost-artifacts/screenshots
```

| Script or test | Coverage and requirements |
| --- | --- |
| `tests/test_product_completion.py` | Configuration parsing, routes, evidence, credentials, sessions, Docker hints, CLI rechecks, redaction, and generated-JavaScript matching |
| `tests/test_product_workflow.py` | Loopback servers and Chromium, source context, credential handling, browser errors, CLI exits, and before/after rechecks |
| `tests/product_browser.py` | Desktop source selection, sessions, evidence, fixes, and optional axe checks via `--axe` |
| `tests/capture_screenshots.py` | Screenshots and PDF output using temporary history and identified fixtures |
| `tests/browser_smoke.py` | Navigation, reports, history, themes, and keyboard behavior; writes screenshots under `/tmp`, so use a Linux environment |
| `tests/live_review.py` | Vulnerable/fixed control servers and optional external training apps; requires a running Localghost API and `--api-url`, `--output`; optional axe via `--axe-path` |
| `tests/authenticated_apps.py` | Sessions on already initialized, disposable Juice Shop/DVWA apps; does not initialize or reset DVWA |

`live_review.py` can initialize/reset the disposable DVWA database when given `--dvwa-url`. Its direct SQL-injection and script-execution controls are separate from Localghost's scanner coverage.

### Docker acceptance

`completion_browser.py` requires a Linux Docker socket at `/var/run/docker.sock` and an already available image with Node. It does not pull an image. Run it from a Linux environment with access to that socket:

```sh
uv run python tests/completion_browser.py --image node:22-bookworm-slim --output ../../localghost-artifacts/docker
```

Use `--node-executable` for an image with a nonstandard Node path and `--axe` to supply axe-core. The script creates and removes its own Compose fixture, publishes ports on loopback, mounts source read-only, and uses temporary history. It checks discovery, source binding, form sign-in, GET API coverage, evidence, rechecks, and themes.

Keep generated evidence outside the repository, as in the output paths above. Do not commit databases, session files, private keys, or bytecode. Track unfinished work in [TASKS.md](TASKS.md), and update the [changelog](CHANGELOG.md) for verified user-visible changes.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Browser check is unavailable | Install Playwright Chromium or set `LOCALGHOST_CHROMIUM_PATH` to a valid executable. UI test scripts use `LOCALGHOST_BROWSER`. |
| Source folder is unavailable | Use an absolute path accessible to the Localghost process. Docker bind-mount suggestions must exist on that machine. |
| Docker app is missing or unreachable | Start the local daemon, check CLI/socket access, and publish the web port. Confirm the HTTP/HTTPS scheme. An unpublished container port cannot be reached through localhost. |
| Production mode remains unknown | Run the production build locally. A selected mode alone is insufficient; served content must provide supporting evidence. |
| Authenticated checks stop | Check the session, asserted page, and visible selector. Supply credentials again for rechecks. |
| History cannot be saved | Check `LOCALGHOST_DB_PATH`, parent-directory existence, and write access. |
| Workload is busy | Wait for the current scan or discovery run. Use one backend worker and coordinate CLI traffic tests. |

When running Localghost in a container yourself, mount the source and use a private target address reachable from that container. Localghost container packaging is not currently provided.

## Capture module

Open **Captures** in the sidebar to capture local or public pages, search saved results, and export content or images. Captures do not reuse scan sessions.

Capture APIs use `/api/xcrape`; the legacy `/api/scrape` and `/api/jobs/...` routes remain available. Capture failures do not disable scans.

From the inner `localghost/` directory, run a standalone capture or import history:

```sh
uv run python -m backend.modules.xcrape capture https://example.com --output capture.json
uv run python -m backend.modules.xcrape import-db /absolute/path/to/scraper.db
```

Captures use optional Playwright Chromium support. Configuration comes from the repository `.env` and matching process variables; see `.env.example`. Scan and capture histories remain separate.

The dashboard defaults to OLED black with cyan and blue accents. Saved light/dark preferences remain available through the theme button. The root `assets/localghost.svg` and packaged SVG are identical.
