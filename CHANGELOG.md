# Localghost Changelog

> **Project:** Localghost
> **Version:** 0.2.0
> **Last Updated:** 2026-02-24

---

## [0.2.0] - 2026-02-24

### Added
- **8 New Scanner Modules**: SSL/TLS analysis, CORS misconfiguration detection, Cookie security audit, Technology fingerprinting, DNS record enumeration, DDoS resilience testing, API rate limit detection, and reflected XSS scanning.
- **Security Scoring Engine**: Weighted 0–100 scoring with letter grades (A+ through F) and per-category breakdown (Headers: 30pt, Files: 25pt, SSL: 20pt, Cookies: 10pt, CORS: 10pt, Ports: 5pt).
- **Scan History**: SQLite-persisted scan history with CRUD API endpoints and sidebar quick-access list.
- **JSON Report Export**: Download full scan reports as pretty-printed JSON files via `/api/report/{scan_id}`.
- **Health Check Endpoint**: `GET /health` for basic liveness checks.
- **Dark/Light Theme Toggle**: Material Design 3 theme switching with localStorage persistence.
- **TUI Terminal Panel**: Hacker-style terminal output during scan execution.
- **Configurable Load Test**: User-adjustable concurrency (1–500) and duration (1–60s) from the sidebar.
- **Latency Percentiles**: P50, P95, P99 latency metrics in benchmark results.
- **Favicon**: Added project logo as browser favicon.

### Changed
- **Backend Architecture**: Complete restructure from flat layout to routers/services/scanners/models/database/utils.
- **Frontend Rewrite**: Replaced glow CSS with Material Design 3 design system (dark/light themes, MD3 tokens, elevation, typography).
- **Responsive Layout**: Sidebar + main content grid with mobile drawer, tablet collapse, and desktop spacious modes.
- **JavaScript Modularization**: Split monolithic `app.js` into 7 ES modules (api, theme, utils, score, results, history, app).
- **Port Scanner**: Expanded from 9 to 35+ common ports with automatic service identification.
- **Vulnerability Scanner**: Added 7 security header checks (was 4), expanded sensitive file list to 18 paths (was 4), added severity levels. Context-aware recommendations for `.git` and `.env` exposure.
- **Load Tester**: Added per-request latency tracking, percentile calculations, error rate, and min/max/avg metrics.
- **API Structure**: Moved from single `POST /api/scan` to multi-router design with scan, history, and report endpoints.
- **Server Port**: Changed from 8000 to **13666** (unique port, avoids conflicts with common dev servers).
- **Port Scanner Self-Exclusion**: Localghost’s own port (13666) is automatically filtered out when scanning localhost targets.
- **Sensitive File List**: Removed `robots.txt`, `sitemap.xml`, and `.well-known/security.txt` (these are intentionally public, not security issues).

### Removed
- Old "Glow" design system CSS.
- Old `backend/scanner/` and `backend/benchmark/` directories (replaced by `backend/scanners/`).

---

## [0.1.0] - 2026-02-23

### Added
- Initial core implementation: port scanning, security header checks, sensitive file hunting, and HTTP load testing.
- FastAPI backend with single `/api/scan` endpoint.
- Vanilla HTML/CSS/JS frontend with "Glow" design system.
- Core documentation suite (README, DEVELOPMENT, CHANGELOG, TASKS, LICENSE).

---