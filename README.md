<p align="center">
  <img src="assets/localghost.png" alt="Localghost Logo" width="120"/>
</p>

<h1 align="center"><a href="https://github.com/qtremors/localghost">Localghost</a></h1>

<p align="center">
  Possess & analyze local running servers with a hauntingly efficient pentesting & benchmarking toolkit.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12+-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.131+-green?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/License-TSL-red" alt="License">
</p>

> [!NOTE]
> **Personal Project** 🎯 I built this to automate local environment security checks and performance benchmarking in a single, lightweight tool.

> [!WARNING]
> **Local Use Only** — This tool is designed for scanning servers you own running on `localhost` / private IPs. Do not use it against servers you don't own or have permission to test.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Port Scanning** | Discover open ports with automatic service identification (35+ known services). |
| 🛡️ **Security Audit** | Check for 7 critical security headers, 18 sensitive file paths, and server disclosures. |
| 🔒 **SSL/TLS Analysis** | Inspect certificates, protocol versions, cipher suites, and expiry status. |
| 🌐 **CORS Audit** | Detect wildcard origins, credential leaks, and origin reflection attacks. |
| 🍪 **Cookie Security** | Audit Secure, HttpOnly, and SameSite flags on all cookies. |
| 🔬 **Tech Detection** | Fingerprint server technologies from headers and HTML content patterns. |
| 🌍 **DNS Enumeration** | Resolve A and AAAA records for the target hostname. |
| 📈 **Load Testing** | Configurable concurrent load tests with percentile latency metrics (p50/p95/p99). |
| ⚡ **DDoS Resilience** | Test connection flood handling, slowloris protection, and post-attack availability with resilience scoring. |
| 🚦 **Rate Limit Detection** | Detect rate limiting via headers, burst tests, sustained traffic analysis, and per-endpoint checks. |
| 🐛 **XSS Scanning** | Reflected XSS detection via parameter injection, path reflection, error page probing, and CSP header checks. |
| 📊 **Security Score** | Weighted 0-100 scoring with letter grades (A+ through F) and category breakdown. |
| 📜 **Scan History** | SQLite-persisted scan history with one-click recall of past results. |
| 📥 **Report Export** | Download full scan reports as JSON files. |

---

## 🚀 Quick Start

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | `3.12+` | [python.org](https://www.python.org/downloads/) |
| uv | `latest` | [astral.sh/uv](https://docs.astral.sh/uv/getting-started/installation/) |

### Setup

```bash
# Clone and navigate
git clone https://github.com/qtremors/localghost.git
cd localghost/localghost

# Install dependencies
uv sync

# Run the project
uv run python -m backend.main
```

Visit **http://127.0.0.1:13666**

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python, FastAPI, aiohttp, aiosqlite |
| **Frontend** | Vanilla HTML5, CSS3 (Material Design 3), ES Modules |
| **Database** | SQLite (scan history) |

---

## 📁 Project Structure

```
localghost/
├── backend/                  # Python/FastAPI Application
│   ├── routers/              # API route definitions
│   │   ├── scan.py           # POST /api/scan
│   │   ├── history.py        # GET/DELETE /api/history
│   │   └── report.py         # GET /api/report/:id
│   ├── services/             # Business logic layer
│   │   ├── scanner.py        # Scan orchestration
│   │   └── scoring.py        # Security score engine
│   ├── scanners/             # Individual scan modules
│   │   ├── port_scan.py      # TCP port discovery + service ID
│   │   ├── vuln_scan.py      # Security headers, sensitive file paths, and server disclosures
│   │   ├── ssl_scan.py       # SSL/TLS certificate analysis
│   │   ├── cors_scan.py      # CORS misconfiguration detection
│   │   ├── cookie_scan.py    # Cookie security audit
│   │   ├── tech_detect.py    # Technology fingerprinting
│   │   ├── dns_scan.py       # DNS record enumeration
│   │   ├── load_test.py      # HTTP load generation
│   │   ├── ddos_test.py      # DDoS resilience testing
│   │   ├── rate_limit_test.py # API rate limit detection
│   │   └── xss_scan.py       # Reflected XSS scanning
│   ├── models/               # Pydantic request/response models
│   │   └── scan.py           # All scan models
│   ├── database/             # SQLite persistence
│   │   └── db.py             # Scan history CRUD
│   ├── utils/                # Shared utilities
│   │   └── validators.py     # URL validation
│   └── main.py               # App factory, router registration
├── frontend/                 # Client-side assets
│   ├── static/
│   │   ├── js/               # ES Module JavaScript
│   │   │   ├── app.js        # Main entry point
│   │   │   ├── api.js        # API client
│   │   │   ├── results.js    # Result rendering
│   │   │   ├── score.js      # Score gauge + breakdown
│   │   │   ├── history.js    # History management
│   │   │   ├── theme.js      # Dark/light toggle
│   │   │   └── utils.js      # DOM helpers
│   │   └── style.css         # Material Design 3 stylesheet
│   └── index.html            # Dashboard UI
├── DEVELOPMENT.md            # Developer documentation
├── CHANGELOG.md              # Version history
├── TASKS.md                  # Planned features & issues
├── LICENSE.md                # License terms
└── pyproject.toml            # Project dependencies (uv)
```

---

## 🧪 Testing

```bash
# Run backend tests (WIP)
uv run pytest
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [DEVELOPMENT.md](DEVELOPMENT.md) | Architecture, API reference, conventions |
| [CHANGELOG.md](CHANGELOG.md) | Version history and release notes |
| [TASKS.md](TASKS.md) | Planned features and known issues |
| [LICENSE.md](LICENSE.md) | License terms and attribution |

---

## 📄 License

**Tremors Source License (TSL)** - Source-available license allowing viewing, forking, and derivative works with **mandatory attribution**. Commercial use requires written permission.

Web Version: [github.com/qtremors/license](https://github.com/qtremors/license)

See [LICENSE.md](LICENSE.md) for full terms.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/qtremors">Tremors</a>
</p>
