<p align="center">
  <img src="https://raw.githubusercontent.com/qtremors/localghost/main/localghost/frontend/static/logo.png" alt="Localghost Logo" width="120"/>
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

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Port Scanning** | Identify open ports and active services on your local target. |
| 🛡️ **Security Audit** | Check for missing security headers and common misconfigurations (HSTS, CSP, etc.). |
| 🕵️ **Sensitive File Hunting** | Basic directory hunting for exposed `.env`, `.git`, or config files. |
| 📈 **Load Testing** | Run quick benchmarks to see how your local server handles ghost traffic. |

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
uv run python backend/main.py
```

Visit **http://127.0.0.1:8000**

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python, FastAPI, aiohttp |
| **Frontend** | Vanilla HTML5, CSS3 (Glow design), JavaScript |

---

## 📁 Project Structure

```
localghost/
├── backend/              # FastAPI application & scanner logic
│   ├── scanner/          # Port & Vulnerability scan modules
│   └── benchmark/        # Load testing implementation
├── frontend/             # Static files and user interface
│   ├── static/           # CSS, JS, and Assets
│   └── index.html        # Main dashboard
├── DEVELOPMENT.md        # Architecture & Conventions
├── CHANGELOG.md          # Version history
├── LICENSE.md            # License terms
└── README.md
```

---

## 🧪 Testing

```bash
# Run backend tests (TBD)
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

See [LICENSE.md](LICENSE.md) for full terms.

---

<p align="center">
  Made with ❤️ by <a href="https://github.com/qtremors">Tremors</a>
</p>
