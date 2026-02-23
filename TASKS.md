# Localghost - Tasks

> **Project:** Localghost
> **Version:** 0.1.0
> **Last Updated:** 2026-02-23

### Status Legend

| Icon | Meaning |
|------|---------|
| `[ ]` | Not started |
| `[/]` | In progress |
| `[x]` | Completed |

<!-- Labels: [Feature] [Bug] [Refactor] [Docs] [Security] [Performance] -->

---

### High Priority

- [ ] [Security] **Expand Vulnerability Database**
  - Add checks for `robots.txt` leaks, `Server` header disclosures, and common dev-server backdoors.
- [ ] [Docs] **Add API route documentation**
  - Document all Pydantic models and request/response shapes in `DEVELOPMENT.md`.

### Medium Priority

- [ ] [Feature] **Report Exporting**
  - Allow users to download the "Possession Report" as a PDF or JSON file.
- [ ] [Refactor] **Frontend Componentization**
  - Move from single static `app.js` to modular JavaScript for better maintainability.

### Low Priority

- [ ] [Performance] **Concurrent Port Scanning Optimization**
  - Fine-tune TCP connection limits to balance speed vs. network stability.

---

### Completed

- [x] [Feature] **Initial Core Implementation** — `v0.1.0`
  - Port scanning, security header checks, and load test engine.
- [x] [Docs] **Initialize Documentation suite** — `v0.1.0`
  - Core README, Architecture, and Task tracking documentation.

---

### Backlog / Ideas

> Parking lot for ideas that aren't prioritized yet.

- Integration with Discord/Slack for scan notifications
- Dockerized execution environment
- Custom scanner plugins support