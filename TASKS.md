# Localghost - Tasks

> **Project:** Localghost
> **Version:** 0.2.0
> **Last Updated:** 2026-02-24

---

### High Priority

- [ ] [Feature] **WebSocket Live Scan Progress**
  - Stream scan progress events to the TUI terminal in real-time instead of waiting for completion.
- [ ] [Feature] **PDF Report Export**
  - Generate formatted PDF reports alongside JSON export.
- [ ] [Security] **Rate Limiting**
  - Add rate limiting to the `/api/scan` endpoint to prevent abuse.

### Medium Priority

- [ ] [Feature] **Custom Port List UI**
  - Allow users to input custom port ranges from the sidebar config panel.
- [ ] [Feature] **Scan Comparison**
  - Compare two past scans side-by-side to track security improvements.
- [ ] [Refactor] **Add Python Logging**
  - Integrate structured logging throughout all scanner modules.
- [ ] [Docs] **Add API route documentation for Pydantic models**
  - Document all request/response shapes with examples in DEVELOPMENT.md.

### Low Priority

- [ ] [Performance] **Concurrent Port Scanning Optimization**
  - Fine-tune TCP connection limits to balance speed vs. network stability.
- [ ] [Feature] **Docker Support**
  - Containerized execution environment for isolated scanning.
- [ ] [Feature] **Scanner Plugin System**
  - Allow users to define custom scan modules via a plugin API.

---