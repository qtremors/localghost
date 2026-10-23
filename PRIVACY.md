# Localghost - Privacy and Data Handling

**Last Updated:** 2026-10-23

Localghost runs on your machine and stores scan reports and captured pages locally. This guide explains its network activity, saved data, credentials, and deletion behavior.

## Network Activity

Localghost has no built-in account service, cloud history sync, or telemetry service. The dashboard's scripts, styles, icons, and fonts are served by the local application.

| Activity | Network behavior |
| --- | --- |
| Scans | Contact the selected local/private app for the enabled checks. Address resolution uses the system resolver, which may contact network DNS services; TLS checks inspect the target connection. |
| Scan browser checks | Visit selected pages with scanner request restrictions; other origins and WebSockets are blocked. |
| Captures | Open local or public HTTP/HTTPS pages in Chromium. Page scripts, redirects, images, and other external resources can make additional requests. |
| Image previews and downloads | Fetch the saved source image address again. The remote server can observe these requests, and the image may have changed since capture. |
| Original-image links | Open the source address in your own browser, which can use that browser's existing session. |
| Installation | Dependency and Chromium installation contact their download services. |

Captures are not an offline browsing mode. A captured page can load third-party analytics or other resources belonging to that site. Scan credentials and personal browser profiles are not reused for captures. Preview/download requests do not inherit the capture browser's cookies or headers.

## Data Stored on Your Machine

| Data | What is stored |
| --- | --- |
| Scan history | Report JSON, selected scope, findings, bounded/redacted evidence, source references, timestamps, and recheck relationships in `localghost.db`. |
| Capture history | Submitted addresses, selectors, job status, errors, extracted page content, metadata, and saved screenshots in `captures.db`. |
| Exports | Files you download or write through a CLI, including report JSON/HTML/text and capture JSON/CSV/images/archives. |
| Browser preferences | Dashboard preferences such as the selected theme in browser local storage. |
| Temporary files and logs | Image fetching can spool temporary data to disk. Server and worker diagnostics are written to process output, which your terminal or launcher may retain. |

The two histories are independent. A standalone capture writes JSON to stdout or a new output file without adding a dashboard history record. Importing capture history copies a compatible database to a new destination and leaves the source unchanged.

### Storage Locations

Source checkouts default to `localghost/localghost.db` and `localghost/captures.db` relative to the repository root. Installed copies choose their data directory in this order:

1. `$XDG_DATA_HOME/localghost`, when set.
2. `%LOCALAPPDATA%/localghost` on Windows, when available.
3. `~/.local/share/localghost` otherwise.

`LOCALGHOST_DB_PATH` and `LOCALGHOST_CAPTURE_DB_PATH` override the corresponding database path. Captures also accept a legacy SQLite `DATABASE_URL` when the modern capture override is unset. Parent folders are created automatically. Configuration precedence and relative paths are documented in the [developer guide](DEVELOPMENT.md#configuration-and-storage).

Localghost does not encrypt its history databases or exported files. Their protection depends on your filesystem permissions, device security, and any backup or sync software you use.

## Credentials and Captured Content

Scan session credentials and the private values used for credential matching are kept in run-local memory. Saved scan requests omit session credentials, sign-in request bodies are excluded from evidence, and report preparation redacts recognized credential values. Authenticated rechecks require credentials to be supplied again. Nonsecret selectors and session assertions can remain in reports so the scope can be repeated.

Source inspection reads connected files without running project code or applying suggested patches. Reports can retain source paths, line references, and redacted excerpts. Review exported evidence before sharing it; automated redaction is not a guarantee that every sensitive value has been recognized.

Captures retain page content and screenshots without the scanner's redaction pipeline. URLs, query parameters, text, links, form metadata, structured data, and screenshots can contain private information. Capture errors and diagnostic logs can also reveal target details. Do not treat captured data as a sanitized report.

## Sharing, Backup, and Deletion

Localghost does not automatically upload saved history. Exporting files, following source links, or placing the databases in a synced folder can share data outside the application.

- Delete individual scan reports or captures through their history controls. Deleting a scan also removes its related recheck links.
- Deleting history does not delete files you previously exported, terminal logs, or copies retained by backup/sync software.
- For a complete history removal or file-level backup, stop Localghost first. Work only with the intended database and its matching `-wal`/`-shm` files, if present. Do not copy, rename, or delete files belonging to a running database.
- SQLite deletion is not secure erasure. Deleted content may remain recoverable in database pages, filesystem snapshots, or backups.

## Local Access

The supported server commands bind to `127.0.0.1`. Host and Origin checks limit browser access, but they do not authenticate other programs running on your machine. Localghost is intended for a trusted local environment; exposing it through a proxy changes who can access saved data and submit work.

Use only apps and pages you are authorized to inspect. Optional traffic tests generate additional requests and are off in the recommended scan workflow.

## Changes and Questions

This guide should change whenever storage, network behavior, authentication, exports, or deletion behavior changes. Report concerns through [GitHub Issues](https://github.com/qtremors/localghost/issues), with private page content, credentials, and sensitive exports removed.

---

[Back to README](README.md)
