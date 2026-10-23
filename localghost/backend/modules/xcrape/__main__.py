"""Capture independently, or copy an existing capture database into Localghost."""

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

from .settings import load_settings, settings


def import_database(source: Path, destination: Path) -> int:
    """Copy a compatible database without changing the source or overwriting data."""
    source = source.resolve(strict=True)
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)) as original:
        columns = {row[1] for row in original.execute("PRAGMA table_info(jobs)")}
        if not {"id", "url", "status", "data"} <= columns:
            raise ValueError("This file is not a compatible capture database.")
        count = original.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Reserve the destination exclusively. Existing captures must never be replaced.
        with destination.open("xb"):
            pass
        try:
            with closing(sqlite3.connect(destination)) as target:
                original.backup(target)
        except BaseException:
            destination.unlink()
            raise
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Serve Captures in the shared Localghost application")
    serve.add_argument("--port", type=int, help="Port override; otherwise use PORT or 8000")
    capture = commands.add_parser("capture", help="Capture a page without starting the dashboard")
    capture.add_argument("url")
    capture.add_argument("--selector")
    capture.add_argument("--output", type=Path, help="Write JSON to a new file instead of stdout")
    migrate = commands.add_parser("import-db", help="Copy an existing capture database; stop the dashboard first")
    migrate.add_argument("source", type=Path)
    migrate.add_argument("--destination", type=Path)
    args = parser.parse_args()
    try:
        load_settings()
        if args.command == "serve":
            import uvicorn

            port = args.port if args.port is not None else settings.port
            if not 1 <= port <= 65535:
                raise ValueError("Port must be between 1 and 65535.")
            uvicorn.run("backend.main:app", host="127.0.0.1", port=port)
            return 0
        if args.command == "import-db":
            destination = args.destination or settings.database
            count = import_database(args.source, destination)
            print(f"Copied {count} captures to {destination}. Start Localghost to upgrade the copy.")
            return 0
        from .jobs import JobManager
        from .router import ScrapeRequest

        request = ScrapeRequest(url=args.url, selector=args.selector)
        if args.output and args.output.exists():
            raise FileExistsError(f"Output already exists: {args.output}")
        result = JobManager()._execute(0, str(request.url), request.selector)
        content = json.dumps(result, ensure_ascii=True, indent=2)
        if args.output:
            with args.output.open("x", encoding="utf-8") as output:
                output.write(content + "\n")
        else:
            print(content)
        return 1 if result.get("error") else 0
    except (OSError, ValueError, sqlite3.Error, RuntimeError, TimeoutError) as exc:
        parser.exit(2, f"{exc}\n")
    except KeyboardInterrupt:
        return 130


def legacy_main() -> int:
    if len(sys.argv) == 1:
        sys.argv.append("serve")
    return main()


if __name__ == "__main__":
    raise SystemExit(main())
