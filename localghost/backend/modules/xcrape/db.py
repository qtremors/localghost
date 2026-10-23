"""SQLite persistence, compatible with databases from earlier versions."""

import json
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite

from .settings import settings

DB_PATH = None
STATUSES = ("pending", "running", "completed", "failed")


@asynccontextmanager
async def connection():
    async with aiosqlite.connect(DB_PATH if DB_PATH is not None else settings.database, timeout=30) as db:
        db.row_factory = aiosqlite.Row
        yield db


async def init_db() -> None:
    Path(DB_PATH if DB_PATH is not None else settings.database).parent.mkdir(parents=True, exist_ok=True)
    async with connection() as db:
        await db.execute("PRAGMA journal_mode=WAL")
        await db.execute("""CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL, status TEXT NOT NULL, data TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            selector TEXT, title TEXT, finished_at TEXT, http_status INTEGER
        )""")
        cursor = await db.execute("PRAGMA table_info(jobs)")
        columns = {row["name"] for row in await cursor.fetchall()}
        # SQLite cannot add a CURRENT_TIMESTAMP default to a populated table.
        for name, kind in {
            "created_at": "TEXT",
            "selector": "TEXT",
            "title": "TEXT",
            "finished_at": "TEXT",
            "http_status": "INTEGER",
        }.items():
            if name not in columns:
                await db.execute(f"ALTER TABLE jobs ADD COLUMN {name} {kind}")
        if "title" not in columns:
            # Backfill once, one record at a time, so old titles are searchable too.
            cursor = await db.execute("SELECT id, data FROM jobs WHERE data IS NOT NULL")
            async for row in cursor:
                try:
                    saved = json.loads(row["data"])
                    meta = saved.get("meta", {}) if isinstance(saved, dict) else {}
                    title = meta.get("title") if isinstance(meta, dict) else None
                    http_status = meta.get("http_status") if isinstance(meta, dict) else None
                    if isinstance(title, str):
                        await db.execute(
                            "UPDATE jobs SET title=?, http_status=? WHERE id=?",
                            (
                                title[:500],
                                http_status if isinstance(http_status, int) else None,
                                row["id"],
                            ),
                        )
                except (TypeError, ValueError, RecursionError):
                    continue
        await db.execute("UPDATE jobs SET created_at = CURRENT_TIMESTAMP WHERE created_at IS NULL")
        await db.execute("CREATE INDEX IF NOT EXISTS jobs_status ON jobs(status)")
        await db.commit()


async def recover_interrupted() -> None:
    error = json.dumps(
        {
            "error": "This capture was interrupted when the app stopped. Try again.",
            "error_type": "Interrupted",
        }
    )
    async with connection() as db:
        await db.execute(
            """UPDATE jobs SET status='failed', data=?, finished_at=CURRENT_TIMESTAMP
                            WHERE status IN ('pending', 'running')""",
            (error,),
        )
        await db.commit()


async def create_job(url: str, selector: str | None = None) -> int:
    async with connection() as db:
        cursor = await db.execute(
            """INSERT INTO jobs (url, selector, status, created_at)
                                     VALUES (?, ?, 'pending', CURRENT_TIMESTAMP)""",
            (url, selector),
        )
        await db.commit()
        return cursor.lastrowid


async def update_job(job_id: int, status: str, data: dict | None = None) -> None:
    if status not in STATUSES:
        raise ValueError("Unknown job status")
    meta = (data or {}).get("meta", {})
    async with connection() as db:
        await db.execute(
            """UPDATE jobs SET status=?, data=?, title=COALESCE(?, title),
                            http_status=?, finished_at=CASE WHEN ? IN ('completed','failed')
                            THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id=?""",
            (
                status,
                json.dumps(data) if data is not None else None,
                meta.get("title"),
                meta.get("http_status"),
                status,
                job_id,
            ),
        )
        await db.commit()


async def get_jobs(page: int = 1, page_size: int = 20, q: str = "", status: str | None = None) -> dict:
    clauses, values = [], []
    if q:
        clauses.append("(instr(lower(url), lower(?)) > 0 OR instr(lower(COALESCE(title,'')), lower(?)) > 0)")
        values.extend([q, q])
    if status:
        clauses.append("status = ?")
        values.append(status)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    async with connection() as db:
        await db.execute("BEGIN")
        cursor = await db.execute("SELECT COUNT(*) FROM jobs" + where, values)
        total = (await cursor.fetchone())[0]
        cursor = await db.execute(
            """SELECT id, url, selector, status, title, created_at,
                                    finished_at, http_status, data IS NOT NULL AS has_data FROM jobs"""
            + where
            + " ORDER BY id DESC LIMIT ? OFFSET ?",
            [*values, page_size, (page - 1) * page_size],
        )
        jobs = [dict(row) for row in await cursor.fetchall()]
        cursor = await db.execute("SELECT status, COUNT(*) AS n FROM jobs GROUP BY status")
        counts = dict.fromkeys(STATUSES, 0)
        counts.update({row["status"]: row["n"] for row in await cursor.fetchall()})
    return {"jobs": jobs, "total": total, "page": page, "page_size": page_size, "counts": counts}


async def get_job(job_id: int) -> dict | None:
    async with connection() as db:
        cursor = await db.execute("SELECT * FROM jobs WHERE id=?", (job_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None


async def delete_job(job_id: int) -> bool:
    async with connection() as db:
        cursor = await db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        await db.commit()
        return cursor.rowcount > 0
