"""SQLite database for scan history persistence."""

import json
import os
from pathlib import Path
from typing import Optional

import aiosqlite

from backend.services.projects import project_origin
from backend.utils.paths import data_path
from backend.utils.privacy import redact_cookie_values

DB_PATH = os.getenv('LOCALGHOST_DB_PATH', str(data_path("localghost.db")))
SUMMARY_COLUMNS = """scan_id, target_url, timestamp, score, grade,
    CASE WHEN json_valid(results_json) THEN json_extract(results_json, '$.score.coverage') END AS coverage,
    CASE WHEN json_valid(results_json) THEN json_extract(results_json, '$.status') END AS status,
    CASE WHEN json_valid(results_json) THEN json_extract(results_json, '$.summary.confirmed') END AS confirmed,
    CASE WHEN json_valid(results_json) THEN json_extract(results_json, '$.summary.review') END AS review,
    CASE WHEN json_valid(results_json) THEN json_extract(results_json, '$.summary.incomplete') END AS incomplete,
    CASE WHEN json_valid(results_json) THEN COALESCE(json_extract(results_json, '$.source_scan.name'), json_extract(results_json, '$.recheck_of.project_name')) END AS project_name"""


def _summary(row):
    return {'scan_id': row['scan_id'], 'target': row['target_url'], 'timestamp': row['timestamp'],
            'score': row['score'], 'grade': row['grade'], 'coverage': row['coverage'], 'status': row['status'],
            'confirmed': row['confirmed'], 'review': row['review'], 'incomplete': row['incomplete'], 'project_name': row['project_name']}


async def init_db():
    """Initialize the database and create tables if they don't exist."""
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target_url TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                score INTEGER DEFAULT 0,
                grade TEXT DEFAULT 'F',
                results_json TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_timestamp 
            ON scans(timestamp DESC)
        """)
        await db.execute('''CREATE TABLE IF NOT EXISTS rechecks (
            original_scan_id TEXT NOT NULL, finding_id TEXT NOT NULL, scan_id TEXT NOT NULL,
            state TEXT NOT NULL, timestamp TEXT NOT NULL,
            PRIMARY KEY (original_scan_id, finding_id, scan_id)
        )''')
        async with db.execute('PRAGMA user_version') as cursor:
            version = (await cursor.fetchone())[0]
        if version < 1:
            # Earlier versions stored cookie prefixes. Remove them once, including
            # from old reports, without deleting report metadata or findings.
            async with db.execute('SELECT scan_id, results_json FROM scans') as cursor:
                async for scan_id, encoded in cursor:
                    try:
                        report = json.loads(encoded)
                    except ValueError:
                        continue
                    if redact_cookie_values(report):
                        await db.execute('UPDATE scans SET results_json = ? WHERE scan_id = ?', (json.dumps(report), scan_id))
            await db.execute('PRAGMA user_version = 1')
        await db.commit()


async def save_scan(scan_id: str, target_url: str, timestamp: str, 
                     score: int, grade: str, results: dict):
    """Save a scan result to the database."""
    redact_cookie_values(results)
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO scans (scan_id, target_url, timestamp, score, grade, results_json) VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, target_url, timestamp, score, grade, json.dumps(results))
        )
        await db.commit()


async def get_scan(scan_id: str) -> Optional[dict]:
    """Retrieve a specific scan by ID."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                results = json.loads(row["results_json"])
                redact_cookie_values(results)
                async with db.execute('SELECT finding_id, scan_id, state, timestamp FROM rechecks WHERE original_scan_id = ? ORDER BY timestamp', (scan_id,)) as recheck_cursor:
                    rechecks = await recheck_cursor.fetchall()
                if rechecks:
                    results['rechecks'] = [dict(item) for item in rechecks]
                return {
                    "scan_id": row["scan_id"],
                    "target_url": row["target_url"],
                    "timestamp": row["timestamp"],
                    "score": row["score"],
                    "grade": row["grade"],
                    "results": results
                }
            return None


async def get_scan_history(limit: int = 50, offset: int = 0, query: str = "", target: str | None = None) -> dict:
    """Get paginated scan history."""
    filters, values = [], []
    if query.strip():
        # Treat SQL LIKE metacharacters as literal search text.
        escaped = query.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        filters.append("target_url LIKE ? ESCAPE '\\'")
        values.append(f"%{escaped}%")
    if target is not None:
        filters.append("target_url = ?")
        values.append(target)
    where = " WHERE " + " AND ".join(filters) if filters else ""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get total count
        async with db.execute("SELECT COUNT(*) as cnt FROM scans" + where, values) as cursor:
            row = await cursor.fetchone()
            total = row["cnt"]

        # Get paginated results
        async with db.execute(
            "SELECT " + SUMMARY_COLUMNS + " FROM scans" + where + " ORDER BY timestamp DESC, scan_id DESC LIMIT ? OFFSET ?",
            [*values, limit, offset]
        ) as cursor:
            rows = await cursor.fetchall()
            scans = [_summary(row) for row in rows]

        return {"scans": scans, "total": total}


async def get_project_history(limit=24, offset=0):
    """Return one page of projects instead of sending every past report to the UI."""
    async with aiosqlite.connect(DB_PATH) as connection:
        connection.row_factory = aiosqlite.Row
        await connection.create_function('project_origin', 1, project_origin, deterministic=True)
        async with connection.execute('SELECT COUNT(*) AS reports, COUNT(DISTINCT project_origin(target_url)) AS projects, MAX(timestamp) AS latest FROM scans') as cursor:
            totals = await cursor.fetchone()
        query = f"""WITH grouped AS (
            SELECT scan_id, project_origin(target_url) AS origin,
                COUNT(*) OVER (PARTITION BY project_origin(target_url)) AS reports,
                ROW_NUMBER() OVER (PARTITION BY project_origin(target_url) ORDER BY timestamp DESC, scan_id DESC) AS position
            FROM scans
        ) SELECT {SUMMARY_COLUMNS}, origin, reports FROM grouped JOIN scans USING (scan_id)
          WHERE position = 1 ORDER BY timestamp DESC, scan_id DESC LIMIT ? OFFSET ?"""
        async with connection.execute(query, (limit, offset)) as cursor:
            rows = await cursor.fetchall()
        projects = [
            {'key': row['origin'], 'origin': row['origin'], 'name': row['project_name'] or row['origin'].split('://', 1)[-1],
             'latest': _summary(row), 'reports': row['reports']}
            for row in rows
        ]
        return {'projects': projects, 'total_projects': totals['projects'], 'total_reports': totals['reports'],
                'latest_timestamp': totals['latest']}


async def delete_scan(scan_id: str) -> bool:
    """Delete a scan by ID. Returns True if deleted."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        await db.execute('DELETE FROM rechecks WHERE original_scan_id = ? OR scan_id = ?', (scan_id, scan_id))
        await db.commit()
        return cursor.rowcount > 0


async def clear_history():
    """Delete all scan history."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM scans")
        await db.execute('DELETE FROM rechecks')
        await db.commit()


async def save_recheck(original_scan_id, finding_id, scan_id, state, timestamp):
    async with aiosqlite.connect(DB_PATH) as connection:
        await connection.execute('INSERT INTO rechecks VALUES (?, ?, ?, ?, ?)', (original_scan_id, finding_id, scan_id, state, timestamp))
        await connection.commit()
