"""SQLite database for scan history persistence."""

import json
import aiosqlite
import os
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "localghost.db")


async def init_db():
    """Initialize the database and create tables if they don't exist."""
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
        await db.commit()


async def save_scan(scan_id: str, target_url: str, timestamp: str, 
                     score: int, grade: str, results: dict):
    """Save a scan result to the database."""
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
                return {
                    "scan_id": row["scan_id"],
                    "target_url": row["target_url"],
                    "timestamp": row["timestamp"],
                    "score": row["score"],
                    "grade": row["grade"],
                    "results": json.loads(row["results_json"])
                }
            return None


async def get_scan_history(limit: int = 50, offset: int = 0) -> dict:
    """Get paginated scan history."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Get total count
        async with db.execute("SELECT COUNT(*) as cnt FROM scans") as cursor:
            row = await cursor.fetchone()
            total = row["cnt"]

        # Get paginated results
        async with db.execute(
            "SELECT scan_id, target_url, timestamp, score, grade FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            (limit, offset)
        ) as cursor:
            rows = await cursor.fetchall()
            scans = [
                {
                    "scan_id": row["scan_id"],
                    "target": row["target_url"],
                    "timestamp": row["timestamp"],
                    "score": row["score"],
                    "grade": row["grade"]
                }
                for row in rows
            ]

        return {"scans": scans, "total": total}


async def delete_scan(scan_id: str) -> bool:
    """Delete a scan by ID. Returns True if deleted."""
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        await db.commit()
        return cursor.rowcount > 0


async def clear_history():
    """Delete all scan history."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM scans")
        await db.commit()
