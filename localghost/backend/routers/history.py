"""Scan history API routes."""

import logging

from fastapi import APIRouter, HTTPException, Query

from backend.database.db import clear_history, delete_scan, get_scan, get_scan_history
from backend.services.comparison import compare_scans

router = APIRouter(prefix="/api/history", tags=["history"])
logger = logging.getLogger(__name__)


@router.get("")
async def list_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    q: str = Query(default="", max_length=200),
    target: str | None = Query(default=None, max_length=2048),
):
    """Get paginated scan history."""
    try:
        return await get_scan_history(limit=limit, offset=offset, query=q, target=target)
    except Exception as exc:
        logger.exception("Could not retrieve history")
        raise HTTPException(status_code=500, detail="Could not retrieve history. Try again.") from exc


@router.get("/{scan_id}/comparison/{baseline_id}")
async def compare_history(scan_id: str, baseline_id: str):
    """Compare saved reports without calling untested modules resolved."""
    current = await get_scan(scan_id)
    baseline = await get_scan(baseline_id)
    if current is None or baseline is None:
        raise HTTPException(status_code=404, detail="One of the reports no longer exists. Refresh history and try again.")
    try:
        return compare_scans(baseline["results"], current["results"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/{scan_id}")
async def get_scan_detail(scan_id: str):
    """Get a specific scan result by ID."""
    result = await get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@router.delete("/{scan_id}")
async def delete_scan_entry(scan_id: str):
    """Delete a specific scan from history."""
    deleted = await delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"status": "deleted", "scan_id": scan_id}


@router.delete("")
async def clear_all_history():
    """Clear all scan history."""
    await clear_history()
    return {"status": "cleared"}
