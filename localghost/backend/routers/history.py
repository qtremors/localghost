"""Scan history API routes."""

from fastapi import APIRouter, HTTPException, Query
from backend.database.db import get_scan_history, get_scan, delete_scan, clear_history

router = APIRouter(prefix="/api/history", tags=["history"])


@router.get("")
async def list_scans(limit: int = Query(default=50, ge=1, le=200), offset: int = Query(default=0, ge=0)):
    """Get paginated scan history."""
    try:
        return await get_scan_history(limit=limit, offset=offset)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not retrieve history: {str(e)}")


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
