"""Report export API routes."""

import json
from fastapi import APIRouter, HTTPException
from fastapi.responses import Response
from backend.database.db import get_scan

router = APIRouter(prefix="/api/report", tags=["report"])


@router.get("/{scan_id}")
async def download_report(scan_id: str):
    """Download a scan report as a pretty-printed JSON file."""
    result = await get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Pretty-print with indent=2 for readability
    formatted_json = json.dumps(result["results"], indent=2, ensure_ascii=False)

    return Response(
        content=formatted_json,
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="localghost_report_{scan_id}.json"',
        }
    )

