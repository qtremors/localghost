"""Scan API routes."""

from fastapi import APIRouter, HTTPException
from backend.models.scan import ScanRequest, ScanResponse
from backend.services.scanner import execute_scan

router = APIRouter(prefix="/api", tags=["scan"])


@router.post("/scan", response_model=ScanResponse)
async def perform_scan(request: ScanRequest):
    """Execute a full multi-module security scan."""
    try:
        result = await execute_scan(request)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
