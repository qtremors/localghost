"""HTTP adapter for the shared individual recheck service."""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.database.db import get_scan
from backend.models.scan import ScanSession
from backend.services.admission import workload_lock
from backend.services.rechecks import perform_recheck

router = APIRouter(prefix='/api/history', tags=['rechecks'])


class RecheckRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    session: ScanSession | None = Field(default=None, repr=False)


@router.post('/{scan_id}/findings/{finding_id}/recheck')
async def recheck(scan_id: str, finding_id: str, body: RecheckRequest):
    stored = await get_scan(scan_id)
    if not stored:
        raise HTTPException(404, 'Report not found')
    if workload_lock.locked():
        raise HTTPException(429, 'Another scan is running. Wait for it to finish.')
    async with workload_lock:
        try:
            result = await perform_recheck(stored['results'], finding_id, body.session)
            result.pop('report')
            return result
        except ValidationError:
            raise HTTPException(422, 'Recheck settings are invalid. Run a new scan or supply the original session configuration.') from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
