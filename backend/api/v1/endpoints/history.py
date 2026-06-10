from fastapi import APIRouter, Depends
from sqlmodel import Session
from api.dependencies import get_session
from schemas.history import ScanHistoryResponse
from repositories.history import get_scan_history
from typing import List

router = APIRouter()


@router.get("", response_model=List[ScanHistoryResponse])
def read_scan_history(session: Session = Depends(get_session), limit: int = 50):
    return get_scan_history(session, limit=limit)
