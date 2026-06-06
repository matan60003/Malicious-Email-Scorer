from fastapi import APIRouter, Depends
from sqlmodel import Session
from api.dependencies import get_session
from models.db_models import ScanHistory
from crud.crud_history import get_scan_history
from typing import List

router = APIRouter()


@router.get("/", response_model=List[ScanHistory])
def read_scan_history(session: Session = Depends(get_session), limit: int = 50):
    return get_scan_history(session, limit=limit)
