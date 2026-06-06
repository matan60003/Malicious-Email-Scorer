from fastapi import APIRouter, Depends
from sqlmodel import Session, select
from core.database import get_session
from models.db_models import ScanHistory
from typing import List

router = APIRouter()


@router.get("/", response_model=List[ScanHistory])
def get_scan_history(session: Session = Depends(get_session), limit: int = 50):
    statement = select(ScanHistory).order_by(ScanHistory.scanned_at.desc()).limit(limit)
    results = session.exec(statement).all()
    return results
