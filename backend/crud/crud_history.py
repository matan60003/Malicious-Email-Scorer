from sqlmodel import Session, select
from models.db_models import ScanHistory
from typing import List


def get_scan_history(session: Session, limit: int = 50) -> List[ScanHistory]:
    statement = select(ScanHistory).order_by(ScanHistory.scanned_at.desc()).limit(limit)
    return session.exec(statement).all()


def create_scan_history(session: Session, history_item: ScanHistory) -> ScanHistory:
    session.add(history_item)
    session.commit()
    session.refresh(history_item)
    return history_item
