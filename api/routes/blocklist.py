from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from core.database import get_session
from models.db_models import Blocklist
from typing import List

router = APIRouter()


@router.post("/", response_model=Blocklist)
def add_to_blocklist(
    blocklist_item: Blocklist, session: Session = Depends(get_session)
):
    # Check if exists
    statement = select(Blocklist).where(Blocklist.value == blocklist_item.value)
    existing = session.exec(statement).first()
    if existing:
        raise HTTPException(status_code=400, detail="Item already in blocklist")

    session.add(blocklist_item)
    session.commit()
    session.refresh(blocklist_item)
    return blocklist_item


@router.get("/", response_model=List[Blocklist])
def get_blocklist(session: Session = Depends(get_session)):
    statement = select(Blocklist)
    results = session.exec(statement).all()
    return results
