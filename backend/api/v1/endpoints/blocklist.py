from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from api.dependencies import get_session
from models.db_models import Blocklist
from crud.crud_blocklist import (
    get_blocklist,
    get_blocklist_item_by_value,
    create_blocklist_item,
)
from typing import List

router = APIRouter()


@router.post("/", response_model=Blocklist)
def add_to_blocklist(
    blocklist_item: Blocklist, session: Session = Depends(get_session)
):
    # Check if exists
    existing = get_blocklist_item_by_value(session, blocklist_item.value)
    if existing:
        raise HTTPException(status_code=400, detail="Item already in blocklist")

    return create_blocklist_item(session, blocklist_item)


@router.get("/", response_model=List[Blocklist])
def read_blocklist(session: Session = Depends(get_session)):
    return get_blocklist(session)
