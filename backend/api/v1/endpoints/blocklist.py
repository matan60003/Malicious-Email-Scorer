from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from api.dependencies import get_session
from orm.db_models import Blocklist
from schemas.blocklist import BlocklistCreate, BlocklistResponse
from repositories.blocklist import (
    get_blocklist,
    get_blocklist_item_by_value,
    create_blocklist_item,
)
from typing import List

router = APIRouter()


@router.post("", response_model=BlocklistResponse)
def add_to_blocklist(
    blocklist_item: BlocklistCreate, session: Session = Depends(get_session)
):
    # Check if exists
    existing = get_blocklist_item_by_value(session, blocklist_item.value)
    if existing:
        raise HTTPException(status_code=400, detail="Item already in blocklist")

    db_item = Blocklist(**blocklist_item.model_dump())
    return create_blocklist_item(session, db_item)


@router.get("", response_model=List[BlocklistResponse])
def read_blocklist(session: Session = Depends(get_session)):
    return get_blocklist(session)
