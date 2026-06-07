from sqlmodel import Session, select
from orm.db_models import Blocklist
from typing import List, Optional


def get_blocklist_item_by_value(session: Session, value: str) -> Optional[Blocklist]:
    statement = select(Blocklist).where(Blocklist.value == value)
    return session.exec(statement).first()


def get_blocklist(session: Session) -> List[Blocklist]:
    statement = select(Blocklist)
    return session.exec(statement).all()


def create_blocklist_item(session: Session, blocklist_item: Blocklist) -> Blocklist:
    session.add(blocklist_item)
    session.commit()
    session.refresh(blocklist_item)
    return blocklist_item
