from sqlmodel import SQLModel, Field, Column, JSON
from typing import Optional, List
from datetime import datetime


class Blocklist(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    value: str = Field(
        index=True, unique=True, description="The email or domain to block"
    )
    type: str = Field(description="'email' or 'domain'")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanHistory(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    message_id: str = Field(index=True, description="Unique ID of the email")
    sender_email: str
    sender_domain: str
    subject: str
    score: int
    verdict: str
    reasons: List[str] = Field(default_factory=list, sa_column=Column(JSON))
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
