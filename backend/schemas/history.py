from pydantic import BaseModel, ConfigDict
from typing import List
from datetime import datetime


class ScanHistoryResponse(BaseModel):
    id: int
    message_id: str
    sender_email: str
    sender_domain: str
    subject: str
    score: int
    verdict: str
    reasons: List[str]
    scanned_at: datetime

    model_config = ConfigDict(from_attributes=True)
