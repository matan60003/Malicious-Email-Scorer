from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional

class EmailSender(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    domain: str

class EmailHeaders(BaseModel):
    spf_status: Optional[str] = Field(None, description="SPF verification status")
    dkim_status: Optional[str] = Field(None, description="DKIM verification status")
    dmarc_status: Optional[str] = Field(None, description="DMARC verification status")

class EmailScanRequest(BaseModel):
    id: str = Field(..., description="Unique identifier for the email")
    sender: EmailSender
    subject: str
    body_text: str
    urls: List[str] = Field(default_factory=list)
    headers: EmailHeaders

class EmailScanResponse(BaseModel):
    id: str
    score: int = Field(..., ge=0, le=100, description="Maliciousness score from 0 to 100")
    verdict: str = Field(..., description="E.g., SAFE, SUSPICIOUS, MALICIOUS")
    reasons: List[str] = Field(default_factory=list, description="List of reasons for the score")
