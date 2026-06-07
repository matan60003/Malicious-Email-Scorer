from pydantic import BaseModel, Field, EmailStr, HttpUrl
from typing import List, Optional


class EmailSender(BaseModel):
    email: EmailStr
    name: Optional[str] = None
    domain: str


class EmailAuthentication(BaseModel):
    spf_status: Optional[str] = Field(None, description="SPF verification status")
    dkim_status: Optional[str] = Field(None, description="DKIM verification status")
    dmarc_status: Optional[str] = Field(None, description="DMARC verification status")


class EmailScanRequest(BaseModel):
    id: str = Field(..., description="Unique identifier for the email")
    sender: EmailSender
    subject: str
    body_text: str
    urls: List[HttpUrl] = Field(default_factory=list)
    authentication: EmailAuthentication


class EmailScanResponse(BaseModel):
    id: str
    score: int = Field(
        ..., description="Unbounded maliciousness score. -1 indicates an error."
    )
    verdict: str = Field(..., description="E.g., SAFE, SUSPICIOUS, MALICIOUS")
    reasons: List[str] = Field(
        default_factory=list, description="List of reasons for the score"
    )
