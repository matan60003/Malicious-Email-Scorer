from fastapi import APIRouter, Depends
from sqlmodel import Session
from api.dependencies import get_session
from schemas.email import EmailScanRequest, EmailScanResponse
from services.scanner import analyze_email

router = APIRouter()


@router.post("/scan", response_model=EmailScanResponse)
async def scan_email(
    request: EmailScanRequest, session: Session = Depends(get_session)
):
    return await analyze_email(request, session)
