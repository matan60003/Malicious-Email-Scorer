from fastapi import APIRouter, Depends
from sqlmodel import Session
from core.database import get_session
from models.schemas import EmailScanRequest, EmailScanResponse
from services.analyzer import analyze_email

router = APIRouter()


@router.post("/scan", response_model=EmailScanResponse)
async def scan_email(
    request: EmailScanRequest, session: Session = Depends(get_session)
):
    return await analyze_email(request, session)
