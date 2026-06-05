from fastapi import APIRouter
from models.schemas import EmailScanRequest, EmailScanResponse
from services.analyzer import analyze_email

router = APIRouter()


@router.post("/scan", response_model=EmailScanResponse)
async def scan_email(request: EmailScanRequest):
    return await analyze_email(request)
