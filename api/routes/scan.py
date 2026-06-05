from fastapi import APIRouter
from models.schemas import EmailScanRequest, EmailScanResponse

router = APIRouter()

@router.post("/scan", response_model=EmailScanResponse)
async def scan_email(request: EmailScanRequest):
    # Mock logic for PR 1
    score = 0
    reasons = []
    
    if "urgent" in request.subject.lower() or "password" in request.subject.lower():
        score += 30
        reasons.append("Suspicious keywords in subject.")
        
    if request.headers.spf_status != "PASS":
        score += 40
        reasons.append("SPF check failed or missing.")
        
    if len(request.urls) > 3:
        score += 20
        reasons.append("Contains multiple URLs.")
        
    verdict = "SAFE"
    if score >= 70:
        verdict = "MALICIOUS"
    elif score >= 30:
        verdict = "SUSPICIOUS"
        
    return EmailScanResponse(
        id=request.id,
        score=min(score, 100),
        verdict=verdict,
        reasons=reasons
    )
