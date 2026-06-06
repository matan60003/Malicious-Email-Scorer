from schemas.email import EmailScanRequest, EmailScanResponse
from models.db_models import ScanHistory
from crud.crud_blocklist import get_blocklist_item_by_value
from crud.crud_history import create_scan_history
from services.external_intel import gather_intel
from sqlmodel import Session
import logging

logger = logging.getLogger(__name__)


async def analyze_email(
    request: EmailScanRequest, session: Session = None
) -> EmailScanResponse:
    score = 0
    reasons = []

    # 0. Check Blocklist First
    if session:
        blocked = get_blocklist_item_by_value(session, request.sender.email)
        if not blocked:
            blocked = get_blocklist_item_by_value(session, request.sender.domain)
        
        if blocked:
            final_score = 100
            verdict = "MALICIOUS"
            reasons = ["Sender is on your personal blocklist."]

            # Record history
            history = ScanHistory(
                message_id=request.id,
                sender_email=request.sender.email,
                sender_domain=request.sender.domain,
                subject=request.subject,
                score=final_score,
                verdict=verdict,
            )
            create_scan_history(session, history)

            return EmailScanResponse(
                id=request.id, score=final_score, verdict=verdict, reasons=reasons
            )

    # 1. Gather Threat Intel
    intel_results = await gather_intel(request.urls)
    vt_data = intel_results.get("virustotal", {})
    sb_data = intel_results.get("safebrowsing", {})

    # 2. Rule Evaluation & Weighted Scoring

    # Check VirusTotal Hits
    for url, stats in vt_data.items():
        if "error" in stats:
            continue
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0:
            score += 30 * malicious
            reasons.append(
                f"VirusTotal flagged {malicious} engine(s) as malicious for URL: {url}"
            )
        if suspicious > 0:
            score += 10 * suspicious
            reasons.append(
                f"VirusTotal flagged {suspicious} engine(s) as suspicious for URL: {url}"
            )

    # Check Google Safe Browsing
    matches = sb_data.get("matches", [])
    if matches:
        score += 50
        reasons.append(f"Google Safe Browsing flagged {len(matches)} URL(s).")

    # Authentication Failures
    if request.headers.spf_status != "PASS":
        score += 20
        reasons.append(
            f"SPF check failed or missing (Status: {request.headers.spf_status})."
        )

    if request.headers.dkim_status != "PASS":
        score += 20
        reasons.append(
            f"DKIM check failed or missing (Status: {request.headers.dkim_status})."
        )

    # Content Heuristics
    subject_lower = request.subject.lower()
    suspicious_keywords = [
        "urgent",
        "password",
        "action required",
        "verify your account",
    ]
    found_keywords = [kw for kw in suspicious_keywords if kw in subject_lower]
    if found_keywords:
        score += 15
        reasons.append(
            f"Suspicious keywords found in subject: {', '.join(found_keywords)}."
        )

    # Link Density
    if len(request.urls) > 3:
        score += 10
        reasons.append(f"High link density detected ({len(request.urls)} URLs).")

    # 3. Thresholds & Explanations
    final_score = min(score, 100)

    if final_score >= 70:
        verdict = "MALICIOUS"
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"

    if final_score == 0:
        reasons.append("No suspicious indicators found.")

    # Record Scan History
    if session:
        history = ScanHistory(
            message_id=request.id,
            sender_email=request.sender.email,
            sender_domain=request.sender.domain,
            subject=request.subject,
            score=final_score,
            verdict=verdict,
        )
        create_scan_history(session, history)

    return EmailScanResponse(
        id=request.id, score=final_score, verdict=verdict, reasons=reasons
    )
