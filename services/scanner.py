from schemas.email import EmailScanRequest, EmailScanResponse
from models.db_models import ScanHistory
from crud.crud_blocklist import get_blocklist_item_by_value
from crud.crud_history import create_scan_history
from services.external_intel import gather_intel
from services.rules import (
    VirusTotalRule,
    SafeBrowsingRule,
    AuthenticationRule,
    KeywordRule,
    LinkDensityRule,
)
from sqlmodel import Session
import structlog

logger = structlog.get_logger(__name__)

# Register all active rules in the engine
ACTIVE_RULES = [
    VirusTotalRule(),
    SafeBrowsingRule(),
    AuthenticationRule(),
    KeywordRule(),
    LinkDensityRule(),
]


async def analyze_email(
    request: EmailScanRequest, session: Session = None
) -> EmailScanResponse:
    try:
        score = 0
        reasons = []

        # 1. Check Blocklist First
        if session:
            blocked = get_blocklist_item_by_value(session, request.sender.email)
            if not blocked:
                blocked = get_blocklist_item_by_value(session, request.sender.domain)

            if blocked:
                final_score = 999
                verdict = "MALICIOUS"
                reasons = ["Sender is on your personal blocklist."]

                # Record history
                _record_scan_history(session, request, final_score, verdict)
                return EmailScanResponse(
                    id=request.id, score=final_score, verdict=verdict, reasons=reasons
                )

        # 2. Gather Threat Intel
        intel_results = await gather_intel(request.urls)

        # 3. Rule Evaluation & Weighted Scoring
        for rule in ACTIVE_RULES:
            rule_score, rule_reason = rule.evaluate(request, intel_results)
            if rule_score > 0:
                score += rule_score
            if rule_reason:
                reasons.append(rule_reason)

        # 4. Thresholds & Explanations
        final_score = score

        if final_score >= 100:
            verdict = "MALICIOUS"
        elif final_score >= 50:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"

        if final_score == 0:
            reasons.append("No suspicious indicators found.")

        # Record Scan History
        _record_scan_history(session, request, final_score, verdict)

        return EmailScanResponse(
            id=request.id, score=final_score, verdict=verdict, reasons=reasons
        )
    except Exception as e:
        logger.error(f"Unexpected error in analyze_email: {e}", exc_info=True)
        return EmailScanResponse(
            id=request.id,
            score=-1,
            verdict="ERROR",
            reasons=[f"Internal Server Error: {str(e)}"],
        )


def _record_scan_history(
    session: Session, request: EmailScanRequest, final_score: int, verdict: str
):
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
