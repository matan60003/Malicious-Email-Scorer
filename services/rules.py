from abc import ABC, abstractmethod
from typing import Tuple, Optional
from schemas.email import EmailScanRequest
from schemas.intel import IntelResult

class ScoringRule(ABC):
    @abstractmethod
    def evaluate(self, request: EmailScanRequest, intel: IntelResult) -> Tuple[int, Optional[str]]:
        """
        Evaluates a specific rule against the email request and intelligence results.
        Returns a tuple of (score_to_add, reason_string).
        If the rule doesn't trigger, return (0, None).
        """
        pass

class VirusTotalRule(ScoringRule):
    def evaluate(self, request: EmailScanRequest, intel: IntelResult) -> Tuple[int, Optional[str]]:
        score = 0
        reasons = []
        for url, vt_result in intel.virustotal.items():
            if vt_result.error or not vt_result.stats:
                continue
            malicious = vt_result.stats.malicious
            suspicious = vt_result.stats.suspicious

            if malicious > 0:
                score += 30 * malicious
                reasons.append(f"VirusTotal flagged {malicious} engine(s) as malicious for URL: {url}")
            if suspicious > 0:
                score += 10 * suspicious
                reasons.append(f"VirusTotal flagged {suspicious} engine(s) as suspicious for URL: {url}")
        
        return score, " | ".join(reasons) if reasons else None

class SafeBrowsingRule(ScoringRule):
    def evaluate(self, request: EmailScanRequest, intel: IntelResult) -> Tuple[int, Optional[str]]:
        if intel.safebrowsing.error:
            return 0, None
        matches = intel.safebrowsing.matches
        if matches:
            return 50, f"Google Safe Browsing flagged {len(matches)} URL(s)."
        return 0, None

class AuthenticationRule(ScoringRule):
    def evaluate(self, request: EmailScanRequest, intel: IntelResult) -> Tuple[int, Optional[str]]:
        score = 0
        reasons = []
        if request.headers.spf_status != "PASS":
            score += 20
            reasons.append(f"SPF check failed or missing (Status: {request.headers.spf_status}).")
        
        if request.headers.dkim_status != "PASS":
            score += 20
            reasons.append(f"DKIM check failed or missing (Status: {request.headers.dkim_status}).")
            
        return score, " | ".join(reasons) if reasons else None

class KeywordRule(ScoringRule):
    def evaluate(self, request: EmailScanRequest, intel: IntelResult) -> Tuple[int, Optional[str]]:
        subject_lower = request.subject.lower()
        suspicious_keywords = [
            "urgent",
            "password",
            "action required",
            "verify your account",
        ]
        found_keywords = [kw for kw in suspicious_keywords if kw in subject_lower]
        if found_keywords:
            return 15, f"Suspicious keywords found in subject: {', '.join(found_keywords)}."
        return 0, None

class LinkDensityRule(ScoringRule):
    def evaluate(self, request: EmailScanRequest, intel: IntelResult) -> Tuple[int, Optional[str]]:
        if len(request.urls) > 3:
            return 10, f"High link density detected ({len(request.urls)} URLs)."
        return 0, None
