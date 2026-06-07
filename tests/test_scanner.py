import pytest
from unittest.mock import patch, AsyncMock
from schemas.email import EmailScanRequest, EmailSender, EmailHeaders
from schemas.intel import IntelResult, VTResult, VTStats, SBResult
from services.scanner import analyze_email


@pytest.fixture
def base_request():
    return EmailScanRequest(
        id="test_id",
        sender=EmailSender(email="test@test.com", domain="test.com"),
        subject="Normal subject",
        body_text="Normal body",
        urls=[],
        headers=EmailHeaders(spf_status="PASS", dkim_status="PASS"),
    )


@pytest.mark.asyncio
@patch("services.scanner.gather_intel", new_callable=AsyncMock)
async def test_analyzer_safe(mock_gather, base_request):
    mock_gather.return_value = IntelResult()
    response = await analyze_email(base_request)
    assert response.score == 0
    assert response.verdict == "SAFE"


@pytest.mark.asyncio
@patch("services.scanner.gather_intel", new_callable=AsyncMock)
async def test_analyzer_malicious_vt(mock_gather, base_request):
    mock_gather.return_value = IntelResult(
        virustotal={
            "http://bad.com": VTResult(stats=VTStats(malicious=2, suspicious=1))
        }
    )
    base_request.urls = ["http://bad.com"]
    response = await analyze_email(base_request)
    # malicious: 2 * 30 = 60
    # suspicious: 1 * 10 = 10
    # total = 70 -> MALICIOUS
    assert response.score == 70
    assert response.verdict == "MALICIOUS"


@pytest.mark.asyncio
@patch("services.scanner.gather_intel", new_callable=AsyncMock)
async def test_analyzer_safebrowsing(mock_gather, base_request):
    mock_gather.return_value = IntelResult(
        safebrowsing=SBResult(matches=[{"threatType": "MALWARE"}])
    )
    base_request.urls = ["http://bad.com"]
    response = await analyze_email(base_request)
    assert response.score == 50
    assert response.verdict == "SUSPICIOUS"


@pytest.mark.asyncio
@patch("services.scanner.gather_intel", new_callable=AsyncMock)
async def test_analyzer_cap_at_100(mock_gather, base_request):
    mock_gather.return_value = IntelResult(
        virustotal={"http://bad.com": VTResult(stats=VTStats(malicious=10))},
        safebrowsing=SBResult(matches=[{"threatType": "MALWARE"}]),
    )
    base_request.urls = ["http://bad.com"]
    base_request.subject = "Urgent password action required"  # 15
    base_request.headers.spf_status = "FAIL"  # 20

    response = await analyze_email(base_request)
    assert response.score == 100
    assert response.verdict == "MALICIOUS"
