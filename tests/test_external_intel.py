import pytest
import respx
from httpx import Response
import base64
from core.config import settings
from services.external_intel import check_virustotal, check_safe_browsing, gather_intel


@pytest.fixture
def api_keys(monkeypatch):
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "test_vt_key")
    monkeypatch.setattr(settings, "SAFE_BROWSING_API_KEY", "test_sb_key")


@pytest.mark.asyncio
@respx.mock
async def test_check_virustotal(api_keys):
    url = "http://malicious.com"
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    vt_route = respx.get(f"https://www.virustotal.com/api/v3/urls/{url_id}").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 5,
                            "suspicious": 1,
                            "undetected": 10,
                        }
                    }
                }
            },
        )
    )

    result = await check_virustotal(url)
    assert vt_route.called
    assert result.stats.malicious == 5


@pytest.mark.asyncio
@respx.mock
async def test_check_safe_browsing(api_keys):
    urls = ["http://bad.com", "http://good.com"]
    sb_route = respx.post(
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=test_sb_key"
    ).mock(
        return_value=Response(
            200,
            json={
                "matches": [
                    {"threatType": "MALWARE", "threat": {"url": "http://bad.com"}}
                ]
            },
        )
    )

    result = await check_safe_browsing(urls)
    assert sb_route.called
    assert len(result.matches) == 1
    assert result.matches[0]["threat"]["url"] == "http://bad.com"


@pytest.mark.asyncio
@respx.mock
async def test_gather_intel(api_keys):
    # Mock both
    respx.get(url__regex=r"https://www.virustotal.com/api/v3/urls/.*").mock(
        return_value=Response(
            200,
            json={"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}},
        )
    )
    respx.post(
        url__regex=r"https://safebrowsing.googleapis.com/v4/threatMatches:find.*"
    ).mock(return_value=Response(200, json={"matches": []}))

    urls = ["http://test.com"]
    result = await gather_intel(urls)

    assert result.virustotal
    assert result.safebrowsing
    assert result.virustotal["http://test.com"].stats.malicious == 1
