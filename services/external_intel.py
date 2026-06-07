import asyncio
import base64
from typing import List
import structlog
from core.config import settings
from core.http_client import get_client
from schemas.intel import IntelResult, VTResult, VTStats, SBResult

logger = structlog.get_logger(__name__)

# Limit concurrent requests to VirusTotal to avoid rate limits
vt_semaphore = asyncio.Semaphore(5)


async def check_virustotal(url: str) -> VTResult:
    if not settings.VIRUSTOTAL_API_KEY:
        logger.warning(
            "VIRUSTOTAL_API_KEY not configured. Returning mock safe response."
        )
        return VTResult(stats=VTStats(undetected=1))

    # VirusTotal v3 requires the URL to be base64 encoded without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
    }

    client = get_client()
    try:
        async with vt_semaphore:
            response = await client.get(api_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats_dict = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return VTResult(stats=VTStats(**stats_dict))
        elif response.status_code == 404:
            return VTResult(error="URL not found in VirusTotal")
        else:
            logger.error(
                f"VirusTotal API error: {response.status_code} - {response.text}"
            )
            return VTResult(error=f"API returned {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to reach VirusTotal: {e}")
        return VTResult(error=str(e))


async def check_safe_browsing(urls: List[str]) -> SBResult:
    if not settings.SAFE_BROWSING_API_KEY:
        logger.warning(
            "SAFE_BROWSING_API_KEY not configured. Returning mock safe response."
        )
        return SBResult(matches=[])

    if not urls:
        return SBResult(matches=[])

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={settings.SAFE_BROWSING_API_KEY}"

    payload = {
        "client": {"clientId": "malicious-email-scorer", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }

    client = get_client()
    try:
        response = await client.post(api_url, json=payload)

        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            return SBResult(matches=matches)
        else:
            logger.error(
                f"Safe Browsing API error: {response.status_code} - {response.text}"
            )
            return SBResult(error=f"API returned {response.status_code}")
    except Exception as e:
        logger.error(f"Failed to reach Safe Browsing: {e}")
        return SBResult(error=str(e))


async def gather_intel(urls: List[str]) -> IntelResult:
    if not urls:
        return IntelResult()

    vt_tasks = [check_virustotal(url) for url in urls]
    sb_task = check_safe_browsing(urls)

    results = await asyncio.gather(*vt_tasks, sb_task)

    vt_results = {url: res for url, res in zip(urls, results[:-1])}
    sb_results = results[-1]

    return IntelResult(virustotal=vt_results, safebrowsing=sb_results)
