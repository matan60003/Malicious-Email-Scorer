import httpx
import asyncio
import base64
from typing import List, Dict, Any
import logging
from core.config import settings

logger = logging.getLogger(__name__)


async def check_virustotal(url: str) -> Dict[str, Any]:
    if not settings.VIRUSTOTAL_API_KEY:
        logger.warning(
            "VIRUSTOTAL_API_KEY not configured. Returning mock safe response."
        )
        return {"malicious": 0, "suspicious": 0, "undetected": 1}

    # VirusTotal v3 requires the URL to be base64 encoded without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {
        "x-apikey": settings.VIRUSTOTAL_API_KEY,
    }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(api_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return stats
        elif response.status_code == 404:
            return {"error": "URL not found in VirusTotal"}
        else:
            logger.error(
                f"VirusTotal API error: {response.status_code} - {response.text}"
            )
            return {"error": f"API returned {response.status_code}"}
    except Exception as e:
        logger.error(f"Failed to reach VirusTotal: {e}")
        return {"error": str(e)}


async def check_safe_browsing(urls: List[str]) -> Dict[str, Any]:
    if not settings.SAFE_BROWSING_API_KEY:
        logger.warning(
            "SAFE_BROWSING_API_KEY not configured. Returning mock safe response."
        )
        return {"matches": []}

    if not urls:
        return {"matches": []}

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

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(api_url, json=payload)

        if response.status_code == 200:
            return response.json()
        else:
            logger.error(
                f"Safe Browsing API error: {response.status_code} - {response.text}"
            )
            return {"error": f"API returned {response.status_code}"}
    except Exception as e:
        logger.error(f"Failed to reach Safe Browsing: {e}")
        return {"error": str(e)}


async def gather_intel(urls: List[str]) -> Dict[str, Any]:
    if not urls:
        return {"virustotal": {}, "safebrowsing": {"matches": []}}

    # We only check the first URL for VT as an example, or all concurrently.
    # To keep it simple, let's just check all of them concurrently for VT and 1 bulk for Safe Browsing.
    vt_tasks = [check_virustotal(url) for url in urls]
    sb_task = check_safe_browsing(urls)

    results = await asyncio.gather(*vt_tasks, sb_task)

    vt_results = {url: res for url, res in zip(urls, results[:-1])}
    sb_results = results[-1]

    return {"virustotal": vt_results, "safebrowsing": sb_results}
