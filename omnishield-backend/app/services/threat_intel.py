"""Optional Google Web Risk URI lookup; does not fetch/visit the scanned URL."""
from typing import Any, Dict
import httpx
from app.config import get_settings


async def lookup_url(url: str) -> Dict[str, Any]:
    settings = get_settings()
    if not settings.google_web_risk_api_key:
        return {"provider": "google_web_risk", "status": "not_configured", "match": None, "threat_types": []}
    params = [
        ("threatTypes", "MALWARE"),
        ("threatTypes", "SOCIAL_ENGINEERING"),
        ("uri", url),
        ("key", settings.google_web_risk_api_key),
    ]
    try:
        async with httpx.AsyncClient(timeout=settings.web_risk_timeout_seconds) as client:
            resp = await client.get("https://webrisk.googleapis.com/v1/uris:search", params=params)
        if resp.status_code == 200:
            payload = resp.json()
            threat = payload.get("threat", {}) or {}
            types = threat.get("threatTypes", []) or []
            return {"provider": "google_web_risk", "status": "match" if types else "no_match",
                    "match": bool(types), "threat_types": [str(t) for t in types]}
        if resp.status_code in (400, 401, 403):
            return {"provider": "google_web_risk", "status": "provider_error", "match": None, "threat_types": []}
        return {"provider": "google_web_risk", "status": "unavailable", "match": None, "threat_types": []}
    except Exception:
        return {"provider": "google_web_risk", "status": "unavailable", "match": None, "threat_types": []}
