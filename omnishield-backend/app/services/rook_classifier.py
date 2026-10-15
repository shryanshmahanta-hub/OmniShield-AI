"""Optional Rook-1 ML classification integration with graceful fallback."""

import logging
from typing import Any, Dict, Optional
import httpx
from app.config import get_settings

logger = logging.getLogger(__name__)


class RookClassifier:
    """Client for the optional Rook-1 ML classification inference service."""

    def __init__(self, service_url: Optional[str] = None, timeout: float = 2.0) -> None:
        self.service_url = service_url
        self.timeout = timeout

    async def classify_text(self, text: str, context: Optional[str] = None) -> Dict[str, Any]:
        """Send text to Rook-1 inference server; return predictions with fallback on error."""
        if not self.service_url:
            return {"available": False, "reason": "service_url_not_configured"}

        endpoint = f"{self.service_url.rstrip('/')}/classify"
        payload = {"text": text, "context": context}

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(endpoint, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    return {
                        "available": True,
                        "label": data.get("label", "unknown"),
                        "confidence": float(data.get("confidence", 0.0)),
                        "model": data.get("model", "rook-1"),
                        "raw": data,
                    }
                else:
                    logger.warning("Rook-1 returned non-200 status (%s)", response.status_code)
                    return {
                        "available": False,
                        "error": "inference_service_http_error",
                        "status_code": response.status_code,
                        "fallback": True,
                    }
        except Exception as exc:
            logger.warning("Failed to communicate with Rook-1 service (%s)", type(exc).__name__)
            return {
                "available": False,
                "error": "inference_service_unavailable",
                "fallback": True,
            }


def get_rook_classifier() -> RookClassifier:
    """Factory helper using current application settings."""
    settings = get_settings()
    return RookClassifier(service_url=settings.rook_service_url)
