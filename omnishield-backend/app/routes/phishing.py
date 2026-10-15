"""Phishing detection route."""

from fastapi import APIRouter, Depends, Request
from app.schemas import (
    Incident,
    PhishingScanRequest,
    RiskLevel,
    ScanResponse,
    ScanType,
    new_scan_id,
    utc_now,
)
from app.services.incident_store import BaseIncidentStore, get_incident_store
from app.services.auth import owner_from_request
from app.services.audit_trail import record_scan_event
from app.services.session_correlation import with_session
from app.services.decision_engine import add_verdict
from app.services.phishing_analyzer import analyze_phishing
from app.services.dlp_detector import detect_dlp
from app.services.rook_classifier import get_rook_classifier

router = APIRouter(prefix="/api/v1/scan", tags=["Scanning"])


@router.post("/phishing", response_model=ScanResponse)
async def scan_phishing(
    request: PhishingScanRequest,
    http_request: Request,
    store: BaseIncidentStore = Depends(get_incident_store)
) -> ScanResponse:
    """Scan message text and URLs for phishing indicators and social engineering cues."""
    result = analyze_phishing(
        text=request.text,
        sender=request.sender,
        subject=request.subject,
        explicit_urls=request.urls,
    )

    # Optional Rook-1 classification enrichment
    rook = get_rook_classifier()
    # If an external classifier is configured, send only locally redacted text.
    redaction_preview = detect_dlp(content=request.text, redact=True)
    rook_safe_text = redaction_preview.get("details", {}).get("redacted_content", "[content redacted]")
    rook_res = await rook.classify_text(rook_safe_text)
    if rook_res.get("available") and rook_res.get("confidence", 0) > 0.85:
        result["details"]["rook_classification"] = rook_res

    scan_resp = ScanResponse(
        scan_id=new_scan_id(),
        timestamp=utc_now(),
        scan_type=ScanType.PHISHING,
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        flagged=result["flagged"],
        findings=result["findings"],
        details=result["details"],
        recommendation=result.get("recommendation"),
        verdict=add_verdict(result),
    )

    record_scan_event(store, scan_resp, owner_from_request(http_request))

    if scan_resp.flagged:
        incident = Incident(
            scan_id=scan_resp.scan_id,
            scan_type=scan_resp.scan_type.value,
            risk_level=scan_resp.risk_level,
            risk_score=scan_resp.risk_score,
            summary=f"Phishing threat detected: {', '.join(scan_resp.findings[:2])}",
            details=with_session(scan_resp.details, http_request),
            created_at=scan_resp.timestamp,
            owner_id=owner_from_request(http_request),
        )
        store.record(incident)

    return scan_resp
