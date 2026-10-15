"""Prompt injection and jailbreak scan route."""

import asyncio
from fastapi import APIRouter, Depends, Request
from app.schemas import (
    Incident,
    MLAnalysis,
    InjectionScanRequest,
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
from app.services.injection_detector import detect_injection
from app.services.dlp_detector import detect_dlp
from app.services.rook_classifier import get_rook_classifier
from app.services.prompt_injection_ml import get_prompt_injection_classifier
from app.config import get_settings
from app.services.risk_engine import score_to_risk_level

router = APIRouter(prefix="/api/v1/scan", tags=["Scanning"])


@router.post("/injection", response_model=ScanResponse)
async def scan_injection(
    request: InjectionScanRequest,
    http_request: Request,
    store: BaseIncidentStore = Depends(get_incident_store)
) -> ScanResponse:
    """Scan LLM prompt for prompt injection, jailbreaks, and persona overrides."""
    result = detect_injection(prompt=request.prompt, context=request.context)

    # Optional ProtectAI DeBERTa classifier. The model is lazy-loaded once and
    # inference runs off the event loop. Rules remain available when ML is off/down.
    settings = get_settings()
    ml_result = {"enabled": settings.enable_prompt_ml, "available": False,
                 "model": settings.prompt_ml_model if settings.enable_prompt_ml else None,
                 "prediction": None, "confidence": None,
                 "status": "disabled" if not settings.enable_prompt_ml else "not_checked"}
    if settings.enable_prompt_ml:
        classifier = get_prompt_injection_classifier()
        ml_result = await asyncio.to_thread(classifier.classify, request.prompt)
        ml_result["enabled"] = True
        # Policy: only a correctly mapped INJECTION label above the configured
        # threshold adds a model finding. It cannot alone produce a critical verdict.
        confidence = ml_result.get("confidence")
        if (ml_result.get("available") and ml_result.get("prediction") == "INJECTION"
                and isinstance(confidence, (int, float)) and 0.0 <= confidence <= 1.0
                and confidence >= settings.prompt_ml_threshold):
            ml_score = min(0.75, max(0.50, float(confidence) * 0.75))
            result["risk_score"] = max(float(result["risk_score"]), ml_score)
            result["risk_level"] = score_to_risk_level(result["risk_score"])
            result["flagged"] = result["risk_score"] >= 0.50
            if "Pretrained ML classifier flagged possible prompt injection" not in result["findings"]:
                result["findings"].append("Pretrained ML classifier flagged possible prompt injection")
            result["details"]["ml_policy"] = "INJECTION prediction above threshold raises risk to at most high; it is not proof of maliciousness."

    # Preserve the existing optional Rook-1 integration only when explicitly configured.
    # Its output is diagnostic enrichment, not an independent proof of an attack.
    rook = get_rook_classifier()
    if settings.rook_service_url:
        # Do not send obvious secrets/PII to an external classifier. The local DLP
        # pattern set is defense-in-depth and cannot guarantee perfect redaction.
        redacted_prompt = detect_dlp(content=request.prompt, redact=True).get("details", {}).get("redacted_content", "[prompt redacted]")
        redacted_context = detect_dlp(content=request.context, redact=True).get("details", {}).get("redacted_content", "") if request.context else None
        rook_res = await rook.classify_text(redacted_prompt, context=redacted_context)
        result["details"]["rook_classification"] = {
            "available": bool(rook_res.get("available")),
            "status": "available" if rook_res.get("available") else "unavailable",
            "model": rook_res.get("model", "rook-1") if rook_res.get("available") else None,
        }

    ml_analysis = MLAnalysis(**ml_result)

    scan_resp = ScanResponse(
        scan_id=new_scan_id(),
        timestamp=utc_now(),
        scan_type=ScanType.INJECTION,
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        flagged=result["flagged"],
        findings=result["findings"],
        details=result["details"],
        recommendation=result.get("recommendation"),
        ml_analysis=ml_analysis,
        ai_analysis={"prompt_injection": ml_analysis},
        verdict=add_verdict(result),
    )

    record_scan_event(store, scan_resp, owner_from_request(http_request))

    if scan_resp.flagged:
        incident = Incident(
            scan_id=scan_resp.scan_id,
            scan_type=scan_resp.scan_type.value,
            risk_level=scan_resp.risk_level,
            risk_score=scan_resp.risk_score,
            summary=f"Prompt injection detected: {', '.join(scan_resp.findings[:2])}",
            details=with_session(scan_resp.details, http_request),
            created_at=scan_resp.timestamp,
            owner_id=owner_from_request(http_request),
        )
        store.record(incident)

    return scan_resp
