"""Data Loss Prevention (DLP) scan route."""

import asyncio
from fastapi import APIRouter, Depends, Request
from app.schemas import (
    DLPScanRequest,
    Incident,
    MLAnalysis,
    ScanResponse,
    ScanType,
    new_scan_id,
    utc_now,
)
from app.services.dlp_detector import detect_dlp
from app.services.incident_store import BaseIncidentStore, get_incident_store
from app.services.auth import owner_from_request
from app.services.audit_trail import record_scan_event
from app.services.session_correlation import with_session
from app.services.decision_engine import add_verdict
from app.services.dlp_ner import analyze_entities
from app.services.risk_engine import score_to_risk_level

router = APIRouter(prefix="/api/v1/scan", tags=["Scanning"])


@router.post("/dlp", response_model=ScanResponse)
async def scan_dlp(
    request: DLPScanRequest,
    http_request: Request,
    store: BaseIncidentStore = Depends(get_incident_store)
) -> ScanResponse:
    """Scan content for sensitive credentials, secrets, and personally identifiable information."""
    result = detect_dlp(content=request.content, redact=request.redact)
    ner_result = await asyncio.to_thread(analyze_entities, request.content)
    result_details = result.setdefault("details", {})
    if ner_result.get("available"):
        counts = {item["type"]: item["count"] for item in ner_result.get("entities", [])}
        entity_count = sum(counts.values())
        if entity_count:
            result_details["ner_entities"] = [{"type": kind, "count": count} for kind, count in counts.items()]
            result_details["total_sensitive_items"] = int(result_details.get("total_sensitive_items", 0)) + entity_count
            result["findings"].append(f"Local NER model detected {entity_count} person, organization or location entity(s)")
            # NER entities are a supplementary privacy signal; they cannot create a critical verdict.
            result["risk_score"] = round(max(float(result["risk_score"]), min(0.45, 0.25 + 0.05 * entity_count)), 3)
            result["risk_level"] = score_to_risk_level(result["risk_score"])
            result["flagged"] = result["risk_score"] >= 0.45
            result["recommendation"] = ("Sensitive entities were detected. Redact or remove sensitive content before sharing."
                                        if result["flagged"] else
                                        "Review the detected person, organization or location entities before sharing.")
        if request.redact and ner_result.get("spans"):
            # Apply NER redactions to the original text from right-to-left so offsets remain valid,
            # then run deterministic secret/PII redaction over the result.
            ner_redacted = request.content
            for span in sorted(ner_result["spans"], key=lambda x: x["start"], reverse=True):
                token = f"[{span['type']}_REDACTED]"
                ner_redacted = ner_redacted[:span["start"]] + token + ner_redacted[span["end"]:]
            final_redaction = detect_dlp(content=ner_redacted, redact=True)
            result_details["redacted_content"] = final_redaction.get("details", {}).get("redacted_content", ner_redacted)
        result_details["ner_truncated"] = bool(ner_result.get("truncated", False))

    result_details["ner_model_status"] = ner_result.get("status", "unknown")
    result_details["ai_scope_note"] = "Deterministic patterns remain primary. Optional NER runs locally to suggest person/organization/location redactions; raw DLP content is not sent to a language model. NER can miss entities and should be reviewed."
    ner_analysis = MLAnalysis(
        enabled=bool(ner_result.get("enabled")),
        available=bool(ner_result.get("available")),
        model=ner_result.get("model"),
        prediction=("entities_detected" if ner_result.get("entities") else "no_entities_detected") if ner_result.get("available") else None,
        confidence=None,
        status=str(ner_result.get("status", "unknown")),
    )
    scan_resp = ScanResponse(
        scan_id=new_scan_id(),
        timestamp=utc_now(),
        scan_type=ScanType.DLP,
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        flagged=result["flagged"],
        findings=result["findings"],
        details=result["details"],
        recommendation=result.get("recommendation"),
        ai_analysis={"dlp_ner": ner_analysis},
        verdict=add_verdict(result),
    )

    record_scan_event(store, scan_resp, owner_from_request(http_request))

    if scan_resp.flagged:
        incident = Incident(
            scan_id=scan_resp.scan_id,
            scan_type=scan_resp.scan_type.value,
            risk_level=scan_resp.risk_level,
            risk_score=scan_resp.risk_score,
            summary=f"Sensitive data leak detected: {', '.join(scan_resp.findings[:2])}",
            details=with_session(scan_resp.details, http_request),
            created_at=scan_resp.timestamp,
            owner_id=owner_from_request(http_request),
        )
        store.record(incident)

    return scan_resp
