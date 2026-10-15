"""WhatsApp / SMS Order Guard route."""
from __future__ import annotations

import asyncio
import hashlib

from fastapi import APIRouter, Depends, Request

from app.routes.multimodal import _as_ml_analysis, _enrich_urls
from app.schemas import (
    ChatGuardResponse,
    ChatGuardScanRequest,
    Incident,
    ScanType,
    new_scan_id,
    utc_now,
)
from app.services.audit_trail import record_scan_event
from app.services.auth import owner_from_request
from app.services.chat_guard import analyze_chat, build_store_owner_alert, extract_hosts
from app.services.decision_engine import add_verdict, fuse_model_signal
from app.services.incident_store import BaseIncidentStore, get_incident_store
from app.services.risk_engine import score_to_risk_level
from app.services.session_correlation import (
    escalate_result_risk,
    evaluate_session_correlation,
    resolve_session_fingerprint,
)
from app.services.text_model import classify_text

router = APIRouter(prefix="/api/v1/chat-guard", tags=["Chat Guard"])


@router.post("/scan", response_model=ChatGuardResponse)
async def scan_chat(
    request: ChatGuardScanRequest,
    http_request: Request,
    store: BaseIncidentStore = Depends(get_incident_store),
) -> ChatGuardResponse:
    """Scan a WhatsApp/SMS order or vendor chat for phishing, fake receipts and social engineering."""
    owner_id = owner_from_request(http_request)
    fingerprint = resolve_session_fingerprint(http_request, request.session_id, owner_id)

    result = analyze_chat(
        request.text, sender=request.sender, sender_role=request.sender_role,
        trusted_domains=request.trusted_domains,
    )
    floor = float(result["floor"])

    # Optional local SMS classifier: may raise risk, never lower it (see decision_engine).
    model_result = await asyncio.to_thread(classify_text, "sms", request.text)
    if model_result.get("enabled"):
        fuse_model_signal(result, model_result, signal_name="chat_sms_classifier")
    # Optional URL model / Web Risk enrichment (no URL is ever fetched by OmniShield).
    await _enrich_urls(result, extract_hosts(request.text))

    # Defense in depth: a deterministic rule floor can never be undercut by anything above.
    result["risk_score"] = round(max(float(result["risk_score"]), floor), 3)
    result["risk_level"] = score_to_risk_level(result["risk_score"])
    result["flagged"] = result["risk_score"] >= 0.45 or bool(result["flagged"])
    result["details"]["deterministic_floor"] = floor

    text_fp = hashlib.sha256(request.text.encode("utf-8")).hexdigest()[:10]
    alert = build_store_owner_alert(
        result, channel=request.channel, sender=request.sender,
        store_name=request.store_name, text_fingerprint_source=text_fp,
    )

    details = dict(result["details"])
    details.update({
        "channel": request.channel.value,
        "sender_role": request.sender_role,
        "sender_masked": alert.sender_masked,
        "lookalike_domains": [h.model_dump() for h in result["lookalikes"]],
        "flagged_keywords": result["flagged_keywords"],
        "message_length": len(request.text),
        "message_sha256_prefix": text_fp,
        "session_fingerprint": fingerprint,
    })
    # Raw chat text is never placed in details: it would be persisted to audit/incident storage.

    response = ChatGuardResponse(
        scan_id=new_scan_id(), timestamp=utc_now(), scan_type=ScanType.CHAT_GUARD,
        risk_level=result["risk_level"], risk_score=result["risk_score"], flagged=result["flagged"],
        findings=result["findings"], details=details, recommendation=result["recommendation"],
        ai_analysis={"sms": _as_ml_analysis(model_result)}, verdict=add_verdict(result),
        channel=request.channel, flagged_keywords=result["flagged_keywords"],
        tactics=result["tactics"], lookalike_domains=result["lookalikes"], store_owner_alert=alert,
    )
    record_scan_event(store, response, owner_id)

    if response.flagged:
        store.record(Incident(
            scan_id=response.scan_id, scan_type=ScanType.CHAT_GUARD.value,
            risk_level=response.risk_level, risk_score=response.risk_score,
            summary=f"Chat scam risk ({request.channel.value}): {', '.join(response.findings[:2])}",
            details=response.details, created_at=response.timestamp, owner_id=owner_id,
        ))

    summary, _lead = evaluate_session_correlation(
        store, owner_id, fingerprint, raise_lead=response.flagged, trigger_module="chat_guard")
    response.correlation = summary
    if response.flagged and summary.coordinated:
        # Monotonic: escalation can raise the alert, never lower it.
        score, level = escalate_result_risk(response.risk_score, summary)
        response.risk_score, response.risk_level = score, level
        response.verdict = add_verdict({"risk_score": score, "findings": response.findings, "details": response.details})
        response.store_owner_alert.reasons.insert(0, "Same session also triggered other OmniShield modules (coordinated attack lead)")
        response.store_owner_alert.severity = "critical" if level.value == "critical" else "high"
        response.store_owner_alert.requires_immediate_attention = True
        response.store_owner_alert.notification.priority = "urgent"
    return response
