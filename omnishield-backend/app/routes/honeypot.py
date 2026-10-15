"""Active Agent Honeypot simulator route."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.routes.multimodal import _as_ml_analysis
from app.schemas import (
    AuditEvent,
    HoneypotChatRequest,
    HoneypotChatResponse,
    Incident,
    ScanType,
    new_scan_id,
    utc_now,
)
from app.services.audit_sanitizer import sanitize_for_audit
from app.services.auth import owner_from_request
from app.services.decision_engine import add_verdict
from app.services.honeypot import (
    BLOCK_REPLY,
    benign_reply,
    message_fingerprint,
    persona_label,
    run_injection_pipeline,
    summarize_vectors,
)
from app.services.incident_store import BaseIncidentStore, get_incident_store
from app.services.session_correlation import (
    escalate_result_risk,
    evaluate_session_correlation,
    resolve_session_fingerprint,
)

router = APIRouter(prefix="/api/v1/honeypot", tags=["Agent Shield Honeypot"])


@router.post("/simulate-chat", response_model=HoneypotChatResponse)
async def simulate_chat(
    request: HoneypotChatRequest,
    http_request: Request,
    store: BaseIncidentStore = Depends(get_incident_store),
) -> HoneypotChatResponse:
    """Chat with a decoy internal assistant. Injection attempts are blocked, logged and correlated."""
    owner_id = owner_from_request(http_request)
    fingerprint = resolve_session_fingerprint(http_request, request.session_id, owner_id)

    result = await run_injection_pipeline(request.message)
    blocked = bool(result["flagged"])
    vectors, explainers = summarize_vectors(result["findings"])
    msg_hash = message_fingerprint(request.message)
    scan_id = new_scan_id()
    now = utc_now()

    # Deliberately excludes the raw message and the detector's matched_text.
    details = {
        "persona": request.persona.value,
        "assistant": persona_label(request.persona),
        "blocked": blocked,
        "attack_vectors": vectors,
        "pattern_findings": result["findings"],
        "message_length": len(request.message),
        "message_sha256_prefix": msg_hash,
        "rule_score_before_model": result["details"]["rule_score_before_model"],
        "decision_fusion": result["details"]["decision_fusion"],
        "ml_policy": result["details"]["ml_policy"],
        "session_fingerprint": fingerprint,
    }

    response = HoneypotChatResponse(
        scan_id=scan_id, timestamp=now, scan_type=ScanType.HONEYPOT,
        risk_level=result["risk_level"], risk_score=result["risk_score"], flagged=blocked,
        findings=result["findings"], details=details,
        recommendation=("Injection blocked and logged; the decoy assistant did not act on the input."
                        if blocked else "No injection signal detected; the decoy assistant answered normally."),
        ai_analysis={"prompt_injection": _as_ml_analysis(result["ml"])},
        verdict=add_verdict(result),
        persona=request.persona, blocked=blocked,
        assistant_reply=BLOCK_REPLY if blocked else benign_reply(request.persona, request.message),
        attack_vectors=vectors, attack_explainer=explainers,
    )

    if blocked:
        incident = store.record(Incident(
            owner_id=owner_id, scan_id=scan_id, scan_type=ScanType.HONEYPOT.value,
            risk_level=response.risk_level, risk_score=response.risk_score,
            summary=f"Honeypot assistant blocked prompt injection: {', '.join(response.findings[:2])}",
            details=details, created_at=now,
        ))
        response.incident_id = incident.incident_id

    # Sanitized audit entry for every turn (action differs so blocked attempts are easy to filter).
    audit = store.record_audit_event(AuditEvent(
        scan_id=scan_id, module=ScanType.HONEYPOT.value,
        action="injection_blocked" if blocked else "chat_turn_allowed",
        result=response.verdict, risk_level=response.risk_level, risk_score=response.risk_score,
        summary=("Prompt injection blocked by honeypot assistant" if blocked else "Honeypot chat turn allowed"),
        details=sanitize_for_audit({
            "persona": request.persona.value, "attack_vectors": vectors,
            "finding_count": len(response.findings), "message_length": len(request.message),
            "message_sha256_prefix": msg_hash, "session_fingerprint": fingerprint,
            "ml": {k: result["ml"].get(k) for k in ("enabled", "available", "model", "prediction", "confidence", "status")},
            "incident_id": response.incident_id,
        }),
        owner_id=owner_id, created_at=now,
    ))
    response.audit_event_id = audit.event_id

    summary, _lead = evaluate_session_correlation(
        store, owner_id, fingerprint, raise_lead=blocked, trigger_module="agent_shield")
    response.correlation = summary
    if blocked and summary.coordinated:
        score, level = escalate_result_risk(response.risk_score, summary)
        response.risk_score, response.risk_level = score, level
        response.verdict = add_verdict({"risk_score": score, "findings": response.findings, "details": details})
        response.recommendation = ("Coordinated BEC / Multi-Vector Attack lead raised: this session also flagged "
                                   "other modules. Review linked incidents in the Incident Center.")
    return response
