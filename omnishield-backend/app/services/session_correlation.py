"""Cross-module session correlation.

Modules tag the incidents they record with a *session fingerprint*. When two or
more distinct product modules (Phishing Scanner, Invoice Shield, Agent Shield,
Data Leak Shield, File Scan) raise risk inside one session window, the incident
is escalated to a "Coordinated BEC / Multi-Vector Attack" lead.

Design notes
------------
* The fingerprint is a one-way hash. Raw session ids, IPs and user agents are
  never persisted.
* State lives in the existing incident store (memory or SQLite), so correlation
  survives restarts and needs no schema change.
* Escalation is monotonic: it can only raise risk, never lower it.
* A lead is an investigative hint. Clients sharing an IP/user-agent (office NAT)
  can share a derived fingerprint, so callers should send ``X-Session-Id`` or a
  body ``session_id`` where they can.
"""
from __future__ import annotations

import hashlib
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import Request

from app.schemas import (
    AuditEvent,
    CorrelationSummary,
    Incident,
    RiskLevel,
    utc_now,
)
from app.services.incident_store import BaseIncidentStore
from app.services.risk_engine import score_to_risk_level

CORRELATION_WINDOW_MINUTES = 60
LEAD_LABEL = "Coordinated BEC / Multi-Vector Attack"
LEAD_SCAN_TYPE = "correlation"
SESSION_DETAIL_KEY = "session_fingerprint"
MIN_SIGNAL_SCORE = 0.45  # same flagging threshold used by the scanners
MIN_MODULES_FOR_LEAD = 2

# scan_type -> product module. Several scan types roll up into one product module so
# that, e.g., a phishing link and a chat scam from the same sender count as ONE vector.
MODULE_FAMILIES: Dict[str, str] = {
    "phishing": "phishing_scanner",
    "message": "phishing_scanner",
    "email": "phishing_scanner",
    "url": "phishing_scanner",
    "qr": "phishing_scanner",
    "chat_guard": "phishing_scanner",
    "invoice": "invoice_shield",
    "injection": "agent_shield",
    "honeypot": "agent_shield",
    "dlp": "data_leak_shield",
    "file": "file_scan",
}


def resolve_session_fingerprint(request: Request, explicit: Optional[str] = None,
                                owner_id: Optional[str] = None) -> str:
    """Return a stable, non-reversible session fingerprint.

    Precedence: ``X-Session-Id`` header, body ``session_id``, then client IP + user agent.
    """
    header = (request.headers.get("x-session-id") or "").strip()
    if header:
        source = f"hdr:{header[:128]}"
    elif explicit and explicit.strip():
        source = f"sid:{explicit.strip()[:128]}"
    else:
        ip = request.client.host if request.client else "unknown-client"
        ua = request.headers.get("user-agent", "")[:200]
        source = f"net:{ip}|{ua}"
    owner = owner_id or getattr(request.state, "owner_id", None) or "anonymous"
    digest = hashlib.sha256(f"{owner}|{source}".encode("utf-8")).hexdigest()
    return f"sess_{digest[:16]}"


def with_session(details: Dict[str, Any], request: Request, explicit: Optional[str] = None) -> Dict[str, Any]:
    """Return a copy of ``details`` tagged with the request's session fingerprint."""
    tagged = dict(details or {})
    tagged[SESSION_DETAIL_KEY] = resolve_session_fingerprint(request, explicit)
    return tagged


def _session_signals(store: BaseIncidentStore, owner_id: Optional[str], fingerprint: str,
                     window_minutes: int) -> List[Incident]:
    cutoff = utc_now() - timedelta(minutes=window_minutes)
    out: List[Incident] = []
    for inc in store.list_incidents(limit=100, offset=0, owner_id=owner_id):
        if inc.scan_type == LEAD_SCAN_TYPE:
            continue  # leads never count as evidence for new leads (no feedback loop)
        if (inc.details or {}).get(SESSION_DETAIL_KEY) != fingerprint:
            continue
        created = inc.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=cutoff.tzinfo)
        if created < cutoff or inc.risk_score < MIN_SIGNAL_SCORE:
            continue
        if inc.scan_type not in MODULE_FAMILIES:
            continue
        out.append(inc)
    return out


def _existing_lead(store: BaseIncidentStore, owner_id: Optional[str], fingerprint: str,
                   modules: Iterable[str], window_minutes: int) -> Optional[Incident]:
    cutoff = utc_now() - timedelta(minutes=window_minutes)
    needed = set(modules)
    for inc in store.list_incidents(limit=100, offset=0, owner_id=owner_id):
        if inc.scan_type != LEAD_SCAN_TYPE or (inc.details or {}).get(SESSION_DETAIL_KEY) != fingerprint:
            continue
        created = inc.created_at if inc.created_at.tzinfo else inc.created_at.replace(tzinfo=cutoff.tzinfo)
        if created >= cutoff and needed.issubset(set((inc.details or {}).get("modules", []))):
            return inc
    return None


def _lead_score(signals: List[Incident], module_count: int) -> float:
    # Conservative: never below the strongest contributing signal, with a floor of 0.80 (HIGH)
    # and a small bump per additional module. Capped below 1.0 because it is a lead, not proof.
    strongest = max((s.risk_score for s in signals), default=0.0)
    return round(min(0.97, max(0.80, strongest) + 0.04 * max(0, module_count - MIN_MODULES_FOR_LEAD)), 3)


def evaluate_session_correlation(
    store: BaseIncidentStore,
    owner_id: Optional[str],
    fingerprint: str,
    *,
    raise_lead: bool,
    trigger_module: str,
    window_minutes: int = CORRELATION_WINDOW_MINUTES,
) -> Tuple[CorrelationSummary, Optional[Incident]]:
    """Check one session for multi-module risk and optionally record a coordinated lead.

    ``raise_lead`` should be true only when the *current* request was itself flagged, so a
    benign request never creates incidents. Returns the summary and the lead (if newly created
    or already present).
    """
    signals = _session_signals(store, owner_id, fingerprint, window_minutes)
    modules = sorted({MODULE_FAMILIES[s.scan_type] for s in signals})
    summary = CorrelationSummary(
        session_fingerprint=fingerprint,
        window_minutes=window_minutes,
        modules_flagged=modules,
        linked_incident_ids=[s.incident_id for s in signals][:20],
    )
    if len(modules) < MIN_MODULES_FOR_LEAD:
        return summary, None

    summary.coordinated = True
    summary.lead_label = LEAD_LABEL
    score = _lead_score(signals, len(modules))
    level = score_to_risk_level(score)
    summary.escalated_risk_level = level
    summary.escalated_risk_score = score

    if not raise_lead:
        return summary, None

    lead = _existing_lead(store, owner_id, fingerprint, modules, window_minutes)
    if lead is None:
        lead = store.record(Incident(
            owner_id=owner_id,
            scan_id=signals[0].scan_id,
            scan_type=LEAD_SCAN_TYPE,
            risk_level=level,
            risk_score=score,
            summary=f"{LEAD_LABEL} lead: {len(modules)} modules flagged in one session ({', '.join(modules)})",
            details={
                "lead_label": LEAD_LABEL,
                SESSION_DETAIL_KEY: fingerprint,
                "modules": modules,
                "trigger_module": trigger_module,
                "linked_incident_ids": summary.linked_incident_ids,
                "linked_scan_types": sorted({s.scan_type for s in signals}),
                "bec_indicators": "invoice_shield" in modules,
                "interpretation": summary.note,
            },
        ))
        store.record_audit_event(AuditEvent(
            scan_id=lead.scan_id, module="correlation", action="coordinated_attack_lead_raised",
            result="coordinated_lead", risk_level=level, risk_score=score,
            summary=f"{LEAD_LABEL} lead raised from {len(modules)} correlated modules",
            details={SESSION_DETAIL_KEY: fingerprint, "modules": modules,
                     "linked_incident_count": len(signals), "trigger_module": trigger_module},
            owner_id=owner_id,
        ))
    summary.lead_incident_id = lead.incident_id
    return summary, lead


def escalate_result_risk(result_score: float, summary: CorrelationSummary) -> Tuple[float, RiskLevel]:
    """Monotonic escalation: returns max(current, lead score) and its level."""
    if not summary.coordinated or summary.escalated_risk_score is None:
        return result_score, score_to_risk_level(result_score)
    new_score = round(max(result_score, summary.escalated_risk_score), 3)
    return new_score, score_to_risk_level(new_score)
