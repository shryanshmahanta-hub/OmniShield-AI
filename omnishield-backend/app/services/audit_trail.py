"""Sanitized audit trail helpers. These events are tamper-evident only if a managed DB/ledger adds that guarantee."""
from typing import Any, Dict
from app.schemas import AuditEvent, ScanResponse
from app.services.incident_store import BaseIncidentStore


def record_scan_event(store: BaseIncidentStore, response: ScanResponse, owner_id: str | None) -> AuditEvent:
    """Record one event per completed scan without retaining the scanned content."""
    ai: Dict[str, Any] = {}
    for name, analysis in response.ai_analysis.items():
        ai[name] = {
            "enabled": analysis.enabled,
            "available": analysis.available,
            "model": analysis.model,
            "prediction": analysis.prediction,
            "confidence": analysis.confidence,
            "status": analysis.status,
        }
    if response.ml_analysis is not None:
        ai["prompt_injection"] = response.ml_analysis.model_dump()

    details: Dict[str, Any] = {
        "flagged": response.flagged,
        "finding_count": len(response.findings),
        "ai_analysis": ai,
    }
    # Preserve provider/scanner statuses but intentionally omit raw inputs, URLs, invoice fields and findings.
    source_details = response.details if isinstance(response.details, dict) else {}
    for key in ("scanner_status", "threat_intelligence", "url_threat_intelligence", "clamav", "decision_fusion", "ml_policy"):
        if key in source_details:
            value = source_details[key]
            if key in {"threat_intelligence", "url_threat_intelligence"} and isinstance(value, list):
                details[key] = [{"provider": row.get("provider"), "status": row.get("status"),
                                 "match": row.get("match"), "threat_types": row.get("threat_types", [])}
                                for row in value if isinstance(row, dict)]
            elif key == "threat_intelligence" and isinstance(value, dict):
                details[key] = {k: value.get(k) for k in ("provider", "status", "match", "threat_types")}
            elif key == "clamav" and isinstance(value, dict):
                details[key] = {k: value.get(k) for k in ("engine", "status", "verdict")}
            else:
                details[key] = value

    summary = (f"{response.scan_type.value.title()} scan flagged for review ({len(response.findings)} finding(s))"
               if response.flagged else f"{response.scan_type.value.title()} scan completed")
    event = AuditEvent(
        scan_id=response.scan_id,
        module=response.scan_type.value,
        action="scan_completed",
        result=response.verdict,
        risk_level=response.risk_level,
        risk_score=response.risk_score,
        summary=summary,
        details=details,
        owner_id=owner_id,
        created_at=response.timestamp,
    )
    return store.record_audit_event(event)


def _indicator_values(value: Any, key: str = "") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            kl = str(k).lower()
            if kl == "hostname" and isinstance(v, str) and "." in v:
                found.append(("domain", v.lower().rstrip(".")))
            elif kl == "vendor_id" and isinstance(v, str) and v:
                found.append(("vendor_id", v.lower()))
            found.extend(_indicator_values(v, kl))
    elif isinstance(value, list):
        for item in value[:100]:
            found.extend(_indicator_values(item, key))
    return found


def correlate_incidents(incidents) -> list[dict[str, Any]]:
    """Return investigative leads for repeated domains/vendor IDs across different scans."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for incident in incidents:
        for kind, value in set(_indicator_values(incident.details)):
            if value in {"localhost", "example.com", "example.org", "example.net"}:
                continue
            key = (kind, value)
            groups.setdefault(key, []).append({
                "incident_id": incident.incident_id,
                "scan_type": incident.scan_type,
                "risk_level": incident.risk_level.value,
                "created_at": incident.created_at.isoformat(),
            })
    result = []
    for (kind, value), members in groups.items():
        distinct_modules = {item["scan_type"] for item in members}
        if len(members) < 2 or len(distinct_modules) < 2:
            continue
        result.append({
            "indicator_type": kind,
            "indicator": value,
            "incident_count": len(members),
            "modules": sorted(distinct_modules),
            "incidents": sorted(members, key=lambda x: x["created_at"], reverse=True),
            "interpretation": "Shared indicator is an investigation lead, not proof of attribution or a confirmed campaign.",
        })
    return sorted(result, key=lambda x: (x["incident_count"], len(x["modules"])), reverse=True)[:50]
