from datetime import datetime, timezone

from app.schemas import AuditEvent, RiskLevel
from app.services.incident_store import SqliteIncidentStore


def test_sqlite_audit_events_persist_across_store_instances_and_are_sanitized(tmp_path):
    db_path = str(tmp_path / "audit.sqlite3")
    first = SqliteIncidentStore(db_path)
    event = AuditEvent(
        scan_id="scan_test123", module="email", action="scan_completed", result="high_risk",
        risk_level=RiskLevel.HIGH, risk_score=0.81, summary="Scanned sample message",
        details={"finding_count": 2, "access_token": "super-secret-token"},
        owner_id="org-demo", created_at=datetime.now(timezone.utc),
    )
    first.record_audit_event(event)
    second = SqliteIncidentStore(db_path)
    rows = second.list_audit_events(owner_id="org-demo")
    assert len(rows) == 1
    assert rows[0].scan_id == "scan_test123"
    assert rows[0].details["access_token"] == "[REDACTED_FOR_AUDIT]"
    assert second.list_audit_events(owner_id="other-org") == []
