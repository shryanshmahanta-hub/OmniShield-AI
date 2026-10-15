from app.services.text_model import LocalTextClassifier
from app.services.audit_sanitizer import sanitize_for_audit
from app.services.decision_engine import fuse_model_signal


def test_model_label_normalization_never_treats_unsafe_as_safe():
    classifier = LocalTextClassifier("test", "none", "")
    assert classifier._normalize_label("unsafe") == "suspicious"
    assert classifier._normalize_label("not phishing") == "legitimate"
    assert classifier._normalize_label("legitimate") == "legitimate"
    assert classifier._normalize_label("LABEL_0") is None


def test_audit_sanitizer_removes_content_and_url_secrets():
    cleaned = sanitize_for_audit({
        "content": "private prompt text",
        "details": "contact person@example.com",
        "url": "https://example.invalid/login?token=secret-value&x=1#sensitive",
        "payload_excerpt": "UPI://pay?pa=private@bank",
    })
    assert cleaned["content"] == "[REDACTED_FOR_AUDIT]"
    assert "person@example.com" not in cleaned["details"]
    assert "secret-value" not in cleaned["url"]
    assert "sensitive" not in cleaned["url"]
    assert cleaned["payload_excerpt"] == "[REDACTED_FOR_AUDIT]"


def test_model_fusion_never_reduces_a_rule_score(setup_test_settings):
    result = {"risk_score": 0.72, "risk_level": "high", "flagged": True, "findings": [], "details": {"rule_score_before_model": 0.72}}
    fuse_model_signal(result, {"enabled": True, "available": True, "prediction": "legitimate", "confidence": 0.99, "model": "test", "status": "success"}, signal_name="test")
    assert result["risk_score"] == 0.72


def test_incident_store_filters_by_owner():
    from app.schemas import Incident, RiskLevel
    from app.services.incident_store import MemoryIncidentStore

    store = MemoryIncidentStore()
    first = Incident(scan_id="scan_1", scan_type="url", risk_level=RiskLevel.HIGH,
                     risk_score=0.8, summary="first tenant", owner_id="tenant-a")
    second = Incident(scan_id="scan_2", scan_type="email", risk_level=RiskLevel.HIGH,
                      risk_score=0.9, summary="second tenant", owner_id="tenant-b")
    store.record(first)
    store.record(second)
    assert store.count(owner_id="tenant-a") == 1
    assert [x.owner_id for x in store.list_incidents(owner_id="tenant-a")] == ["tenant-a"]
    assert store.get_incident(second.incident_id, owner_id="tenant-a") is None


def test_audit_sanitizer_catches_camel_case_secret_keys():
    from app.services.audit_sanitizer import sanitize_for_audit
    cleaned = sanitize_for_audit({"accessToken": "private", "clientSecret": "another-private"})
    assert cleaned["accessToken"] == "[REDACTED_FOR_AUDIT]"
    assert cleaned["clientSecret"] == "[REDACTED_FOR_AUDIT]"
