"""Integration tests for the new, optional scanner routes."""
from fastapi.testclient import TestClient


def test_message_scan_has_shared_schema_and_explicit_ai_status(client: TestClient):
    response = client.post("/api/v1/scan/message", json={"text": "Your meeting is at 3 PM."})
    assert response.status_code == 200
    body = response.json()
    for key in ("scan_id", "scan_type", "risk_level", "risk_score", "flagged", "findings", "details", "aiAnalysis", "verdict"):
        assert key in body
    assert body["scan_type"] == "message"
    assert body["aiAnalysis"]["sms"]["status"] == "disabled"
    assert body["verdict"] in {"no_high_risk_signal_detected", "suspicious", "high_risk", "critical_risk"}


def test_url_scan_does_not_fetch_destination_and_has_provider_status(client: TestClient):
    response = client.post("/api/v1/scan/url", json={"url": "https://accounts.example.invalid/login?token=demo"})
    assert response.status_code == 200
    body = response.json()
    assert body["details"]["url_analysis"]["valid"] is True
    assert body["details"]["threat_intelligence"]["status"] == "not_configured"
    assert body["aiAnalysis"]["url_phishing"]["status"] == "disabled"
    assert "does not open" not in body["details"].get("note", "")


def test_unsupported_url_is_not_marked_safe(client: TestClient):
    response = client.post("/api/v1/scan/url", json={"url": "javascript:alert(1)"})
    assert response.status_code == 200
    body = response.json()
    assert body["details"]["url_analysis"]["valid"] is False
    assert body["verdict"] == "unknown"


def test_qr_payload_is_scanned_as_data_not_opened(client: TestClient):
    response = client.post("/api/v1/scan/qr", json={"payload": "https://payment-check.example.invalid/login"})
    assert response.status_code == 200
    body = response.json()
    assert body["scan_type"] == "qr"
    assert body["details"]["payload_type"] == "url_or_domain"
    assert "url_checks_note" in body["details"]
    assert "did not open" in body["details"]["url_checks_note"]


def test_dlp_redacted_content_is_returned(client: TestClient):
    response = client.post("/api/v1/scan/dlp", json={"content": "Reach demo.user@example.invalid", "redact": True})
    assert response.status_code == 200
    body = response.json()
    assert "redacted_content" in body["details"]
    assert "[EMAIL_REDACTED]" in body["details"]["redacted_content"]


def test_file_without_scanner_reports_unknown(monkeypatch, client: TestClient):
    import app.routes.file_scan as route

    async def unavailable(filename, payload):
        return {
            "risk_score": 0.0, "risk_level": "safe", "flagged": False, "findings": [],
            "details": {"sha256": "0" * 64, "model_signal": {"enabled": False, "available": False,
                "model": None, "prediction": None, "confidence": None, "status": "not_configured"},
                "scanner_status": "unavailable"},
            "checked_artifact": False,
        }

    monkeypatch.setattr(route, "scan_file", unavailable)
    response = client.post("/api/v1/scan/file", files={"file": ("sample.bin", b"synthetic bytes", "application/octet-stream")})
    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "unknown"
    assert body["aiAnalysis"]["malware_deep_learning"]["status"] == "not_configured"


def test_production_auth_off_fails_closed(client: TestClient, setup_test_settings, monkeypatch):
    setup_test_settings.environment = "production"
    import app.services.auth as auth_module
    monkeypatch.setattr(auth_module, "get_settings", lambda: setup_test_settings)
    response = client.post("/api/v1/scan/url", json={"url": "https://example.invalid"})
    assert response.status_code == 503


def test_ai_status_does_not_expose_secret_values(client: TestClient, setup_test_settings):
    setup_test_settings.google_web_risk_api_key = "never-show-this"
    response = client.get("/api/v1/scan/ai-status")
    assert response.status_code == 200
    assert "never-show-this" not in response.text


def test_api_key_auth_rejects_missing_key_and_accepts_correct_key(client: TestClient, setup_test_settings, monkeypatch):
    import app.services.auth as auth_module
    setup_test_settings.auth_mode = "api_key"
    setup_test_settings.api_key = "server-only-demo-key"
    monkeypatch.setattr(auth_module, "get_settings", lambda: setup_test_settings)
    denied = client.post("/api/v1/scan/url", json={"url": "https://example.invalid"})
    allowed = client.post("/api/v1/scan/url", headers={"X-API-Key": "server-only-demo-key"}, json={"url": "https://example.invalid"})
    assert denied.status_code == 401
    assert allowed.status_code == 200


def test_audit_trail_records_even_non_flagged_scans(client: TestClient):
    scan = client.post("/api/v1/scan/message", json={"text": "The team meeting is at 3 PM."})
    assert scan.status_code == 200
    response = client.get("/api/v1/audit")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    event = body["events"][0]
    assert event["action"] == "scan_completed"
    assert event["module"] == "message"
    assert "text" not in event["details"]


def test_audit_summary_and_incident_correlations_routes(client: TestClient):
    # A reserved synthetic IP + login URL creates a flagged URL incident.
    client.post("/api/v1/scan/url", json={"url": "http://192.0.2.10/login"})
    client.post("/api/v1/scan/email", json={
        "text": "Urgent account verification at http://192.0.2.10/login",
        "subject": "Urgent verification",
    })
    summary = client.get("/api/v1/audit/summary")
    correlations = client.get("/api/v1/incidents/correlations")
    assert summary.status_code == 200
    assert summary.json()["total"] >= 2
    assert correlations.status_code == 200
    assert isinstance(correlations.json()["correlations"], list)


def test_dlp_optional_ner_entities_are_reported_and_redacted(monkeypatch, client: TestClient):
    import app.routes.dlp as route

    monkeypatch.setattr(route, "analyze_entities", lambda text: {
        "enabled": True, "available": True, "model": "test/local-ner", "status": "success",
        "entities": [{"type": "PERSON", "count": 1}],
        "spans": [{"start": 0, "end": 5, "type": "PERSON", "confidence": 0.99}],
        "truncated": False,
    })
    response = client.post("/api/v1/scan/dlp", json={
        "content": "Alice contact alice@example.invalid", "redact": True,
    })
    assert response.status_code == 200
    body = response.json()
    assert body["aiAnalysis"]["dlp_ner"]["status"] == "success"
    assert "[PERSON_REDACTED]" in body["details"]["redacted_content"]
    assert "[EMAIL_REDACTED]" in body["details"]["redacted_content"]


def test_qr_decoder_rejects_invalid_image_without_crashing():
    from app.services.qr_decoder import decode_qr_image
    assert decode_qr_image(b"not an image") is None


def test_demo_frontend_is_served_from_project_root(client: TestClient):
    response = client.get("/demo")
    assert response.status_code == 200
    assert "Data Leak Shield" in response.text
    assert "Incident Center" in response.text
