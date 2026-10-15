"""Phishing scan endpoint tests."""

from fastapi.testclient import TestClient


def test_scan_phishing_benign(client: TestClient):
    """Benign email should not be flagged as phishing."""
    payload = {
        "text": "Hey team, just wanted to check if our meeting is still on for tomorrow at 2pm.",
        "sender": "colleague@company.internal",
        "subject": "Quick meeting check",
        "urls": []
    }
    response = client.post("/api/v1/scan/phishing", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "scan_id" in data
    assert "timestamp" in data
    assert data["scan_type"] == "phishing"
    assert data["risk_level"] in ("safe", "low")
    assert data["flagged"] is False
    assert data["risk_score"] < 0.40


def test_scan_phishing_malicious_link_and_urgency(client: TestClient):
    """Urgent email with suspicious TLD link should be flagged as high risk."""
    payload = {
        "text": "Your account has been suspended! Immediate action required. Click here to verify password immediately.",
        "sender": "security-alert@paypal.suspicious-domain.xyz",
        "subject": "URGENT: Verify your account immediately",
        "urls": ["http://paypal-security-update.xyz/login"]
    }
    response = client.post("/api/v1/scan/phishing", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["flagged"] is True
    assert data["risk_level"] in ("high", "critical")
    assert data["risk_score"] >= 0.70
    assert len(data["findings"]) > 0

    # Ensure incident was recorded
    incidents_resp = client.get("/api/v1/incidents")
    assert incidents_resp.status_code == 200
    inc_data = incidents_resp.json()
    assert inc_data["total"] >= 1
    assert any(inc["scan_id"] == data["scan_id"] for inc in inc_data["incidents"])
