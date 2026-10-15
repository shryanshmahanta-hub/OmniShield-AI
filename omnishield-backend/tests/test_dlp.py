"""Data Loss Prevention (DLP) tests."""

from fastapi.testclient import TestClient


def test_scan_dlp_clean(client: TestClient):
    """Clean text without secrets should return safe."""
    payload = {
        "content": "Our quarterly financial review is scheduled for Thursday.",
        "redact": False
    }
    response = client.post("/api/v1/scan/dlp", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["scan_type"] == "dlp"
    assert data["flagged"] is False
    assert data["risk_level"] in ("safe", "low")


def test_scan_dlp_api_key_leak(client: TestClient):
    """OpenAI API key pattern should be flagged."""
    payload = {
        "content": "Here is the OpenAI test key: sk-abcdef1234567890abcdef1234567890 please keep it safe.",
        "redact": True
    }
    response = client.post("/api/v1/scan/dlp", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["flagged"] is True
    assert data["risk_level"] in ("high", "critical")
    assert "redacted_content" in data["details"]
    assert "sk-" not in data["details"]["redacted_content"]


def test_scan_dlp_credit_card(client: TestClient):
    """Valid credit card numbers matching Luhn algorithm should be detected."""
    # Standard Visa test card passing Luhn algorithm: 4532 0150 0000 0007
    payload = {
        "content": "Customer credit card number: 4532-0150-0000-0007 expires 12/28",
        "redact": True
    }
    response = client.post("/api/v1/scan/dlp", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["flagged"] is True
    assert data["risk_level"] in ("high", "critical")
    assert "redacted_content" in data["details"]
    assert "4532" not in data["details"]["redacted_content"]
