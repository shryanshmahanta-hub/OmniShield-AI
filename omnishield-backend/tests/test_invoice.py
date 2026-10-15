"""Invoice validation and fraud check tests."""

from fastapi.testclient import TestClient


def test_scan_invoice_valid_vendor(client: TestClient):
    """Invoice matching registered vendor records should pass without flags."""
    payload = {
        "vendor_name": "Acme Cloud Services",
        "amount": 12500.0,
        "iban": "GB82WEST12345698765432",
        "account_number": "ACME-992144",
        "currency": "USD"
    }
    response = client.post("/api/v1/scan/invoice", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["scan_type"] == "invoice"
    assert data["flagged"] is False
    assert data["risk_level"] in ("safe", "low")
    assert data["details"]["vendor_registered"] is True


def test_scan_invoice_unknown_vendor(client: TestClient):
    """Invoice for unregistered vendor should be flagged."""
    payload = {
        "vendor_name": "Unregistered Shadow Vendor LLC",
        "amount": 9500.0,
        "iban": "US00MOCK1234567890",
        "currency": "USD"
    }
    response = client.post("/api/v1/scan/invoice", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["flagged"] is True
    assert data["risk_level"] in ("high", "critical")
    assert any("Unregistered" in f for f in data["findings"])


def test_scan_invoice_iban_mismatch_fraud(client: TestClient):
    """Known vendor name with altered IBAN (account takeover/redirection) must be flagged."""
    payload = {
        "vendor_name": "Acme Cloud Services",
        "amount": 15000.0,
        "iban": "FR7699999999999999999999999",  # Fraudulent altered IBAN
        "account_number": "ACME-992144",
        "currency": "USD",
        "notes": "Urgent wire required to updated bank account"
    }
    response = client.post("/api/v1/scan/invoice", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["flagged"] is True
    assert data["risk_level"] in ("high", "critical")
    assert any("mismatch" in f.lower() for f in data["findings"])
