"""Invoice BEC comparison inspector tests."""
import json

from fastapi.testclient import TestClient

URL = "/api/v1/invoice/inspect-comparison"
H = {"X-Session-Id": "inv-test"}

GOOD = {
    "vendor_name": "Acme Cloud Services", "account_number": "ACME-992144", "iban": "GB82WEST12345698765432",
    "amount": 12500.0, "invoice_id": "INV-1001", "currency": "USD",
}


def inspect(client: TestClient, **overrides):
    resp = client.post(URL, json={**GOOD, **overrides}, headers=H)
    assert resp.status_code == 200, resp.text
    return resp.json()


def diff_row(data, field):
    return next(d for d in data["field_diff"] if d["field"] == field)


def test_matching_invoice_is_verified_and_has_no_email(client: TestClient):
    data = inspect(client)
    assert data["flagged"] is False
    assert data["payment_destination_verified"] is True
    assert data["vendor_match_type"] == "exact" and data["matched_vendor_id"] == "v-001"
    assert data["mismatched_fields"] == []
    assert data["verification_email"] is None
    assert all(d["status"] == "match" for d in data["field_diff"])


def test_account_mismatch_triggers_high_alert_diff_and_email(client: TestClient):
    data = inspect(client, account_number="ACME-111111", business_name="Lakshmi Textiles")
    assert data["flagged"] is True
    assert data["alert_level"] in ("high", "critical")
    assert data["risk_score"] >= 0.80
    assert data["mismatched_fields"] == ["account_number"]
    row = diff_row(data, "account_number")
    assert row["status"] == "mismatch" and row["severity"] == "critical"
    assert row["submitted"] != row["registered"]
    assert diff_row(data, "iban")["status"] == "match"

    email = data["verification_email"]
    assert email is not None
    assert "INV-1001" in email["subject"]
    assert "Lakshmi Textiles" in email["body"]
    assert "hold" in email["body"].lower()
    assert email["to"] is None and "Do NOT reply" in email["to_note"]


def test_verification_email_and_diff_never_contain_full_account_numbers(client: TestClient):
    data = inspect(client, account_number="ACME-111111", iban="GB00FAKE00000000001111")
    blob = json.dumps(data)
    for full in ("ACME-111111", "ACME-992144", "GB00FAKE00000000001111", "GB82WEST12345698765432"):
        assert full not in blob, f"{full} leaked in response"
    assert data["verification_email"]["body"].count("*") > 0


def test_iban_only_mismatch_is_high(client: TestClient):
    data = inspect(client, iban="FR7699999999999999999999999")
    assert data["mismatched_fields"] == ["iban"]
    assert data["risk_score"] >= 0.80 and data["flagged"] is True


def test_unknown_vendor_flagged(client: TestClient):
    data = inspect(client, vendor_name="Totally New Supplies Pvt")
    assert data["vendor_registered"] is False and data["vendor_match_type"] == "none"
    assert data["flagged"] is True and data["risk_level"] in ("high", "critical")
    assert data["verification_email"] is not None


def test_lookalike_vendor_name_is_flagged_even_with_real_account(client: TestClient):
    data = inspect(client, vendor_name="Acme Cloud Servlces")
    assert data["vendor_match_type"] == "lookalike"
    assert data["flagged"] is True and data["risk_score"] >= 0.80
    assert data["payment_destination_verified"] is False
    assert diff_row(data, "vendor_name")["status"] == "mismatch"
    assert any("resembles" in f for f in data["findings"])


def test_payment_destination_must_match_a_trusted_identifier(client: TestClient):
    ok = inspect(client, payment_destination="ACME-992144")
    assert ok["flagged"] is False
    bad = inspect(client, payment_destination="attacker@upi")
    assert bad["flagged"] is True
    assert "payment_destination" in bad["mismatched_fields"]


def test_missing_iban_is_unverifiable_not_a_false_alarm(client: TestClient):
    body = {k: v for k, v in GOOD.items() if k != "iban"}
    data = client.post(URL, json=body, headers=H).json()
    assert diff_row(data, "iban")["status"] == "not_provided"
    assert data["flagged"] is False
    assert data["payment_destination_verified"] is False


def test_known_supplier_email_is_used_as_draft_recipient(client: TestClient):
    data = inspect(client, account_number="ACME-111111", known_supplier_email="accounts@acme-known.example")
    assert data["verification_email"]["to"] == "accounts@acme-known.example"


def test_low_risk_ai_cannot_lower_destination_mismatch_floor(client: TestClient, setup_test_settings, monkeypatch):
    setup_test_settings.enable_invoice_ml = True
    setup_test_settings.invoice_ml_model = "fake-model"
    legit = {"enabled": True, "available": True, "model": "fake", "prediction": "legitimate",
             "confidence": 0.99, "status": "success"}
    monkeypatch.setattr("app.routes.invoice.classify_text", lambda task, text: legit)
    data = inspect(client, account_number="ACME-111111")
    assert data["flagged"] is True
    assert data["risk_score"] >= 0.80
    assert data["aiAnalysis"]["invoice_text_model"]["prediction"] == "legitimate"


def test_incident_and_audit_are_recorded_without_account_numbers(client: TestClient):
    inspect(client, account_number="ACME-111111", notes="Urgent wire to updated bank account")
    incidents = client.get("/api/v1/incidents").json()
    audit = client.get("/api/v1/audit", params={"module": "invoice"}).json()
    assert incidents["total"] == 1 and incidents["incidents"][0]["scan_type"] == "invoice"
    assert audit["total"] == 1
    blob = json.dumps(incidents) + json.dumps(audit)
    assert "ACME-111111" not in blob and "ACME-992144" not in blob
    assert "Urgent wire" not in blob


def test_validation(client: TestClient):
    bad = {k: v for k, v in GOOD.items() if k != "invoice_id"}
    assert client.post(URL, json=bad).status_code == 422
    assert client.post(URL, json={**GOOD, "amount": -5}).status_code == 422


def test_legacy_invoice_scan_still_works(client: TestClient):
    resp = client.post("/api/v1/scan/invoice", json={"vendor_name": "Acme Cloud Services", "amount": 10.0,
                                                      "account_number": "ACME-992144", "iban": "GB82WEST12345698765432"})
    assert resp.status_code == 200 and resp.json()["flagged"] is False
