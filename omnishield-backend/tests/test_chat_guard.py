"""WhatsApp / SMS Order Guard tests."""
import json

import pytest
from fastapi.testclient import TestClient

from app.services.chat_guard import analyze_chat, detect_lookalike

URL = "/api/v1/chat-guard/scan"
H = {"X-Session-Id": "chat-test"}


def scan(client: TestClient, text: str, **extra):
    resp = client.post(URL, json={"text": text, **extra}, headers=H)
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_benign_order_chat_is_not_flagged(client: TestClient):
    data = scan(client, "Hi, do you have the blue kurta in size M? I can pick it up at 5pm.", sender="+919876543210")
    assert data["scan_type"] == "chat_guard"
    assert data["flagged"] is False
    assert data["risk_level"] in ("safe", "low")
    assert data["flagged_keywords"] == []
    alert = data["store_owner_alert"]
    assert alert["requires_immediate_attention"] is False
    assert alert["notification"]["channels"] == []


def test_lookalike_domain_with_fake_receipt_is_critical_and_alerts_owner(client: TestClient):
    data = scan(client, "Hi, I already paid. Receipt: paytm-secure-pay.xyz/r/8841 please ship today, urgent!",
                sender="+919876543210", store_name="Lakshmi Textiles")
    assert data["flagged"] is True
    assert data["risk_level"] in ("high", "critical")
    assert "lookalike_domain" in data["tactics"]
    assert "fake_payment_receipt_link" in data["tactics"]
    assert data["lookalike_domains"][0]["impersonates"] == "paytm.com"
    assert any("[.]" in k for k in data["flagged_keywords"]), "hostnames in keywords must be defanged"

    alert = data["store_owner_alert"]
    assert alert["severity"] in ("high", "critical")
    assert alert["requires_immediate_attention"] is True
    assert alert["notification"]["priority"] == "urgent"
    assert len(alert["notification"]["sms_text"]) <= 160
    assert alert["suggested_automation"]["hold_pending_orders_from_sender"] is True
    assert "Lakshmi Textiles" in alert["headline"]
    # Sender phone must be masked everywhere in the alert.
    assert "9876543210" not in json.dumps(alert)
    assert alert["sender_masked"].endswith("210")


@pytest.mark.parametrize("text,tactic", [
    ("Scan this QR code to receive your refund of 2000", "qr_or_collect_request_scam"),
    ("Please share your OTP so I can verify the payment", "credential_or_otp_request"),
    ("Payment proof attached: receipt_8841.apk", "malicious_receipt_attachment"),
    ("Sorry I sent you extra by mistake, please send back the difference", "overpayment_refund_scam"),
])
def test_social_engineering_patterns(client: TestClient, text: str, tactic: str):
    data = scan(client, text)
    assert tactic in data["tactics"]
    assert data["flagged"] is True


@pytest.mark.parametrize("text", [
    "Scan this QR code to receive your refund of 2000",
    "Please share your OTP so I can verify the payment",
    "Payment proof attached: receipt_8841.apk",
])
def test_hard_rules_have_high_floor(client: TestClient, text: str):
    data = scan(client, text)
    assert data["risk_score"] >= 0.75
    assert data["details"]["deterministic_floor"] >= 0.75


def test_vendor_bank_change_request_is_high_for_vendor_chat(client: TestClient):
    data = scan(client, "Hello, we have new bank details for this month's invoice. Please pay to the new account.",
                sender_role="vendor")
    assert "supplier_bank_detail_change" in data["tactics"]
    assert data["risk_level"] in ("high", "critical")
    assert data["store_owner_alert"]["suggested_automation"]["freeze_supplier_payments"] is True


def test_owner_whitelisted_domain_is_not_penalised(client: TestClient):
    text = "Order paid. Receipt: https://shop.mystore.in/receipt/1"
    assert scan(client, text)["flagged"] is True  # unknown host + receipt language
    assert scan(client, text, trusted_domains=["mystore.in"])["flagged"] is False


def test_legitimate_brand_link_and_names_with_dots_not_flagged(client: TestClient):
    data = scan(client, "Check https://www.paypal.com/myaccount. Mr.Sharma from the shop will call, thanks.")
    assert data["flagged"] is False
    assert data["lookalike_domains"] == []


@pytest.mark.parametrize("host,expected", [
    ("paypa1.com", "paypal.com"),
    ("rnicrosoft.com", "microsoft.com"),
    ("paypall.com", "paypal.com"),
    ("paypal.com.verify-login.top", "paypal.com"),
    ("razorpay-refund.in", "razorpay.com"),
    ("paypal.co", "paypal.com"),
])
def test_detect_lookalike_positive(host: str, expected: str):
    hit = detect_lookalike(host, set())
    assert hit is not None and hit.impersonates == expected


@pytest.mark.parametrize("host", ["paypal.com", "www.paypal.com", "amazon.in", "example.org", "apply.com", "mystore.in"])
def test_detect_lookalike_negative(host: str):
    assert detect_lookalike(host, set()) is None


def test_analyzer_uses_existing_phishing_analyzer_signals():
    result = analyze_chat("URGENT: your PayPal account is suspended, verify your account", sender="+15550001111")
    assert result["details"]["brands_detected"] == ["paypal"]
    assert result["details"]["sender_flags"]  # brand/sender mismatch from PhishingAnalyzer
    assert "urgent" in result["flagged_keywords"]


def test_ai_cannot_lower_risk_below_deterministic_floor(client: TestClient, monkeypatch):
    legit = {"enabled": True, "available": True, "model": "fake", "prediction": "legitimate",
             "confidence": 0.99, "status": "success"}
    monkeypatch.setattr("app.routes.chat_guard.classify_text", lambda task, text: legit)
    data = scan(client, "Please share your OTP so I can verify the payment")
    assert data["flagged"] is True
    assert data["risk_score"] >= 0.75
    assert data["aiAnalysis"]["sms"]["prediction"] == "legitimate"


def test_ai_can_raise_but_not_set_critical_alone(client: TestClient, monkeypatch):
    spam = {"enabled": True, "available": True, "model": "fake", "prediction": "spam",
            "confidence": 0.97, "status": "success"}
    monkeypatch.setattr("app.routes.chat_guard.classify_text", lambda task, text: spam)
    data = scan(client, "Hello, are you open on Sunday?")
    assert data["flagged"] is True
    assert 0.5 <= data["risk_score"] < 0.88
    assert any("Deep-learning" in f for f in data["findings"])


def test_incident_and_audit_never_store_raw_chat_text(client: TestClient):
    secret_phrase = "ship the saffron order to Gate 7 tonight"
    scan(client, f"I paid, receipt paytm-secure-pay.xyz/r/1. Please {secret_phrase} and share your OTP")
    incidents = client.get("/api/v1/incidents").json()
    audit = client.get("/api/v1/audit").json()
    assert incidents["total"] == 1 and incidents["incidents"][0]["scan_type"] == "chat_guard"
    assert any(e["module"] == "chat_guard" for e in audit["events"])
    blob = json.dumps(incidents) + json.dumps(audit)
    assert secret_phrase not in blob
    assert "message_sha256_prefix" in incidents["incidents"][0]["details"]


def test_validation_errors(client: TestClient):
    assert client.post(URL, json={"text": ""}).status_code == 422
    assert client.post(URL, json={"text": "hi", "channel": "carrier-pigeon"}).status_code == 422
