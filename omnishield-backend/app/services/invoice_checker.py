"""Invoice fraud verification and vendor validation service."""

import json
import os
from typing import Any, Dict, List, Optional
from app.services.risk_engine import score_to_risk_level

DEFAULT_VENDORS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "vendors.json"
)


def load_vendors(path: str = DEFAULT_VENDORS_FILE) -> List[Dict[str, Any]]:
    """Load approved vendor directory from JSON file."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data.get("vendors", [])
    except Exception:
        return []


def check_invoice(
    vendor_name: str,
    amount: float,
    iban: Optional[str] = None,
    account_number: Optional[str] = None,
    currency: str = "USD",
    notes: Optional[str] = None,
    vendors_path: str = DEFAULT_VENDORS_FILE
) -> Dict[str, Any]:
    """Verify invoice against approved vendor directory and banking records."""
    vendors = load_vendors(vendors_path)
    vendor_name_clean = vendor_name.strip().lower()

    # Find matching vendor by name or aliases
    matched_vendor = None
    for v in vendors:
        v_name = v.get("name", "").strip().lower()
        aliases = [a.strip().lower() for a in v.get("aliases", [])]
        if vendor_name_clean == v_name or vendor_name_clean in aliases:
            matched_vendor = v
            break

    findings: List[str] = []
    score = 0.0

    if not matched_vendor:
        findings.append(f"Unregistered / unknown vendor '{vendor_name}'")
        score = 0.85
    else:
        # Check IBAN mismatch
        if iban and matched_vendor.get("iban"):
            clean_input_iban = iban.replace(" ", "").upper()
            clean_vendor_iban = matched_vendor["iban"].replace(" ", "").upper()
            if clean_input_iban != clean_vendor_iban:
                findings.append(f"IBAN mismatch for vendor '{matched_vendor['name']}'; possible account redirection fraud")
                score += 0.85

        # Check Account Number mismatch
        if account_number and matched_vendor.get("account_number"):
            clean_input_acc = account_number.replace(" ", "").upper()
            clean_vendor_acc = matched_vendor["account_number"].replace(" ", "").upper()
            if clean_input_acc != clean_vendor_acc:
                findings.append("Bank account number does not match registered vendor profile")
                score += 0.70

        # Check invoice amount limit
        max_limit = matched_vendor.get("max_invoice_limit", 100000.0)
        if amount > max_limit:
            findings.append(f"Invoice amount ({amount}) exceeds authorized vendor threshold ({max_limit})")
            score += 0.40

        # Check currency
        registered_currency = matched_vendor.get("currency", "USD")
        if currency.upper() != registered_currency.upper():
            findings.append(f"Currency mismatch: expected {registered_currency}, received {currency}")
            score += 0.20

    # Check for social engineering cues in invoice notes
    if notes:
        lower_notes = notes.lower()
        if "urgent" in lower_notes or "new account" in lower_notes or "updated bank" in lower_notes:
            findings.append("Suspicious payment instructions in invoice notes ('urgent' or 'updated bank')")
            score += 0.35

    normalized_score = round(min(1.0, score), 3)
    risk_level = score_to_risk_level(normalized_score)
    flagged = normalized_score >= 0.50

    recommendation = "Invoice is verified against approved vendor records."
    if flagged:
        recommendation = "Hold payment immediately. Contact vendor via authorized phone directory to confirm banking details."

    return {
        "risk_score": normalized_score,
        "risk_level": risk_level,
        "flagged": flagged,
        "findings": findings,
        "details": {
            "vendor_registered": matched_vendor is not None,
            "vendor_id": matched_vendor.get("id") if matched_vendor else None,
            "amount": amount,
            "currency": currency,
        },
        "recommendation": recommendation,
    }
