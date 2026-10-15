"""Invoice BEC (business email compromise) comparison inspector.

Builds on ``invoice_checker.check_invoice`` (vendor lookup, amount, currency, notes cues) and adds:
* lookalike vendor-name detection (``Acme Cloud Servlces`` vs ``Acme Cloud Services``),
* a field-by-field diff against the trusted vendor record in ``app/data/vendors.json``,
* a hard HIGH-risk floor whenever the payment destination does not match the record,
* a draft manual-verification email that never contains full account numbers.

Registered values are returned masked (last four characters). The caller can see *that* and *where*
a value differs, and the diff is safe to persist or paste into a ticket.
"""
from __future__ import annotations

from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple

from app.schemas import FieldDiff, VerificationEmailDraft
from app.services.invoice_checker import DEFAULT_VENDORS_FILE, check_invoice, load_vendors
from app.services.risk_engine import score_to_risk_level

DESTINATION_MISMATCH_FLOOR = 0.80  # HIGH
LOOKALIKE_VENDOR_RATIO = 0.84


def _norm(value: Optional[str]) -> str:
    # Same normalisation as check_invoice so both checks always agree.
    return (value or "").replace(" ", "").upper()


def mask_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    clean = value.replace(" ", "")
    if len(clean) <= 4:
        return "*" * len(clean)
    return "*" * (len(clean) - 4) + clean[-4:]


def _find_vendor(vendor_name: str, vendors: List[Dict[str, Any]]) -> Tuple[Optional[Dict[str, Any]], str, Optional[float]]:
    needle = vendor_name.strip().lower()
    for v in vendors:
        names = [v.get("name", "").strip().lower()] + [a.strip().lower() for a in v.get("aliases", [])]
        if needle in names:
            return v, "exact", 1.0
    best: Optional[Dict[str, Any]] = None
    best_ratio = 0.0
    for v in vendors:
        for name in [v.get("name", "")] + list(v.get("aliases", [])):
            ratio = SequenceMatcher(None, needle, name.strip().lower()).ratio()
            if ratio > best_ratio:
                best, best_ratio = v, ratio
    if best is not None and best_ratio >= LOOKALIKE_VENDOR_RATIO:
        return best, "lookalike", round(best_ratio, 3)
    return None, "none", None


def inspect_invoice(
    *, vendor_name: str, account_number: str, amount: float, invoice_id: str,
    iban: Optional[str], payment_destination: Optional[str], currency: str,
    notes: Optional[str], business_name: Optional[str], known_supplier_email: Optional[str],
    vendors_path: str = DEFAULT_VENDORS_FILE,
) -> Dict[str, Any]:
    vendors = load_vendors(vendors_path)
    vendor, match_type, ratio = _find_vendor(vendor_name, vendors)

    # Baseline: existing rule checker (exact vendor/alias only; handles amount, currency, notes cues).
    base = check_invoice(
        vendor_name=vendor_name, amount=amount, iban=iban, account_number=account_number,
        currency=currency, notes=notes, vendors_path=vendors_path,
    )
    findings: List[str] = list(base["findings"])
    score = float(base["risk_score"])
    diffs: List[FieldDiff] = []

    if vendor is None:
        findings = [f for f in findings if "Unregistered" not in f] + [
            f"Vendor '{vendor_name}' is not in the trusted vendor record"]
        score = max(score, 0.85)
        diffs.append(FieldDiff(field="vendor_name", submitted=vendor_name, registered=None,
                               status="not_on_file", severity="critical",
                               note="No trusted vendor with this name or a similar name"))
        diffs.append(FieldDiff(field="account_number", submitted=mask_value(account_number), registered=None,
                               status="not_on_file", severity="critical", note="Nothing on file to compare against"))
    else:
        if match_type == "lookalike":
            findings.append(f"Vendor name closely resembles trusted vendor '{vendor['name']}' "
                            f"(similarity {ratio}); possible supplier impersonation")
            score = max(score, 0.85)
        diffs.append(FieldDiff(
            field="vendor_name", submitted=vendor_name, registered=vendor["name"],
            status="match" if match_type == "exact" else "mismatch",
            severity="info" if match_type == "exact" else "critical",
            note=None if match_type == "exact" else "Name is similar to, but not the same as, a trusted vendor"))

        acc_ok = _norm(account_number) == _norm(vendor.get("account_number"))
        diffs.append(FieldDiff(
            field="account_number", submitted=mask_value(account_number),
            registered=mask_value(vendor.get("account_number")),
            status="match" if acc_ok else "mismatch", severity="info" if acc_ok else "critical",
            note=None if acc_ok else "Payee account differs from the trusted record"))

        iban_ok: Optional[bool] = None
        if vendor.get("iban"):
            if iban:
                iban_ok = _norm(iban) == _norm(vendor["iban"])
                diffs.append(FieldDiff(
                    field="iban", submitted=mask_value(iban), registered=mask_value(vendor["iban"]),
                    status="match" if iban_ok else "mismatch", severity="info" if iban_ok else "critical",
                    note=None if iban_ok else "IBAN differs from the trusted record"))
            else:
                diffs.append(FieldDiff(
                    field="iban", submitted=None, registered=mask_value(vendor["iban"]),
                    status="not_provided", severity="warning",
                    note="Invoice has no IBAN, so that part of the destination cannot be verified"))
                findings.append("IBAN missing from invoice; payment destination only partially verified")
                score += 0.15

        if payment_destination:
            dest = _norm(payment_destination)
            dest_ok = dest in {_norm(vendor.get("account_number")), _norm(vendor.get("iban"))}
            diffs.append(FieldDiff(
                field="payment_destination", submitted=mask_value(payment_destination),
                registered=f"{mask_value(vendor.get('account_number'))} / {mask_value(vendor.get('iban'))}",
                status="match" if dest_ok else "mismatch", severity="info" if dest_ok else "critical",
                note=None if dest_ok else "Payee identifier is neither the trusted account nor the trusted IBAN"))
            if not dest_ok:
                findings.append("Payment destination does not match the trusted vendor record")
                score += 0.70

        cur_ok = currency.upper() == str(vendor.get("currency", "")).upper()
        diffs.append(FieldDiff(
            field="currency", submitted=currency.upper(), registered=vendor.get("currency"),
            status="match" if cur_ok else "mismatch", severity="info" if cur_ok else "warning"))
        limit = float(vendor.get("max_invoice_limit", 0) or 0)
        over = limit > 0 and amount > limit
        diffs.append(FieldDiff(
            field="amount", submitted=f"{amount:,.2f}", registered=f"limit {limit:,.2f}" if limit else None,
            status="exceeds_limit" if over else "match", severity="warning" if over else "info"))

    mismatched = [d.field for d in diffs if d.status == "mismatch"]
    destination_mismatch = any(d.field in {"account_number", "iban", "payment_destination"} and d.status == "mismatch"
                               for d in diffs) or vendor is None
    # Hard rule: a destination that is not the trusted one is at least HIGH. Nothing may lower it.
    if destination_mismatch:
        score = max(score, DESTINATION_MISMATCH_FLOOR)
    score = round(min(1.0, score), 3)
    level = score_to_risk_level(score)
    flagged = score >= 0.50

    destination_verified = bool(vendor) and match_type == "exact" and not destination_mismatch and all(
        d.status == "match" for d in diffs if d.field in {"account_number", "iban", "payment_destination"})

    email = build_verification_email(
        invoice_id=invoice_id, vendor=vendor, submitted_vendor_name=vendor_name, amount=amount,
        currency=currency.upper(), diffs=diffs, business_name=business_name,
        known_supplier_email=known_supplier_email) if flagged else None

    return {
        "risk_score": score, "risk_level": level, "flagged": flagged,
        "findings": list(dict.fromkeys(findings)),
        "details": {
            "inspection": "invoice_comparison",
            "invoice_id": invoice_id,
            "vendor_registered": vendor is not None,
            "vendor_id": vendor.get("id") if vendor else None,
            "vendor_match_type": match_type,
            "vendor_similarity": ratio,
            "mismatched_fields": mismatched,
            "field_diff": [d.model_dump() for d in diffs],  # masked values only
            "deterministic_floor": DESTINATION_MISMATCH_FLOOR if destination_mismatch else 0.0,
            "rule_score_before_model": score,
            "amount": amount,
            "currency": currency.upper(),
            "baseline_rule_score": base["risk_score"],
        },
        "recommendation": ("HOLD PAYMENT. Do not pay to the account on this invoice. Phone the supplier on a number from "
                           "your own records (not from the invoice or email) and confirm the bank details."
                           if flagged else "Payment details match the trusted vendor record."),
        "vendor": vendor, "match_type": match_type, "diffs": diffs, "mismatched": mismatched,
        "destination_verified": destination_verified, "email": email,
    }


def build_verification_email(
    *, invoice_id: str, vendor: Optional[Dict[str, Any]], submitted_vendor_name: str, amount: float,
    currency: str, diffs: List[FieldDiff], business_name: Optional[str], known_supplier_email: Optional[str],
) -> VerificationEmailDraft:
    supplier = (vendor or {}).get("name") or submitted_vendor_name
    sender = business_name or "Accounts Payable"
    lines = []
    for d in diffs:
        if d.field in {"account_number", "iban", "payment_destination"} and d.status in {"mismatch", "not_on_file"}:
            label = {"account_number": "Account number", "iban": "IBAN", "payment_destination": "Payee identifier"}[d.field]
            registered = f"; on our records: {d.registered}" if d.registered else ""
            lines.append(f"  - {label} on invoice: {d.submitted}{registered}")
    if not lines:
        lines.append("  - The supplier details on the invoice could not be matched to our records")
    body = (
        f"Dear {supplier} accounts team,\n\n"
        f"We received invoice {invoice_id} for {currency} {amount:,.2f}. As part of our standard payment-fraud checks, "
        f"the payment details on this invoice do not match what we hold on file:\n"
        + "\n".join(lines) + "\n\n"
        "We have placed this payment on hold and have not released any funds. To protect both of us, we will "
        "confirm the correct bank details by phone using the contact number we already have for you.\n\n"
        "Please do not send updated bank details by email alone. If these details are genuine, ask your finance "
        "contact to take our call, or reply with the date and time that suits you.\n\n"
        f"Kind regards,\n{sender}"
    )
    return VerificationEmailDraft(
        to=known_supplier_email,
        to_note=("Address supplied by you as trusted." if known_supplier_email else
                 "Fill in a supplier address from your own records. Do NOT reply to the address that sent the invoice."),
        subject=f"Action required: please verify bank details for invoice {invoice_id}",
        body=body,
        send_guidance=("Send to a known contact, then confirm by phone before paying. If the invoice email was "
                       "compromised, replying to it may reach the attacker."),
    )
