"""Invoice verification and payment fraud scan route."""

import asyncio
from fastapi import APIRouter, Depends, Request
from app.schemas import (
    Incident,
    InvoiceInspectRequest,
    InvoiceInspectResponse,
    InvoiceScanRequest,
    ScanResponse,
    ScanType,
    new_scan_id,
    utc_now,
)
from app.services.incident_store import BaseIncidentStore, get_incident_store
from app.services.auth import owner_from_request
from app.services.audit_trail import record_scan_event
from app.services.text_model import classify_text
from app.services.decision_engine import fuse_model_signal, add_verdict
from app.schemas import MLAnalysis
from app.services.risk_engine import score_to_risk_level
from app.services.dlp_detector import detect_dlp
from app.services.invoice_checker import check_invoice
from app.services.invoice_inspector import inspect_invoice
from app.services.session_correlation import (
    escalate_result_risk,
    evaluate_session_correlation,
    resolve_session_fingerprint,
    with_session,
)

router = APIRouter(prefix="/api/v1/scan", tags=["Scanning"])
inspect_router = APIRouter(prefix="/api/v1/invoice", tags=["Invoice Shield"])


@router.post("/invoice", response_model=ScanResponse)
async def scan_invoice(
    request: InvoiceScanRequest,
    http_request: Request,
    store: BaseIncidentStore = Depends(get_incident_store)
) -> ScanResponse:
    """Scan invoice details against approved vendor directory and banking records."""
    result = check_invoice(
        vendor_name=request.vendor_name,
        amount=request.amount,
        iban=request.iban,
        account_number=request.account_number,
        currency=request.currency,
        notes=request.notes,
    )

    result.setdefault("details", {})["rule_score_before_model"] = result.get("risk_score", 0.0)
    ai_result = {"enabled": False, "available": False, "model": None, "prediction": None,
                 "confidence": None, "status": "disabled"}
    from app.config import get_settings
    settings = get_settings()
    if settings.enable_invoice_ml and settings.invoice_ml_model:
        # Do not feed account numbers or IBANs into the text model. Notes are
        # redacted locally before inference; rule-based vendor/bank checks remain authoritative.
        safe_notes = detect_dlp(content=request.notes or "No invoice notes provided", redact=True)
        redacted_notes = safe_notes.get("details", {}).get("redacted_content", "No invoice notes provided")
        model_input = f"Invoice vendor={request.vendor_name}; amount={request.amount}; currency={request.currency}; notes={redacted_notes}"
        ai_result = await asyncio.to_thread(classify_text, "invoice", model_input)
        if ai_result.get("enabled"):
            fuse_model_signal(result, ai_result, signal_name="invoice_text_model")
    result.setdefault("details", {})["ai_scope_note"] = "Vendor/account comparison is rule-based. Optional model analyzes vendor, amount, currency and redacted notes only; it is not an independently validated invoice-fraud model."
    scan_resp = ScanResponse(
        scan_id=new_scan_id(),
        timestamp=utc_now(),
        scan_type=ScanType.INVOICE,
        risk_level=result["risk_level"],
        risk_score=result["risk_score"],
        flagged=result["flagged"],
        findings=result["findings"],
        details=result["details"],
        recommendation=result.get("recommendation"),
        ai_analysis={"invoice_text_model": MLAnalysis(**ai_result)},
        verdict=add_verdict(result),
    )

    record_scan_event(store, scan_resp, owner_from_request(http_request))

    if scan_resp.flagged:
        incident = Incident(
            scan_id=scan_resp.scan_id,
            scan_type=scan_resp.scan_type.value,
            risk_level=scan_resp.risk_level,
            risk_score=scan_resp.risk_score,
            summary=f"Invoice fraud risk: {', '.join(scan_resp.findings[:2])}",
            details=with_session(scan_resp.details, http_request),
            created_at=scan_resp.timestamp,
            owner_id=owner_from_request(http_request),
        )
        store.record(incident)

    return scan_resp


@inspect_router.post("/inspect-comparison", response_model=InvoiceInspectResponse)
async def inspect_invoice_comparison(
    request: InvoiceInspectRequest,
    http_request: Request,
    store: BaseIncidentStore = Depends(get_incident_store),
) -> InvoiceInspectResponse:
    """Compare an invoice's payee details with the trusted vendor record and flag BEC / bank-detail fraud."""
    owner_id = owner_from_request(http_request)
    fingerprint = resolve_session_fingerprint(http_request, request.session_id, owner_id)

    result = inspect_invoice(
        vendor_name=request.vendor_name, account_number=request.account_number, amount=request.amount,
        invoice_id=request.invoice_id, iban=request.iban, payment_destination=request.payment_destination,
        currency=request.currency, notes=request.notes, business_name=request.business_name,
        known_supplier_email=request.known_supplier_email,
    )
    floor = float(result["details"]["deterministic_floor"])

    # Optional invoice text model (same policy as /scan/invoice): redacted notes only, raise-only fusion.
    from app.config import get_settings
    settings = get_settings()
    ai_result = {"enabled": False, "available": False, "model": None, "prediction": None,
                 "confidence": None, "status": "disabled"}
    if settings.enable_invoice_ml and settings.invoice_ml_model:
        safe = detect_dlp(content=request.notes or "No invoice notes provided", redact=True)
        redacted = safe.get("details", {}).get("redacted_content", "No invoice notes provided")
        ai_result = await asyncio.to_thread(
            classify_text, "invoice",
            f"Invoice vendor={request.vendor_name}; amount={request.amount}; currency={request.currency}; notes={redacted}")
        if ai_result.get("enabled"):
            fuse_model_signal(result, ai_result, signal_name="invoice_text_model")
    # A low-risk model result can never pull the score under the destination-mismatch floor.
    if floor and result["risk_score"] < floor:
        result["risk_score"] = floor
        result["risk_level"] = score_to_risk_level(floor)
        result["flagged"] = True
    result["details"]["session_fingerprint"] = fingerprint
    result["details"]["ai_scope_note"] = ("Account/IBAN comparison is deterministic and authoritative. The optional model "
                                          "sees vendor, amount, currency and redacted notes only.")

    response = InvoiceInspectResponse(
        scan_id=new_scan_id(), timestamp=utc_now(), scan_type=ScanType.INVOICE,
        risk_level=result["risk_level"], risk_score=result["risk_score"], flagged=result["flagged"],
        findings=result["findings"], details=result["details"], recommendation=result["recommendation"],
        ai_analysis={"invoice_text_model": MLAnalysis(**ai_result)}, verdict=add_verdict(result),
        invoice_id=request.invoice_id, vendor_registered=result["vendor"] is not None,
        matched_vendor_id=(result["vendor"] or {}).get("id"), vendor_match_type=result["match_type"],
        payment_destination_verified=result["destination_verified"], alert_level=result["risk_level"],
        field_diff=result["diffs"], mismatched_fields=result["mismatched"],
        verification_email=result["email"] if result["flagged"] else None,
    )
    record_scan_event(store, response, owner_id)

    if response.flagged:
        store.record(Incident(
            scan_id=response.scan_id, scan_type=ScanType.INVOICE.value,
            risk_level=response.risk_level, risk_score=response.risk_score,
            summary=(f"Invoice BEC risk (invoice {request.invoice_id}): "
                     f"{', '.join(response.findings[:2])}"),
            details=response.details, created_at=response.timestamp, owner_id=owner_id,
        ))

    summary, _lead = evaluate_session_correlation(
        store, owner_id, fingerprint, raise_lead=response.flagged, trigger_module="invoice_shield")
    response.correlation = summary
    if response.flagged and summary.coordinated:
        score, level = escalate_result_risk(response.risk_score, summary)
        response.risk_score, response.risk_level, response.alert_level = score, level, level
        response.verdict = add_verdict({"risk_score": score, "findings": response.findings, "details": response.details})
        response.findings.insert(0, "Same session also raised risk in other OmniShield modules (coordinated BEC lead)")
    return response
