"""Additional scan routes: SMS/message, email, URL/domain and QR payloads."""
from __future__ import annotations
import asyncio
from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, status
from app.config import get_settings
from app.schemas import (
    EmailScanRequest, Incident, MLAnalysis, MessageScanRequest, QRScanRequest,
    RiskLevel, ScanResponse, ScanType, URLScanRequest, new_scan_id, utc_now,
)
from app.services.auth import owner_from_request
from app.services.audit_trail import record_scan_event
from app.services.session_correlation import with_session
from app.services.decision_engine import add_verdict, fuse_model_signal
from app.services.incident_store import BaseIncidentStore, get_incident_store
from app.services.phishing_analyzer import analyze_phishing
from app.services.risk_engine import score_to_risk_level
from app.services.text_model import classify_text
from app.services.threat_intel import lookup_url
from app.services.url_analyzer import analyze_url
from app.services.qr_decoder import decode_qr_image

router = APIRouter(prefix="/api/v1/scan", tags=["Additional Scanners"])


def _as_ml_analysis(result: Dict[str, Any]) -> MLAnalysis:
    return MLAnalysis(
        enabled=bool(result.get("enabled")), available=bool(result.get("available")),
        model=result.get("model"), prediction=result.get("prediction"),
        confidence=result.get("confidence"), status=str(result.get("status", "unknown")),
    )


async def _enrich_urls(result: Dict[str, Any], urls: List[str]) -> None:
    """Check at most five URLs with local URL model and optional Web Risk."""
    url_ml_results: List[Dict[str, Any]] = []
    threat_results: List[Dict[str, Any]] = []
    cleaned = list(dict.fromkeys([u.strip() for u in urls if u and u.strip()]))[:5]
    if not cleaned:
        return
    for url in cleaned:
        heuristic = analyze_url(url)
        model_signal = await asyncio.to_thread(classify_text, "url", url)
        if model_signal.get("enabled"):
            url_ml_results.append({"url": heuristic.get("url", url), **model_signal})
            if heuristic.get("valid"):
                fuse_model_signal(result, model_signal, signal_name="url_phishing")
        else:
            url_ml_results.append({"url": heuristic.get("url", url), **model_signal})
        intel = await lookup_url(heuristic.get("url", url)) if heuristic.get("valid") else {
            "provider": "google_web_risk", "status": "not_checked_invalid_url", "match": None, "threat_types": []
        }
        threat_results.append({"url": heuristic.get("url", url), **intel})
        if intel.get("match") is True:
            result["risk_score"] = round(max(float(result.get("risk_score", 0)), 0.99), 3)
            result["risk_level"] = RiskLevel.CRITICAL
            result["flagged"] = True
            finding = "Configured threat-intelligence provider matched a known unsafe URL"
            if finding not in result.setdefault("findings", []):
                result["findings"].append(finding)
    result.setdefault("details", {})["url_model_results"] = url_ml_results
    result["details"]["url_threat_intelligence"] = threat_results
    result["details"]["url_checks_note"] = "URLs were analyzed as text; OmniShield did not open, resolve, or visit them."


def _response_and_record(
    result: Dict[str, Any], scan_type: ScanType, http_request: Request,
    store: BaseIncidentStore, ai: Dict[str, MLAnalysis] | None = None,
    checked_artifact: bool = True,
) -> ScanResponse:
    verdict = add_verdict(result, checked_artifact=checked_artifact)
    response = ScanResponse(
        scan_id=new_scan_id(), timestamp=utc_now(), scan_type=scan_type,
        risk_level=result["risk_level"], risk_score=result["risk_score"],
        flagged=bool(result.get("flagged")), findings=result.get("findings", []),
        details=result.get("details", {}), recommendation=result.get("recommendation"),
        ai_analysis=ai or {}, verdict=verdict,
    )
    record_scan_event(store, response, owner_from_request(http_request))
    if response.flagged:
        store.record(Incident(
            scan_id=response.scan_id, scan_type=response.scan_type.value,
            risk_level=response.risk_level, risk_score=response.risk_score,
            summary=f"{scan_type.value.title()} risk: {', '.join(response.findings[:2]) or response.verdict}",
            details=with_session(response.details, http_request), created_at=response.timestamp,
            owner_id=owner_from_request(http_request),
        ))
    return response


async def _scan_communication(
    text: str, *, task: str, scan_type: ScanType, sender: str | None,
    subject: str | None, urls: List[str], http_request: Request,
    store: BaseIncidentStore,
) -> ScanResponse:
    result = analyze_phishing(text=text, sender=sender, subject=subject, explicit_urls=urls)
    # Preserve the rule-only score so the final model contribution is auditable.
    result.setdefault("details", {})["rule_score_before_model"] = result.get("risk_score", 0.0)
    model_result = await asyncio.to_thread(classify_text, task, f"{subject or ''}\n{sender or ''}\n{text}".strip())
    if model_result.get("enabled"):
        fuse_model_signal(result, model_result, signal_name=f"{task}_classifier")
    discovered_urls = [x.get("url", "") for x in result.get("details", {}).get("url_analysis", [])]
    await _enrich_urls(result, (urls or []) + discovered_urls)
    if result.get("flagged"):
        result["recommendation"] = "Do not click links, share credentials, or send money until verified through a trusted channel."
    ai = {task: _as_ml_analysis(model_result)}
    for item in result.get("details", {}).get("url_model_results", []):
        # Include a single representative URL-model status in the dashboard response.
        if item.get("enabled"):
            ai["url_phishing"] = _as_ml_analysis(item)
            break
    return _response_and_record(result, scan_type, http_request, store, ai)


@router.post("/message", response_model=ScanResponse)
async def scan_message(request: MessageScanRequest, http_request: Request,
                       store: BaseIncidentStore = Depends(get_incident_store)) -> ScanResponse:
    """Analyze SMS/chat messages for scams and smishing."""
    return await _scan_communication(request.text, task="sms", scan_type=ScanType.MESSAGE,
        sender=request.sender, subject=None, urls=[], http_request=http_request, store=store)


@router.post("/email", response_model=ScanResponse)
async def scan_email(request: EmailScanRequest, http_request: Request,
                     store: BaseIncidentStore = Depends(get_incident_store)) -> ScanResponse:
    """Analyze email text, sender, subject and links for phishing and spoofing cues."""
    return await _scan_communication(request.text, task="email", scan_type=ScanType.EMAIL,
        sender=request.sender, subject=request.subject, urls=request.urls,
        http_request=http_request, store=store)


@router.post("/url", response_model=ScanResponse)
async def scan_url(request: URLScanRequest, http_request: Request,
                   store: BaseIncidentStore = Depends(get_incident_store)) -> ScanResponse:
    """Inspect a URL locally and optionally look it up in configured threat intel."""
    result_url = analyze_url(request.url)
    score = float(result_url.get("score", 0.0))
    findings = list(result_url.get("flags", []))
    result: Dict[str, Any] = {
        "risk_score": score, "risk_level": score_to_risk_level(score),
        "flagged": score >= 0.45,
        "findings": findings,
        "details": {"url_analysis": result_url, "rule_score_before_model": score},
        "recommendation": "Do not open suspicious links; verify the domain using a trusted channel.",
    }
    model_result = await asyncio.to_thread(classify_text, "url", request.url)
    if model_result.get("enabled"):
        fuse_model_signal(result, model_result, signal_name="url_phishing")
    intel = await lookup_url(result_url.get("url", request.url)) if result_url.get("valid") else {
        "provider": "google_web_risk", "status": "not_checked_invalid_url", "match": None, "threat_types": []
    }
    result["details"]["threat_intelligence"] = intel
    if intel.get("match") is True:
        result["risk_score"] = 0.99
        result["risk_level"] = RiskLevel.CRITICAL
        result["flagged"] = True
        result["findings"].append("Configured threat-intelligence provider matched a known unsafe URL")
        result["recommendation"] = "Do not open this URL. Block it in your security controls and investigate related messages."
    if not result_url.get("valid"):
        result["findings"].append("The supplied value is not a supported HTTP or HTTPS URL")
        result["recommendation"] = "Enter a full HTTP(S) URL to run URL and threat-intelligence checks."
    ai = {"url_phishing": _as_ml_analysis(model_result)}
    return _response_and_record(result, ScanType.URL, http_request, store, ai,
                                checked_artifact=bool(result_url.get("valid")) or bool(intel.get("match")))


def _scan_qr_payload_result(payload: str) -> tuple[Dict[str, Any], Dict[str, MLAnalysis]]:
    settings = get_settings()
    result = analyze_url(payload) if payload.startswith(("http://", "https://")) or ("." in payload and " " not in payload) else None
    if result is not None:
        base_score = float(result.get("score", 0.0))
        base = {"risk_score": base_score, "risk_level": score_to_risk_level(base_score),
                "flagged": base_score >= 0.45, "findings": list(result.get("flags", [])),
                "details": {"payload_type": "url_or_domain", "payload_excerpt": payload[:120], "url_analysis": result, "rule_score_before_model": base_score,
                            "url_checks_note": "QR destination URL was analyzed as text; OmniShield did not open or visit it."},
                "recommendation": "Verify the destination domain before opening a link encoded in a QR code."}
        return base, {}
    scheme = payload.split(":", 1)[0].lower() if ":" in payload else "plain_text"
    # Payment QR contents are not proof of fraud; they require recipient/amount verification.
    is_payment = scheme in {"upi", "bitcoin", "ethereum", "payto"} or payload.lower().startswith("upi://pay")
    score = 0.25 if is_payment else 0.05
    findings = ["QR code contains a payment payload; verify recipient and amount before authorizing"] if is_payment else []
    return ({"risk_score": score, "risk_level": score_to_risk_level(score), "flagged": False,
             "findings": findings, "details": {"payload_type": "payment_uri" if is_payment else "text_or_other_scheme",
             "scheme": scheme, "payload_excerpt": payload[:120],
             "note": "QR payloads are untrusted input. No embedded URL or payment action was opened."},
             "recommendation": "Confirm the recipient and amount in your trusted payment app before approving."
             if is_payment else "Do not follow unknown QR instructions or submit sensitive information."}, {})


@router.post("/qr", response_model=ScanResponse)
async def scan_qr(request: QRScanRequest, http_request: Request,
                  store: BaseIncidentStore = Depends(get_incident_store)) -> ScanResponse:
    """Analyze a decoded QR payload. This endpoint does not navigate to its destination."""
    payload = request.payload.strip()
    result, _ = _scan_qr_payload_result(payload)
    ai: Dict[str, MLAnalysis] = {}
    if result["details"].get("payload_type") == "url_or_domain":
        model_result = await asyncio.to_thread(classify_text, "url", payload)
        if model_result.get("enabled"):
            fuse_model_signal(result, model_result, signal_name="qr_destination_url")
        result["details"]["threat_intelligence"] = await lookup_url(result["details"]["url_analysis"].get("url", payload)) if result["details"]["url_analysis"].get("valid") else {
            "provider": "google_web_risk", "status": "not_checked_invalid_url", "match": None, "threat_types": []
        }
        if result["details"]["threat_intelligence"].get("match") is True:
            result["risk_score"] = 0.99
            result["risk_level"] = RiskLevel.CRITICAL
            result["flagged"] = True
            result["findings"].append("Configured threat-intelligence provider matched a known unsafe QR destination")
        ai["url_phishing"] = _as_ml_analysis(model_result)
    return _response_and_record(result, ScanType.QR, http_request, store, ai,
                                checked_artifact=result["details"].get("payload_type") == "url_or_domain")


@router.post("/qr/image", response_model=ScanResponse)
async def scan_qr_image(http_request: Request, file: UploadFile = File(...),
                        store: BaseIncidentStore = Depends(get_incident_store)) -> ScanResponse:
    """Decode QR image bytes with OpenCV, then scan the decoded payload without opening links."""
    settings = get_settings()
    payload = await file.read(settings.max_upload_bytes + 1)
    await file.close()
    if len(payload) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="QR image exceeds the configured upload size limit")
    if not payload:
        raise HTTPException(status_code=400, detail="Empty image upload")
    decoded = decode_qr_image(payload)
    if not decoded:
        result = {"risk_score": 0.0, "risk_level": RiskLevel.LOW, "flagged": False,
                  "findings": ["No readable QR code was detected in the uploaded image"],
                  "details": {"scanner_status": "unavailable", "payload_type": "unknown"},
                  "recommendation": "Try a clearer, tightly cropped image. No QR destination was evaluated."}
        return _response_and_record(result, ScanType.QR, http_request, store, {}, checked_artifact=False)
    result, _ = _scan_qr_payload_result(decoded)
    result["details"]["qr_decoder"] = "OpenCV QRCodeDetector"
    result["details"]["file_name"] = (file.filename or "qr-upload")[:128]
    ai: Dict[str, MLAnalysis] = {}
    if result["details"].get("payload_type") == "url_or_domain":
        model_result = await asyncio.to_thread(classify_text, "url", decoded)
        if model_result.get("enabled"):
            fuse_model_signal(result, model_result, signal_name="qr_destination_url")
        result["details"]["threat_intelligence"] = await lookup_url(result["details"]["url_analysis"].get("url", decoded)) if result["details"]["url_analysis"].get("valid") else {
            "provider": "google_web_risk", "status": "not_checked_invalid_url", "match": None, "threat_types": []
        }
        if result["details"]["threat_intelligence"].get("match") is True:
            result["risk_score"] = 0.99; result["risk_level"] = RiskLevel.CRITICAL; result["flagged"] = True
            result["findings"].append("Configured threat-intelligence provider matched a known unsafe QR destination")
        ai["url_phishing"] = _as_ml_analysis(model_result)
    return _response_and_record(result, ScanType.QR, http_request, store, ai,
                                checked_artifact=result["details"].get("payload_type") == "url_or_domain")


@router.get("/ai-status", tags=["AI Status"])
def ai_status() -> Dict[str, Any]:
    """Report configured AI integrations without disclosing credentials or local file paths."""
    s = get_settings()
    def item(enabled: bool, model: str | None, status: str) -> Dict[str, Any]:
        return {"enabled": enabled, "model": model if enabled else None, "status": status if enabled else "disabled"}
    # Report runtime dependency availability separately from configuration. This endpoint
    # never loads large weights or triggers network downloads as a side effect.
    from importlib.util import find_spec
    torch_available = find_spec("torch") is not None
    transformers_available = find_spec("transformers") is not None
    def model_item(enabled: bool, model: str | None, purpose: str, needs_transformers: bool = True) -> Dict[str, Any]:
        configured = bool(enabled and model)
        dependencies_ok = (torch_available and transformers_available) if needs_transformers else True
        if not enabled:
            runtime_status = "disabled"
        elif not model:
            runtime_status = "model_not_configured"
        elif not dependencies_ok:
            runtime_status = "dependencies_missing"
        else:
            runtime_status = "configured_lazy_load_on_first_scan"
        return {
            "enabled": bool(enabled), "model": model if configured else None,
            "status": runtime_status, "purpose": purpose,
            "dependencies_available": dependencies_ok if needs_transformers else None,
            "weights_verified": False,
            "note": "Model weights are verified only when a scan attempts inference; see that scan's AI analysis status."
                if configured and dependencies_ok else None,
        }
    return {
        "text_models": {
            "sms": model_item(s.enable_sms_ml, s.sms_ml_model, "Classify SMS/chat text"),
            "email": model_item(s.enable_email_ml, s.email_ml_model, "Classify email text"),
            "url": model_item(s.enable_url_ml, s.url_ml_model, "Classify URL strings"),
            "dlp_ner": model_item(s.enable_dlp_ner, s.dlp_ner_model, "Optional named-entity detection"),
            "prompt_injection": model_item(s.enable_prompt_ml, s.prompt_ml_model, "Detect prompt injection"),
            "invoice": model_item(s.enable_invoice_ml, s.invoice_ml_model, "Optional invoice text classification"),
        },
        "runtime_dependencies": {"torch_installed": torch_available, "transformers_installed": transformers_available},
        "threat_intelligence": {"provider": "google_web_risk", "status": "configured" if s.google_web_risk_api_key else "not_configured"},
        "malware": {"clamav_binary_configured": bool(s.clamav_binary), "optional_ml_endpoint_configured": bool(s.malware_inference_url)},
        "model_loading_policy": "local_files_only" if s.text_ml_local_files_only else "network_downloads_allowed",
        "safety_note": "Enabled/configured does not mean weights loaded or a model prediction was produced. Inspect each scan response's ai_analysis status.",
    }
