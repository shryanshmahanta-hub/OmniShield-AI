"""Uploaded-file malware triage route. Files are scanned locally or by an explicitly configured model endpoint."""
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from app.config import get_settings
from app.schemas import Incident, RiskLevel, ScanResponse, ScanType, new_scan_id, utc_now
from app.services.auth import owner_from_request
from app.services.audit_trail import record_scan_event
from app.services.session_correlation import with_session
from app.services.decision_engine import add_verdict
from app.services.incident_store import BaseIncidentStore, get_incident_store
from app.services.malware_scanner import scan_file

router = APIRouter(prefix="/api/v1/scan", tags=["Malware Scanner"])


@router.post("/file", response_model=ScanResponse)
async def scan_uploaded_file(
    http_request: Request,
    file: UploadFile = File(...),
    store: BaseIncidentStore = Depends(get_incident_store),
) -> ScanResponse:
    """Scan a file without executing it. Hashes are always computed; ClamAV/ML are optional."""
    settings = get_settings()
    filename = (file.filename or "upload.bin").replace("\\", "/").split("/")[-1][:128]
    payload = await file.read(settings.max_upload_bytes + 1)
    await file.close()
    if len(payload) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_upload_bytes} byte upload limit")
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    result = await scan_file(filename, payload)
    verdict = add_verdict(result, checked_artifact=bool(result.get("checked_artifact")))
    # File details contain the digest and scanner output, never the uploaded bytes.
    response = ScanResponse(
        scan_id=new_scan_id(), timestamp=utc_now(), scan_type=ScanType.FILE,
        risk_level=result["risk_level"], risk_score=result["risk_score"], flagged=result["flagged"],
        findings=result["findings"], details=result["details"], recommendation=result.get("recommendation"),
        ai_analysis={"malware_deep_learning": {
            "enabled": bool(result["details"]["model_signal"].get("enabled")),
            "available": bool(result["details"]["model_signal"].get("available")),
            "model": result["details"]["model_signal"].get("model"),
            "prediction": result["details"]["model_signal"].get("prediction"),
            "confidence": result["details"]["model_signal"].get("confidence"),
            "status": result["details"]["model_signal"].get("status", "not_configured"),
        }},
        verdict=verdict,
    )
    record_scan_event(store, response, owner_from_request(http_request))

    if response.flagged:
        store.record(Incident(
            scan_id=response.scan_id, scan_type=response.scan_type.value, risk_level=response.risk_level,
            risk_score=response.risk_score, summary=f"File scanner raised a risk: {', '.join(response.findings[:2])}",
            details=with_session(response.details, http_request), created_at=response.timestamp, owner_id=owner_from_request(http_request),
        ))
    return response
