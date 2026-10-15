"""Incident management and reporting routes."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from app.schemas import Incident, IncidentListResponse
from app.services.incident_store import BaseIncidentStore, get_incident_store
from app.services.auth import owner_from_request, is_admin_request
from app.services.audit_trail import correlate_incidents, record_scan_event
from app.schemas import AuditEvent, RiskLevel, utc_now

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])


@router.get("", response_model=IncidentListResponse)
def list_incidents(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    store: BaseIncidentStore = Depends(get_incident_store),
) -> IncidentListResponse:
    """Retrieve list of flagged security incidents with pagination."""
    owner_id = owner_from_request(request)
    incidents = store.list_incidents(limit=limit, offset=offset, owner_id=owner_id)
    total = store.count(owner_id=owner_id)
    return IncidentListResponse(incidents=incidents, total=total)


@router.get("/correlations")
def incident_correlations(
    request: Request,
    store: BaseIncidentStore = Depends(get_incident_store),
) -> dict:
    """Return possible shared domains/vendor IDs across recent incidents (investigation leads only)."""
    incidents = store.list_incidents(limit=100, offset=0, owner_id=owner_from_request(request))
    return {"correlations": correlate_incidents(incidents), "incident_sample_size": len(incidents),
            "note": "Correlations are investigative leads, not proof of attribution or a confirmed campaign."}


@router.get("/{incident_id}", response_model=Incident)
def get_incident(
    incident_id: str,
    request: Request,
    store: BaseIncidentStore = Depends(get_incident_store),
) -> Incident:
    """Retrieve details for a specific incident by ID."""
    incident = store.get_incident(incident_id, owner_id=owner_from_request(request))
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident with ID '{incident_id}' not found",
        )
    return incident


@router.delete("", status_code=status.HTTP_204_NO_CONTENT)
def clear_incidents(
    request: Request,
    store: BaseIncidentStore = Depends(get_incident_store),
) -> None:
    """Clear current owner's incidents; production Supabase users need an admin app_metadata role."""
    if not is_admin_request(request):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Administrator role required")
    owner = owner_from_request(request)
    store.clear(owner_id=owner)
    store.record_audit_event(AuditEvent(module="incident_center", action="incidents_cleared",
        result="recorded", risk_level=RiskLevel.SAFE, risk_score=0.0,
        summary="Incident records cleared by an authorized administrator",
        details={"scope": "current_owner"}, owner_id=owner, created_at=utc_now()))
