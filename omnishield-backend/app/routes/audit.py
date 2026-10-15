"""Owner-scoped, sanitized audit trail API."""
from typing import Any, Dict
from fastapi import APIRouter, Depends, Query, Request
from app.schemas import AuditListResponse
from app.services.auth import owner_from_request
from app.services.incident_store import BaseIncidentStore, get_incident_store

router = APIRouter(prefix="/api/v1/audit", tags=["Audit Trail"])


@router.get("", response_model=AuditListResponse)
def list_audit_events(
    request: Request,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    module: str | None = Query(default=None, min_length=1, max_length=30),
    result: str | None = Query(default=None, min_length=1, max_length=80),
    search: str | None = Query(default=None, min_length=1, max_length=100),
    store: BaseIncidentStore = Depends(get_incident_store),
) -> AuditListResponse:
    owner = owner_from_request(request)
    events = store.list_audit_events(limit=limit, offset=offset, owner_id=owner,
                                     module=module, result=result, search=search)
    total = store.count_audit_events(owner_id=owner, module=module, result=result, search=search)
    return AuditListResponse(events=events, total=total)


@router.get("/summary")
def audit_summary(request: Request, store: BaseIncidentStore = Depends(get_incident_store)) -> Dict[str, Any]:
    owner = owner_from_request(request)
    # The UI needs a compact summary; the event endpoint remains paginated.
    recent = store.list_audit_events(limit=1000, offset=0, owner_id=owner)
    module_counts: Dict[str, int] = {}
    result_counts: Dict[str, int] = {}
    for event in recent:
        module_counts[event.module] = module_counts.get(event.module, 0) + 1
        result_counts[event.result] = result_counts.get(event.result, 0) + 1
    return {"total": store.count_audit_events(owner_id=owner), "sampled_recent_events": len(recent),
            "module_counts": module_counts, "result_counts": result_counts,
            "note": "Counts reflect the latest 1,000 events for breakdowns; total is all retained events."}
