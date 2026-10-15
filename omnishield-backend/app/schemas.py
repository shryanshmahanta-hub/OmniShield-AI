"""Pydantic schemas and utility functions for requests and responses."""

from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Optional
import uuid
from pydantic import BaseModel, Field, ConfigDict


def new_scan_id() -> str:
    """Generate a unique scan identifier."""
    return f"scan_{uuid.uuid4().hex[:12]}"


def utc_now() -> datetime:
    """Return current timestamp with UTC timezone."""
    return datetime.now(timezone.utc)


class RiskLevel(str, Enum):
    """Enumeration of risk levels."""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanType(str, Enum):
    """Supported scan types."""
    PHISHING = "phishing"
    INJECTION = "injection"
    DLP = "dlp"
    INVOICE = "invoice"
    MESSAGE = "message"
    EMAIL = "email"
    URL = "url"
    QR = "qr"
    FILE = "file"
    CHAT_GUARD = "chat_guard"
    HONEYPOT = "honeypot"


class MLAnalysis(BaseModel):
    """Optional, explicit status for prompt-injection model inference."""
    enabled: bool
    available: bool
    model: Optional[str] = None
    prediction: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    status: str


class ScanResponse(BaseModel):
    """Standardized response schema for all security scans."""
    model_config = ConfigDict(populate_by_name=True)
    scan_id: str = Field(default_factory=new_scan_id)
    timestamp: datetime = Field(default_factory=utc_now)
    scan_type: ScanType
    risk_level: RiskLevel
    risk_score: float = Field(ge=0.0, le=1.0)
    flagged: bool
    findings: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    recommendation: Optional[str] = None
    ml_analysis: Optional[MLAnalysis] = Field(default=None, alias="mlAnalysis")
    ai_analysis: Dict[str, MLAnalysis] = Field(default_factory=dict, alias="aiAnalysis")
    # A 'low risk' result is not a guarantee of safety. Use 'unknown' when no
    # scanner/model actually inspected the relevant artifact.
    verdict: str = "unknown"


# --- Scan Request Schemas ---

class PhishingScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=30000)
    sender: Optional[str] = Field(default=None, max_length=320)
    subject: Optional[str] = Field(default=None, max_length=998)
    urls: List[Annotated[str, Field(max_length=4096)]] = Field(default_factory=list, max_length=20)


class InjectionScanRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=20000)
    context: Optional[str] = Field(default=None, max_length=8000)


class DLPScanRequest(BaseModel):
    content: str = Field(min_length=1, max_length=50000)
    redact: bool = False


class InvoiceScanRequest(BaseModel):
    vendor_name: str = Field(min_length=1, max_length=200)
    amount: float = Field(ge=0, le=1000000000000)
    iban: Optional[str] = Field(default=None, max_length=64)
    account_number: Optional[str] = Field(default=None, max_length=128)
    currency: str = Field(default="USD", min_length=3, max_length=3)
    notes: Optional[str] = Field(default=None, max_length=10000)


# --- Incident Schemas ---

class Incident(BaseModel):
    owner_id: Optional[str] = None
    incident_id: str = Field(default_factory=lambda: f"inc_{uuid.uuid4().hex[:10]}")
    scan_id: str
    scan_type: str
    risk_level: RiskLevel
    risk_score: float
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class IncidentListResponse(BaseModel):
    incidents: List[Incident]
    total: int


class URLScanRequest(BaseModel):
    url: str = Field(min_length=1, max_length=4096)


class MessageScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=30000)
    sender: Optional[str] = Field(default=None, max_length=320)


class EmailScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=30000)
    sender: Optional[str] = Field(default=None, max_length=320)
    subject: Optional[str] = Field(default=None, max_length=998)
    urls: List[Annotated[str, Field(max_length=4096)]] = Field(default_factory=list, max_length=20)


class QRScanRequest(BaseModel):
    # For native/browser QR scanning. The frontend decodes locally and sends the
    # decoded payload; raw images can instead be sent to /qr/image.
    payload: str = Field(min_length=1, max_length=4096)



class AuditEvent(BaseModel):
    """Sanitized immutable-by-application audit event (not a tamper-proof ledger)."""
    event_id: str = Field(default_factory=lambda: f"log_{uuid.uuid4().hex[:12]}")
    scan_id: Optional[str] = None
    module: str
    action: str
    result: str
    risk_level: RiskLevel = RiskLevel.SAFE
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    owner_id: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)


class AuditListResponse(BaseModel):
    events: List[AuditEvent]
    total: int



# ---------------------------------------------------------------------------
# Cross-module session correlation (shared by Chat Guard, Invoice Inspector, Honeypot)
# ---------------------------------------------------------------------------

class CorrelationSummary(BaseModel):
    """Result of checking whether one session has raised risk in several modules.

    A coordinated lead is an investigation lead, not proof of attribution.
    """
    session_fingerprint: str
    window_minutes: int
    modules_flagged: List[str] = Field(default_factory=list)
    coordinated: bool = False
    lead_label: Optional[str] = None
    lead_incident_id: Optional[str] = None
    linked_incident_ids: List[str] = Field(default_factory=list)
    escalated_risk_level: Optional[RiskLevel] = None
    escalated_risk_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    note: str = ("Session correlation is an investigative lead based on a shared session identifier "
                 "or client fingerprint; it is not proof of attribution.")


# ---------------------------------------------------------------------------
# 1. WhatsApp / SMS Order Guard
# ---------------------------------------------------------------------------

class ChatChannel(str, Enum):
    WHATSAPP = "whatsapp"
    SMS = "sms"
    OTHER = "other"


class ChatGuardScanRequest(BaseModel):
    text: str = Field(min_length=1, max_length=10000)
    channel: ChatChannel = ChatChannel.WHATSAPP
    sender: Optional[str] = Field(default=None, max_length=320, description="Phone number, handle or email of the sender")
    sender_role: Literal["customer", "vendor", "unknown"] = "unknown"
    store_name: Optional[str] = Field(default=None, max_length=120)
    trusted_domains: List[Annotated[str, Field(max_length=253)]] = Field(
        default_factory=list, max_length=20,
        description="Domains the store owner knows are legitimate (own shop, courier, supplier portals)")
    session_id: Optional[str] = Field(default=None, max_length=128)


class LookalikeDomain(BaseModel):
    hostname: str
    impersonates: str
    technique: str


class AlertNotification(BaseModel):
    priority: Literal["normal", "urgent"]
    channels: List[str]
    push_title: str
    push_body: str
    sms_text: str = Field(max_length=160)
    whatsapp_text: str


class StoreOwnerAlert(BaseModel):
    """Structured payload ready for push / WhatsApp / SMS notification fan-out."""
    alert_id: str = Field(default_factory=lambda: f"alert_{uuid.uuid4().hex[:10]}")
    dedupe_key: str
    severity: Literal["info", "warning", "high", "critical"]
    requires_immediate_attention: bool
    title: str
    headline: str
    channel: ChatChannel
    sender_masked: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    do_not: List[str] = Field(default_factory=list)
    suggested_automation: Dict[str, bool] = Field(default_factory=dict)
    notification: AlertNotification
    generated_at: datetime = Field(default_factory=utc_now)


class ChatGuardResponse(ScanResponse):
    scan_type: ScanType = ScanType.CHAT_GUARD
    channel: ChatChannel
    flagged_keywords: List[str] = Field(default_factory=list)
    tactics: List[str] = Field(default_factory=list)
    lookalike_domains: List[LookalikeDomain] = Field(default_factory=list)
    store_owner_alert: StoreOwnerAlert
    correlation: Optional[CorrelationSummary] = None


# ---------------------------------------------------------------------------
# 2. Invoice BEC comparison inspector
# ---------------------------------------------------------------------------

class InvoiceInspectRequest(BaseModel):
    vendor_name: str = Field(min_length=1, max_length=200)
    account_number: str = Field(min_length=1, max_length=128)
    amount: float = Field(ge=0, le=1000000000000)
    invoice_id: str = Field(min_length=1, max_length=64)
    iban: Optional[str] = Field(default=None, max_length=64)
    payment_destination: Optional[str] = Field(
        default=None, max_length=128,
        description="Any other payee identifier on the invoice (UPI id, wallet, beneficiary account)")
    currency: str = Field(default="USD", min_length=3, max_length=3)
    notes: Optional[str] = Field(default=None, max_length=10000)
    business_name: Optional[str] = Field(default=None, max_length=120, description="Your business name, used to sign the draft email")
    known_supplier_email: Optional[str] = Field(
        default=None, max_length=320,
        description="A supplier address YOU already trust. Never the address that sent the invoice.")
    session_id: Optional[str] = Field(default=None, max_length=128)


class FieldDiff(BaseModel):
    field: str
    submitted: Optional[str] = None
    registered: Optional[str] = None
    status: Literal["match", "mismatch", "not_provided", "not_on_file", "exceeds_limit"]
    severity: Literal["info", "warning", "critical"]
    note: Optional[str] = None


class VerificationEmailDraft(BaseModel):
    to: Optional[str] = None
    to_note: str
    subject: str
    body: str
    send_guidance: str


class InvoiceInspectResponse(ScanResponse):
    scan_type: ScanType = ScanType.INVOICE
    invoice_id: str
    vendor_registered: bool
    matched_vendor_id: Optional[str] = None
    vendor_match_type: Literal["exact", "lookalike", "none"] = "none"
    payment_destination_verified: bool = False
    alert_level: RiskLevel
    field_diff: List[FieldDiff] = Field(default_factory=list)
    mismatched_fields: List[str] = Field(default_factory=list)
    verification_email: Optional[VerificationEmailDraft] = None
    correlation: Optional[CorrelationSummary] = None


# ---------------------------------------------------------------------------
# 3. Active Agent Honeypot
# ---------------------------------------------------------------------------

class HoneypotPersona(str, Enum):
    HR = "hr"
    INVENTORY = "inventory"


class HoneypotChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    persona: HoneypotPersona = HoneypotPersona.HR
    session_id: Optional[str] = Field(default=None, max_length=128)


class HoneypotChatResponse(ScanResponse):
    scan_type: ScanType = ScanType.HONEYPOT
    persona: HoneypotPersona
    assistant_reply: str
    blocked: bool
    attack_vectors: List[str] = Field(default_factory=list)
    attack_explainer: List[str] = Field(default_factory=list)
    incident_id: Optional[str] = None
    audit_event_id: Optional[str] = None
    correlation: Optional[CorrelationSummary] = None
