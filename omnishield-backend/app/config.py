"""Application configuration and settings."""

from dataclasses import dataclass
from functools import lru_cache
import os
from typing import Optional
from dotenv import load_dotenv

# Load local project .env during development; process environment still takes precedence.
load_dotenv(override=False)


@dataclass
class Settings:
    """Application settings with defaults matching documentation and test fixtures."""
    app_name: str = "OmniShield AI"
    environment: str = "development"
    debug: bool = False
    rate_limit_per_minute: int = 60
    # Storage settings
    incident_store: str = "memory"  # options: "memory", "sqlite"
    incident_store_path: str = "data/incidents.db"
    # Optional external integrations
    rook_service_url: Optional[str] = None
    api_key: Optional[str] = None
    enable_prompt_ml: bool = False
    prompt_ml_model: str = "protectai/deberta-v3-base-prompt-injection-v2"
    prompt_ml_threshold: float = 0.80
    # ProtectAI model card documents class 0=benign and class 1=injection.
    # Update this mapping when changing PROMPT_ML_MODEL.
    prompt_ml_labels: str = "SAFE,INJECTION"
    prompt_ml_local_files_only: bool = True
    # Task-specific local Transformer classifiers. Weights are never fetched at request
    # time unless *_LOCAL_FILES_ONLY is explicitly set to false.
    enable_sms_ml: bool = False
    sms_ml_model: str = "omarash/sms-spam-distilbert"
    sms_ml_labels: str = ""
    enable_email_ml: bool = False
    email_ml_model: str = "dima806/phishing-email-detection"
    email_ml_labels: str = ""
    enable_url_ml: bool = False
    url_ml_model: str = "ealvaradob/bert-finetuned-phishing"
    url_ml_labels: str = ""
    enable_invoice_ml: bool = False
    invoice_ml_model: Optional[str] = None
    invoice_ml_labels: str = ""
    domain_ml_threshold: float = 0.80
    text_ml_local_files_only: bool = True
    enable_dlp_ner: bool = False
    dlp_ner_model: str = "dslim/bert-base-NER"
    # Threat-intelligence and malware scanners are optional, explicit integrations.
    google_web_risk_api_key: Optional[str] = None
    web_risk_timeout_seconds: float = 3.0
    clamav_binary: str = "clamscan"
    clamav_timeout_seconds: float = 12.0
    max_upload_bytes: int = 15728640
    malware_inference_url: Optional[str] = None
    malware_inference_token: Optional[str] = None
    # 'off' is only appropriate for local development. Production must use api_key or supabase.
    auth_mode: str = "off"
    supabase_url: Optional[str] = None
    supabase_jwt_audience: str = "authenticated"
    cors_allowed_origins: str = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173"

    def __post_init__(self) -> None:
        # Normalize incident_store to lower-case string
        if self.incident_store:
            self.incident_store = self.incident_store.strip().lower()
        if self.rate_limit_per_minute < 0:
            self.rate_limit_per_minute = 0


def _read_probability(name: str, default: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
        return value if 0.0 <= value <= 1.0 else default
    except ValueError:
        return default


def _read_float(name: str, default: float, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
        return value if minimum <= value <= maximum else default
    except ValueError:
        return default


def _read_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return value if minimum <= value <= maximum else default
    except ValueError:
        return default


@lru_cache()
def get_settings() -> Settings:
    """Factory function for cached application settings read from environment."""
    rate_limit_raw = os.getenv("RATE_LIMIT_PER_MINUTE", "60")
    try:
        rate_limit = int(rate_limit_raw)
    except ValueError:
        rate_limit = 60

    debug_raw = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")
    try:
        prompt_ml_threshold = float(os.getenv("PROMPT_ML_THRESHOLD", "0.80"))
        if not 0.0 <= prompt_ml_threshold <= 1.0:
            prompt_ml_threshold = 0.80
    except ValueError:
        prompt_ml_threshold = 0.80

    return Settings(
        app_name=os.getenv("APP_NAME", "OmniShield AI"),
        environment=os.getenv("ENVIRONMENT", "development"),
        debug=debug_raw,
        rate_limit_per_minute=rate_limit,
        incident_store=os.getenv("INCIDENT_STORE", "memory"),
        incident_store_path=os.getenv("INCIDENT_STORE_PATH", "data/incidents.db"),
        rook_service_url=os.getenv("ROOK_SERVICE_URL") or None,
        api_key=os.getenv("API_KEY") or None,
        enable_prompt_ml=os.getenv("ENABLE_PROMPT_ML", "false").lower() in ("true", "1", "yes"),
        prompt_ml_model=os.getenv("PROMPT_ML_MODEL", "protectai/deberta-v3-base-prompt-injection-v2"),
        prompt_ml_threshold=prompt_ml_threshold,
        prompt_ml_labels=os.getenv("PROMPT_ML_LABELS", "SAFE,INJECTION"),
        prompt_ml_local_files_only=os.getenv("PROMPT_ML_LOCAL_FILES_ONLY", "true").lower() in ("true", "1", "yes"),
        cors_allowed_origins=os.getenv("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173"),
        enable_sms_ml=os.getenv("ENABLE_SMS_ML", "false").lower() in ("true", "1", "yes"),
        sms_ml_model=os.getenv("SMS_ML_MODEL", "omarash/sms-spam-distilbert"),
        sms_ml_labels=os.getenv("SMS_ML_LABELS", ""),
        enable_email_ml=os.getenv("ENABLE_EMAIL_ML", "false").lower() in ("true", "1", "yes"),
        email_ml_model=os.getenv("EMAIL_ML_MODEL", "dima806/phishing-email-detection"),
        email_ml_labels=os.getenv("EMAIL_ML_LABELS", ""),
        enable_url_ml=os.getenv("ENABLE_URL_ML", "false").lower() in ("true", "1", "yes"),
        url_ml_model=os.getenv("URL_ML_MODEL", "ealvaradob/bert-finetuned-phishing"),
        url_ml_labels=os.getenv("URL_ML_LABELS", ""),
        enable_invoice_ml=os.getenv("ENABLE_INVOICE_ML", "false").lower() in ("true", "1", "yes"),
        invoice_ml_model=os.getenv("INVOICE_ML_MODEL") or None,
        invoice_ml_labels=os.getenv("INVOICE_ML_LABELS", ""),
        domain_ml_threshold=_read_probability("DOMAIN_ML_THRESHOLD", 0.80),
        text_ml_local_files_only=os.getenv("TEXT_ML_LOCAL_FILES_ONLY", "true").lower() in ("true", "1", "yes"),
        enable_dlp_ner=os.getenv("ENABLE_DLP_NER", "false").lower() in ("true", "1", "yes"),
        dlp_ner_model=os.getenv("DLP_NER_MODEL", "dslim/bert-base-NER"),
        google_web_risk_api_key=os.getenv("GOOGLE_WEB_RISK_API_KEY") or None,
        web_risk_timeout_seconds=_read_float("WEB_RISK_TIMEOUT_SECONDS", 3.0, 0.5, 15.0),
        clamav_binary=os.getenv("CLAMAV_BINARY", "clamscan"),
        clamav_timeout_seconds=_read_float("CLAMAV_TIMEOUT_SECONDS", 12.0, 1.0, 60.0),
        max_upload_bytes=_read_int("MAX_UPLOAD_BYTES", 15728640, 1024, 52428800),
        malware_inference_url=os.getenv("MALWARE_INFERENCE_URL") or None,
        malware_inference_token=os.getenv("MALWARE_INFERENCE_TOKEN") or None,
        auth_mode=os.getenv("AUTH_MODE", "off").strip().lower(),
        supabase_url=os.getenv("SUPABASE_URL") or None,
        supabase_jwt_audience=os.getenv("SUPABASE_JWT_AUDIENCE", "authenticated"),
    )
