"""Reduce sensitive material before persisting incident/audit details."""
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SENSITIVE_KEYS = ("text", "content", "redacted_content", "payload_excerpt", "raw_text", "original_text", "prompt", "message_body", "raw_message", "matched_text", "raw_payload", "token_value", "api_key_value", "access_token", "refresh_token", "authorization", "secret", "password", "api_key", "private_key", "client_secret")
_SECRET_QUERY_WORDS = ("token", "key", "secret", "password", "auth", "session", "code", "signature", "email", "phone")
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I)
_BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*")
_URL = re.compile(r"(?i)https?://[^\s<>\"']+")


def _sanitize_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if not parts.scheme or not parts.netloc:
            return value
        pairs = []
        for key, val in parse_qsl(parts.query, keep_blank_values=True):
            pairs.append((key, "[REDACTED]" if any(w in key.lower() for w in _SECRET_QUERY_WORDS) else val))
        # Never keep credential-style userinfo (user:password@host) or fragments.
        safe_netloc = parts.netloc.rsplit("@", 1)[-1]
        return urlunsplit((parts.scheme, safe_netloc, parts.path, urlencode(pairs), ""))
    except Exception:
        return "[REDACTED_URL]"


def sanitize_for_audit(value: Any, key: str = "") -> Any:
    normalized_key = re.sub(r"[^a-z0-9]", "", key.lower())
    sensitive_key_names = {re.sub(r"[^a-z0-9]", "", item.lower()) for item in _SENSITIVE_KEYS}
    if normalized_key in sensitive_key_names:
        return "[REDACTED_FOR_AUDIT]"
    if isinstance(value, dict):
        return {str(k): sanitize_for_audit(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_for_audit(v, key) for v in value[:100]]
    if isinstance(value, str):
        text = _BEARER.sub("Bearer [REDACTED]", value)
        text = _EMAIL.sub("[EMAIL_REDACTED]", text)
        text = _URL.sub(lambda match: _sanitize_url(match.group(0)), text)
        return text[:2000]
    return value
