"""Small auth gateway supporting server API keys or Supabase Auth JWTs."""
from __future__ import annotations
import time
from typing import Any, Dict, Optional
import httpx
from fastapi import Request
from app.config import get_settings

_jwks_cache: Dict[str, Any] = {}
_jwks_cache_expires = 0.0
_jwks_cache_url = ""


async def _get_jwks(url: str) -> Dict[str, Any]:
    global _jwks_cache, _jwks_cache_expires, _jwks_cache_url
    now = time.time()
    normalized_url = url.rstrip("/")
    if _jwks_cache and _jwks_cache_url == normalized_url and now < _jwks_cache_expires:
        return _jwks_cache
    async with httpx.AsyncClient(timeout=3.0) as client:
        response = await client.get(url.rstrip("/") + "/auth/v1/.well-known/jwks.json")
        response.raise_for_status()
        data = response.json()
    keys = data.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("Invalid JWKS response")
    _jwks_cache = {str(k.get("kid")): k for k in keys if k.get("kid")}
    _jwks_cache_url = normalized_url
    _jwks_cache_expires = now + 600
    return _jwks_cache


async def authenticate_request(request: Request) -> tuple[bool, Optional[str], str]:
    """Return (authorized, owner_id, error_code). Never log raw credentials."""
    settings = get_settings()
    mode = settings.auth_mode
    if mode == "off":
        if settings.environment.lower() == "production":
            return False, None, "auth_required_in_production"
        request.state.owner_id = "local-development"
        request.state.is_admin = True
        return True, "local-development", ""
    if mode == "api_key":
        if not settings.api_key:
            return False, None, "api_key_not_configured"
        import hmac
        supplied = request.headers.get("x-api-key", "")
        if not supplied or not hmac.compare_digest(supplied, settings.api_key):
            return False, None, "invalid_api_key"
        request.state.owner_id = "service-api-key"
        request.state.is_admin = True  # API keys are privileged server-to-server credentials.
        return True, "service-api-key", ""
    if mode == "supabase":
        if not settings.supabase_url:
            return False, None, "supabase_auth_not_configured"
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            return False, None, "bearer_token_required"
        token = header[7:].strip()
        try:
            import jwt
            unverified_header = jwt.get_unverified_header(token)
            algorithm = str(unverified_header.get("alg", ""))
            if algorithm not in {"ES256", "RS256", "EdDSA"}:
                return False, None, "unsupported_token_algorithm"
            jwks = await _get_jwks(settings.supabase_url)
            entry = jwks.get(str(unverified_header.get("kid", "")))
            if not entry:
                # Retry once with a fresh JWKS cache to accommodate key rotation.
                reset_jwks_cache()
                jwks = await _get_jwks(settings.supabase_url)
                entry = jwks.get(str(unverified_header.get("kid", "")))
            if not entry:
                return False, None, "unknown_token_key"
            signing_key = jwt.PyJWK.from_dict(entry).key
            claims = jwt.decode(
                token, signing_key, algorithms=[algorithm],
                audience=settings.supabase_jwt_audience,
                issuer=settings.supabase_url.rstrip("/") + "/auth/v1",
                options={"require": ["exp", "sub", "aud", "iss"]},
            )
            user_id = str(claims.get("sub", ""))
            if not user_id:
                return False, None, "subject_missing"
            app_metadata = claims.get("app_metadata") if isinstance(claims.get("app_metadata"), dict) else {}
            # Share workspace data only when trusted Supabase app_metadata assigns an org_id.
            # Otherwise incidents remain user-scoped. Never trust user_metadata/client org headers.
            owner_id = str(app_metadata.get("org_id") or user_id)
            roles = app_metadata.get("roles", []) if isinstance(app_metadata.get("roles", []), list) else []
            request.state.owner_id = owner_id
            request.state.user_id = user_id
            request.state.is_admin = app_metadata.get("role") == "admin" or "admin" in roles
            return True, owner_id, ""
        except Exception:
            return False, None, "invalid_bearer_token"
    return False, None, "unsupported_auth_mode"


def owner_from_request(request: Request) -> Optional[str]:
    """Trusted principal set by the auth middleware, never a client-supplied org id."""
    return getattr(request.state, "owner_id", None)


def is_admin_request(request: Request) -> bool:
    """Return true only for local dev, server API key, or trusted app_metadata admin role."""
    return bool(getattr(request.state, "is_admin", False))


def reset_jwks_cache() -> None:
    global _jwks_cache, _jwks_cache_expires, _jwks_cache_url
    _jwks_cache = {}
    _jwks_cache_expires = 0.0
    _jwks_cache_url = ""
