"""OmniShield AI FastAPI backend application entry point."""

from contextlib import asynccontextmanager
from pathlib import Path
import time
from typing import AsyncGenerator, Dict, Tuple
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi import HTTPException

from app.config import get_settings
from app.errors import setup_exception_handlers
from app.routes.dlp import router as dlp_router
from app.routes.health import router as health_router
from app.routes.incidents import router as incidents_router
from app.routes.injection import router as injection_router
from app.routes.invoice import router as invoice_router, inspect_router as invoice_inspect_router
from app.routes.chat_guard import router as chat_guard_router
from app.routes.honeypot import router as honeypot_router
from app.routes.phishing import router as phishing_router
from app.services.incident_store import get_incident_store
from app.services.auth import authenticate_request
from app.routes.multimodal import router as multimodal_router
from app.routes.file_scan import router as file_scan_router
from app.routes.audit import router as audit_router


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown lifespan handler."""
    # Ensure incident store is initialized during startup
    get_incident_store()
    yield


def create_app() -> FastAPI:
    """FastAPI application factory."""
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        description="Unified AI Security and Multi-Threat Detection Gateway",
        version="1.0.0",
        lifespan=lifespan,
    )

    # Optional screenshot-inspired single-file frontend. It is served from the same origin
    # so local browser requests do not need relaxed CORS. The API works without this file.
    demo_index = Path(__file__).resolve().parents[2] / "frontend-demo" / "index.html"

    async def demo_ui():
        if demo_index.is_file():
            return FileResponse(demo_index, media_type="text/html; charset=utf-8")
        return JSONResponse(status_code=404, content={"detail": "Optional frontend-demo/index.html was not included in this deployment."})

    app.add_api_route("/demo", demo_ui, methods=["GET"], include_in_schema=False)
    app.add_api_route("/demo/", demo_ui, methods=["GET"], include_in_schema=False)

    home3d_index = demo_index.parent / "home-3d.html"

    async def home3d_ui():
        if home3d_index.is_file():
            return FileResponse(home3d_index, media_type="text/html; charset=utf-8")
        return JSONResponse(status_code=404, content={"detail": "Homepage frontend-demo/home-3d.html was not included in this deployment."})

    app.add_api_route("/", home3d_ui, methods=["GET"], include_in_schema=False)
    app.add_api_route("/home3d", home3d_ui, methods=["GET"], include_in_schema=False)
    app.add_api_route("/home3d/", home3d_ui, methods=["GET"], include_in_schema=False)

    # PWA resources are served same-origin so the dashboard can be installed on
    # supported desktop and mobile browsers. The service worker intentionally
    # excludes API/auth responses from caching.
    pwa_dir = demo_index.parent

    async def pwa_manifest():
        manifest = pwa_dir / "manifest.webmanifest"
        if manifest.is_file():
            return FileResponse(manifest, media_type="application/manifest+json", headers={"Cache-Control": "no-cache"})
        return JSONResponse(status_code=404, content={"detail": "PWA manifest unavailable."})

    async def pwa_service_worker():
        worker = pwa_dir / "service-worker.js"
        if worker.is_file():
            return FileResponse(worker, media_type="application/javascript", headers={"Cache-Control": "no-cache", "Service-Worker-Allowed": "/"})
        return JSONResponse(status_code=404, content={"detail": "PWA service worker unavailable."})

    async def pwa_icon(size: int):
        icon_path = pwa_dir / "icons" / f"icon-{size}.png"
        if icon_path.is_file():
            return FileResponse(icon_path, media_type="image/png", headers={"Cache-Control": "public, max-age=604800"})
        return JSONResponse(status_code=404, content={"detail": "PWA icon unavailable."})

    app.add_api_route("/manifest.webmanifest", pwa_manifest, methods=["GET"], include_in_schema=False)
    app.add_api_route("/service-worker.js", pwa_service_worker, methods=["GET"], include_in_schema=False)
    async def pwa_icon_192():
        return await pwa_icon(192)

    async def pwa_icon_512():
        return await pwa_icon(512)

    app.add_api_route("/icons/icon-192.png", pwa_icon_192, methods=["GET"], include_in_schema=False)
    app.add_api_route("/icons/icon-512.png", pwa_icon_512, methods=["GET"], include_in_schema=False)

    # Explicit CORS allowlist. Configure CORS_ALLOWED_ORIGINS for deployed frontend origins.
    allowed_origins = [origin.strip() for origin in settings.cors_allowed_origins.split(",") if origin.strip()]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Session-Id"],
    )

    # Simple in-memory rate limiting middleware
    # If rate_limit_per_minute == 0, rate limiting is disabled (e.g. during testing)
    client_requests: Dict[str, list] = {}

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):
        curr_settings = get_settings()
        path = request.url.path

        # Protected API defaults are intentionally opt-in for local development.
        # Production with AUTH_MODE=off fails closed instead of silently exposing scans.
        if path.startswith("/api/"):
            authorized, _owner_id, error_code = await authenticate_request(request)
            if not authorized:
                if error_code.endswith("not_configured") or error_code == "auth_required_in_production":
                    code = status.HTTP_503_SERVICE_UNAVAILABLE
                    message = "API authentication is not configured for this deployment."
                else:
                    code = status.HTTP_401_UNAUTHORIZED
                    message = "Authentication required or credentials are invalid."
                return JSONResponse(status_code=code, content={"detail": message})

        limit = curr_settings.rate_limit_per_minute
        if limit > 0 and not path.startswith("/health"):
            # Do not trust X-Forwarded-For unless a reverse proxy is configured
            # and its trust boundary is managed separately.
            client_ip = request.client.host if request.client else "unknown-client"
            now = time.time()
            window_start = now - 60.0
            timestamps = [t for t in client_requests.get(client_ip, []) if t > window_start]
            if len(timestamps) >= limit:
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={"detail": "Rate limit exceeded. Try again in 60 seconds."},
                    headers={"Retry-After": "60"},
                )
            timestamps.append(now)
            client_requests[client_ip] = timestamps
            # Bound memory in this single-process development limiter.
            if len(client_requests) > 5000:
                stale = [key for key, vals in client_requests.items() if not vals or vals[-1] <= window_start]
                for key in stale:
                    client_requests.pop(key, None)

        return await call_next(request)

    # Exception Handlers
    setup_exception_handlers(app)

    # Register API Routers
    app.include_router(health_router)
    app.include_router(phishing_router)
    app.include_router(multimodal_router)
    app.include_router(file_scan_router)
    app.include_router(injection_router)
    app.include_router(dlp_router)
    app.include_router(invoice_router)
    app.include_router(invoice_inspect_router)
    app.include_router(chat_guard_router)
    app.include_router(honeypot_router)
    app.include_router(incidents_router)
    app.include_router(audit_router)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
