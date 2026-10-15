"""Regression checks for the dashboard-to-FastAPI route contract."""
from pathlib import Path
import re

from app.main import create_app

PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND = PROJECT_ROOT.parent / "frontend-demo" / "index.html"


def test_dashboard_scan_paths_are_registered():
    """The visible scan workflow must not call stale/nonexistent endpoints."""
    source = FRONTEND.read_text(encoding="utf-8")
    app = create_app()
    registered = {(route.path, method) for route in app.routes
                  for method in getattr(route, "methods", set())}
    expected = {
        ("/api/v1/scan/message", "POST"),
        ("/api/v1/scan/email", "POST"),
        ("/api/v1/scan/url", "POST"),
        ("/api/v1/scan/qr", "POST"),
        ("/api/v1/scan/qr/image", "POST"),
        ("/api/v1/scan/file", "POST"),
        ("/api/v1/scan/dlp", "POST"),
        ("/api/v1/scan/invoice", "POST"),
        ("/api/v1/scan/injection", "POST"),
        ("/api/v1/scan/ai-status", "GET"),
        ("/api/v1/incidents", "GET"),
        ("/api/v1/audit", "GET"),
        ("/health", "GET"),
    }
    for path, method in expected:
        assert (path, method) in registered, f"Dashboard contract route missing: {method} {path}"
        assert path in source, f"Frontend no longer references expected path: {path}"


def test_api_base_normalizer_and_error_diagnostics_are_present():
    source = FRONTEND.read_text(encoding="utf-8")
    assert "function normalizeApiBase(value)" in source
    assert "function friendlyApiError(status,detail)" in source
    # Prevent accidental duplicated API prefixes from common Settings input.
    assert "(api\\/v1|api)" in source


def test_pwa_assets_are_served_by_backend(client):
    for path in ("/demo", "/manifest.webmanifest", "/service-worker.js",
                 "/icons/icon-192.png", "/icons/icon-512.png"):
        response = client.get(path)
        assert response.status_code == 200, f"{path}: {response.status_code}"
