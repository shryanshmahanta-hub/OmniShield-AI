"""Health check and application startup tests."""

from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app


def test_app_startup():
    """Verify application startup lifecycle and basic configuration."""
    app = create_app()
    with TestClient(app) as test_client:
        response = test_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "incident_store" in data


def test_settings_construction():
    """Verify Settings dataclass supports rate_limit_per_minute=0 and incident_store."""
    s = Settings(rate_limit_per_minute=0, incident_store="sqlite")
    assert s.rate_limit_per_minute == 0
    assert s.incident_store == "sqlite"
    assert s.incident_store_path == "data/incidents.db"


def test_health_endpoint(client: TestClient):
    """Verify GET /health returns expected fields and 200 OK."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["incident_store"] == "memory"


def test_ai_status_reports_configuration_without_claiming_weights_loaded(client: TestClient):
    """AI status must distinguish configuration from verified inference readiness."""
    response = client.get("/api/v1/scan/ai-status")
    assert response.status_code == 200
    data = response.json()
    assert "runtime_dependencies" in data
    assert "torch_installed" in data["runtime_dependencies"]
    assert "transformers_installed" in data["runtime_dependencies"]
    assert "safety_note" in data
    for key in ("sms", "email", "url", "prompt_injection", "invoice"):
        assert "status" in data["text_models"][key]
        assert "weights_verified" in data["text_models"][key]
        assert data["text_models"][key]["weights_verified"] is False
