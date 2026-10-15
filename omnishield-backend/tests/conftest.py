"""Pytest fixtures for OmniShield AI backend testing."""

import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.main import create_app
from app.services.incident_store import MemoryIncidentStore, set_incident_store


@pytest.fixture(autouse=True)
def setup_test_settings(monkeypatch):
    """Fixture ensuring Settings with rate_limit_per_minute=0 and memory store."""
    test_settings = Settings(
        app_name="OmniShield AI Test",
        environment="test",
        debug=True,
        rate_limit_per_minute=0,  # Zero rate limit matches conftest requirements
        incident_store="memory",
    )
    store = MemoryIncidentStore()
    set_incident_store(store)

    from app import config
    config.get_settings.cache_clear()
    monkeypatch.setattr(config, "get_settings", lambda: test_settings)

    yield test_settings


@pytest.fixture
def client(setup_test_settings):
    """FastAPI TestClient fixture."""
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
