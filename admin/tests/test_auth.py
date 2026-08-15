import pytest
from fastapi.testclient import TestClient

import main as app_module


@pytest.fixture
def client():
    return TestClient(app_module.app)


def test_health_is_open(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_dashboard_requires_auth(client):
    resp = client.get("/")
    assert resp.status_code == 401
    assert resp.headers["WWW-Authenticate"] == "Basic"


def test_dashboard_rejects_wrong_credentials(client):
    resp = client.get("/", auth=("testadmin", "wrong"))
    assert resp.status_code == 401


def test_dashboard_rejects_empty_credentials(client):
    # The exact bypass auth.py's fail-closed startup guard exists to
    # prevent: if ADMIN_UI_USERNAME/PASSWORD were ever unset (empty string
    # default), empty submitted credentials would match via
    # compare_digest("", ""). Getting this far without RuntimeError already
    # confirms real, non-empty creds were configured.
    resp = client.get("/", auth=("", ""))
    assert resp.status_code == 401


def test_dashboard_accepts_correct_credentials(client):
    resp = client.get("/", auth=("testadmin", "testpass"))
    assert resp.status_code == 200
