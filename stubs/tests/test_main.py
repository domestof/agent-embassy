import pytest
from fastapi.testclient import TestClient

import main as app_module


@pytest.fixture(autouse=True)
def fresh_state():
    app_module._deliveries.clear()
    yield


@pytest.fixture
def client():
    return TestClient(app_module.app)


def test_mock_erp_records_and_references(client):
    resp = client.post(
        "/mock-erp/orders",
        json={"action_id": "act-1-abc", "client_id": "p1", "item": "towels", "quantity": 2, "amount_cents": 500},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["reference"].startswith("ERP-")
    assert "Illustrative stub" in body["disclaimer"]

    deliveries = client.get("/deliveries").json()["entries"]
    assert deliveries[0]["channel"] == "mock_erp"
    assert deliveries[0]["reference"] == body["reference"]


def test_slack_and_email_record(client):
    slack = client.post("/slack/webhook", json={"action_id": "act-2-abc", "text": "hello ops"})
    email = client.post(
        "/email/send",
        json={"action_id": "act-3-abc", "to": "ops@example.invalid", "subject": "s", "body": "b"},
    )
    assert slack.json()["reference"].startswith("SLACK-")
    assert email.json()["reference"].startswith("EMAIL-")
    channels = [e["channel"] for e in client.get("/deliveries").json()["entries"]]
    assert channels == ["email_stub", "slack_stub"]


def test_invalid_bodies_422(client):
    assert client.post("/mock-erp/orders", json={"item": "x"}).status_code == 422
    assert client.post("/slack/webhook", json={"action_id": "a", "text": ""}).status_code == 422


def test_deliveries_bounded(client, monkeypatch):
    monkeypatch.setattr(app_module, "_DELIVERIES_MAX", 2)
    for i in range(4):
        client.post("/slack/webhook", json={"action_id": f"act-{i}-abc", "text": "x"})
    assert len(client.get("/deliveries").json()["entries"]) == 2


def test_docs_are_disabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
