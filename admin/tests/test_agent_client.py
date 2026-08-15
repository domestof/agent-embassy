"""agent_client.py: the never-raise contract, the status-token header, and
that the module holds only the STATUS secret (never a token verify accepts).
"""
from __future__ import annotations

import json

import agent_client as ac


class _FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self, *args):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_get_status_parses_and_sends_the_status_token(monkeypatch):
    payload = {
        "rules": {"allowed_channels": ["mock_erp"], "rules": [], "path": "/app/rules.json"},
        "llm": {"configured": False, "model": None, "base_url": "http://litellm:4000"},
        "decisions": [{"action_id": "act-1-ab"}],
    }
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["headers"] = dict(req.headers)
        captured["url"] = req.full_url
        return _FakeResponse(200, json.dumps(payload).encode())

    monkeypatch.setattr(ac.urllib.request, "urlopen", fake_urlopen)
    result = ac.get_status()
    assert result.ok is True
    assert result.rules["allowed_channels"] == ["mock_erp"]
    assert result.decisions[0]["action_id"] == "act-1-ab"
    assert captured["headers"].get("X-agent-status-token") == ac.AGENT_STATUS_TOKEN
    assert captured["url"].endswith("/internal/status")


def test_get_status_degrades_gracefully_when_agent_unreachable(monkeypatch):
    monkeypatch.setattr(ac, "AGENT_BASE_URL", "http://127.0.0.1:1")
    result = ac.get_status()
    assert result.ok is False
    assert result.error == "could not reach the internal agent"
    assert ac.AGENT_STATUS_TOKEN not in (result.error or "")


def test_get_status_maps_non_200_to_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        return _FakeResponse(403, b"forbidden")

    monkeypatch.setattr(ac.urllib.request, "urlopen", fake_urlopen)
    result = ac.get_status()
    assert result.ok is False
    assert "403" in result.error


def test_get_status_maps_unparseable_body_to_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        return _FakeResponse(200, b"not json")

    monkeypatch.setattr(ac.urllib.request, "urlopen", fake_urlopen)
    result = ac.get_status()
    assert result.ok is False
    assert "unparseable" in result.error
