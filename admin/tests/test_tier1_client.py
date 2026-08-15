"""Regression coverage for tier1_client.py: the never-raise contract on
malformed/unreachable input, and -- the single most important case -- that
update_config() really does send every field verify's Tier1ConfigUpdate
model requires, with the shared-secret header attached, since a request
missing either would fail closed on verify's side in a way this module's
result dataclass must surface cleanly rather than crash on.
"""
from __future__ import annotations

import json

import pytest

import tier1_client as tc


def test_verify_request_survives_malformed_url(monkeypatch):
    # Same "Request(...) construction can itself raise ValueError" case
    # keycloak_client.py's equivalent test documents -- confirmed live there,
    # applies identically here since _verify_request follows the same shape.
    for bad_url in ["not a url at all", "http://verify:abc/x", "http://[invalid/x"]:
        monkeypatch.setattr(tc, "_CONFIG_URL", bad_url)
        status, body = tc._verify_request("GET")
        assert status == 0


def test_verify_request_survives_unreachable_host(monkeypatch):
    monkeypatch.setattr(tc, "_CONFIG_URL", "http://127.0.0.1:1/tier1/admin-config")
    status, body = tc._verify_request("GET")
    assert status == 0


def test_get_config_degrades_gracefully_when_verify_unreachable(monkeypatch):
    monkeypatch.setattr(tc, "_CONFIG_URL", "http://127.0.0.1:1/tier1/admin-config")
    result = tc.get_config()
    assert result.ok is False
    assert result.error
    assert tc.ADMIN_INTERNAL_TOKEN not in result.error


def test_update_config_degrades_gracefully_when_verify_unreachable(monkeypatch):
    monkeypatch.setattr(tc, "_CONFIG_URL", "http://127.0.0.1:1/tier1/admin-config")
    result = tc.update_config(**{f: 1 for f in tc.CONFIG_FIELDS})
    assert result.ok is False
    assert result.error
    assert tc.ADMIN_INTERNAL_TOKEN not in result.error


def test_update_config_rejects_missing_field_without_a_network_call(monkeypatch):
    def boom(*a, **kw):
        raise AssertionError("should not have made a network call")

    monkeypatch.setattr(tc, "_verify_request", boom)
    incomplete = {f: 1 for f in tc.CONFIG_FIELDS if f != "challenge_ttl_seconds"}
    result = tc.update_config(**incomplete)
    assert result.ok is False
    assert "challenge_ttl_seconds" in result.error


class _FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_update_config_request_sends_every_field_and_the_admin_token(monkeypatch):
    # The single most important test in this file: proves the real outgoing
    # request (not a stubbed return value) carries the shared-secret header
    # and every field verify's Tier1ConfigUpdate model requires -- a
    # regression here can't hide behind a mocked-away shape.
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["method"] = req.method
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data)
        return _FakeResponse(200, req.data)

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)

    values = {
        "challenge_ttl_seconds": 111,
        "session_ttl_seconds": 222,
        "challenge_rate_limit_max": 3,
        "challenge_rate_limit_window": 44,
        "verify_rate_limit_max": 5,
        "verify_rate_limit_window": 66,
    }
    result = tc.update_config(**values)

    assert result.ok is True
    assert result.values == values
    assert captured["method"] == "PUT"
    assert captured["headers"].get("X-admin-token") == tc.ADMIN_INTERNAL_TOKEN
    assert captured["body"] == values


def test_get_config_parses_successful_response(monkeypatch):
    values = {f: i for i, f in enumerate(tc.CONFIG_FIELDS, start=1)}

    def fake_urlopen(req, timeout=None):
        assert req.method == "GET"
        assert dict(req.headers).get("X-admin-token") == tc.ADMIN_INTERNAL_TOKEN
        return _FakeResponse(200, json.dumps(values).encode())

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.get_config()
    assert result.ok is True
    assert result.values == values


def test_update_config_maps_422_to_a_friendly_range_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise tc.urllib.error.HTTPError(req.full_url, 422, "Unprocessable Entity", {}, None)

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.update_config(**{f: 1 for f in tc.CONFIG_FIELDS})
    assert result.ok is False
    assert "range" in result.error


@pytest.mark.parametrize("status", [401, 403, 500])
def test_update_config_maps_other_bad_statuses_to_a_generic_error(monkeypatch, status):
    def fake_urlopen(req, timeout=None):
        raise tc.urllib.error.HTTPError(req.full_url, status, "error", {}, None)

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.update_config(**{f: 1 for f in tc.CONFIG_FIELDS})
    assert result.ok is False
    assert str(status) in result.error
