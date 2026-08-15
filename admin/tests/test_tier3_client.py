"""Regression coverage for tier3_client.py: the never-raise contract on
malformed/unreachable input, that requests carry the shared-secret header,
and that a client_id containing a "/" gets percent-encoded into a single
path segment rather than silently routing to the wrong path.
"""
from __future__ import annotations

import json

import pytest

import tier3_client as tc


def test_tier3_request_survives_malformed_url(monkeypatch):
    # Same "Request(...) construction can itself raise ValueError" case
    # keycloak_client.py's and tier1_client.py's equivalent tests document.
    for bad_url in ["not a url at all", "http://verify:abc/x", "http://[invalid/x"]:
        status, body = tc._tier3_request("GET", bad_url)
        assert status == 0


def test_tier3_request_survives_unreachable_host():
    status, body = tc._tier3_request("GET", "http://127.0.0.1:1/tier3/admin-grants/x")
    assert status == 0


def test_get_grant_degrades_gracefully_when_verify_unreachable(monkeypatch):
    monkeypatch.setattr(tc, "_GRANTS_URL", "http://127.0.0.1:1/tier3/admin-grants")
    result = tc.get_grant("some-client")
    assert result.ok is False
    assert result.error
    assert tc.ADMIN_INTERNAL_TOKEN not in result.error


def test_list_audit_degrades_gracefully_when_verify_unreachable(monkeypatch):
    monkeypatch.setattr(tc, "_AUDIT_URL", "http://127.0.0.1:1/tier3/admin-audit")
    result = tc.list_audit()
    assert result.ok is False
    assert result.error
    assert tc.ADMIN_INTERNAL_TOKEN not in result.error


def test_grant_url_percent_encodes_client_id_with_slash():
    url = tc._grant_url("weird/client")
    assert url == f"{tc._GRANTS_URL}/weird%2Fclient"


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


def test_set_grant_request_sends_the_body_and_the_admin_token(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["method"] = req.method
        captured["url"] = req.full_url
        captured["headers"] = dict(req.headers)
        captured["body"] = json.loads(req.data)
        return _FakeResponse(200, req.data)

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)

    result = tc.set_grant("laundry-co", 40000)

    assert result.ok is True
    assert captured["method"] == "PUT"
    assert captured["url"] == f"{tc._GRANTS_URL}/laundry-co"
    assert captured["headers"].get("X-admin-token") == tc.ADMIN_INTERNAL_TOKEN
    assert captured["body"] == {"weekly_limit_cents": 40000}


def test_get_grant_parses_successful_response(monkeypatch):
    values = {"client_id": "laundry-co", "weekly_limit_cents": 1000, "used_cents": 0, "remaining_cents": 1000}

    def fake_urlopen(req, timeout=None):
        assert req.method == "GET"
        assert dict(req.headers).get("X-admin-token") == tc.ADMIN_INTERNAL_TOKEN
        return _FakeResponse(200, json.dumps(values).encode())

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.get_grant("laundry-co")
    assert result.ok is True
    assert result.values == values


def test_revoke_grant_uses_delete(monkeypatch):
    def fake_urlopen(req, timeout=None):
        assert req.method == "DELETE"
        return _FakeResponse(200, json.dumps({"client_id": "laundry-co", "weekly_limit_cents": None}).encode())

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.revoke_grant("laundry-co")
    assert result.ok is True
    assert result.values["weekly_limit_cents"] is None


def test_set_grant_maps_422_to_a_friendly_range_error(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise tc.urllib.error.HTTPError(req.full_url, 422, "Unprocessable Entity", {}, None)

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.set_grant("laundry-co", 40000)
    assert result.ok is False
    assert "range" in result.error


@pytest.mark.parametrize("status", [401, 403, 500])
def test_set_grant_maps_other_bad_statuses_to_a_generic_error(monkeypatch, status):
    def fake_urlopen(req, timeout=None):
        raise tc.urllib.error.HTTPError(req.full_url, status, "error", {}, None)

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.set_grant("laundry-co", 40000)
    assert result.ok is False
    assert str(status) in result.error


def test_list_audit_parses_entries(monkeypatch):
    entries = [{"client_id": "laundry-co", "outcome": "accepted"}]

    def fake_urlopen(req, timeout=None):
        assert req.full_url == tc._AUDIT_URL
        return _FakeResponse(200, json.dumps({"entries": entries}).encode())

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.list_audit()
    assert result.ok is True
    assert result.entries == entries


# --- step 10: approvals ------------------------------------------------------


def test_list_pending_parses_entries(monkeypatch):
    entries = [{"action_id": "act-1-ab", "client_id": "laundry-co", "amount_cents": 60000}]

    def fake_urlopen(req, timeout=None):
        assert req.method == "GET"
        assert dict(req.headers).get("X-admin-token") == tc.ADMIN_INTERNAL_TOKEN
        return _FakeResponse(200, json.dumps({"entries": entries}).encode())

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.list_pending()
    assert result.ok is True
    assert result.entries == entries


def test_list_pending_degrades_gracefully_when_verify_unreachable(monkeypatch):
    monkeypatch.setattr(tc, "_APPROVALS_URL", "http://127.0.0.1:1/tier3/admin-approvals")
    result = tc.list_pending()
    assert result.ok is False
    assert tc.ADMIN_INTERNAL_TOKEN not in (result.error or "")


def test_approve_uses_the_long_timeout_not_the_5s_convention(monkeypatch):
    """Plan-review F8: verify's approve synchronously performs the internal-
    agent handoff (up to 2 x 10s attempts) -- a 5s admin-side timeout would
    report failure WHILE the action executes and the budget is consumed."""
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["timeout"] = timeout
        captured["method"] = req.method
        captured["url"] = req.full_url
        return _FakeResponse(200, json.dumps({"orderNumber": "ERP-1", "channel": "mock_erp"}).encode())

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.approve_action("act-1-ab")
    assert result.ok is True
    assert result.outcome["orderNumber"] == "ERP-1"
    assert captured["method"] == "POST"
    assert captured["url"].endswith("/tier3/admin-approvals/act-1-ab/approve")
    assert captured["timeout"] >= 21, "must comfortably exceed the handoff's 2x10s worst case"


def test_approve_maps_404_to_no_longer_pending(monkeypatch):
    def fake_urlopen(req, timeout=None):
        return _FakeResponse(404, b'{"detail": "unknown"}')

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.approve_action("act-1-ab")
    assert result.ok is False
    assert "no longer pending" in result.error


def test_approve_maps_409_to_mandate_revoked(monkeypatch):
    def fake_urlopen(req, timeout=None):
        return _FakeResponse(409, b'{"detail": "revoked"}')

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.approve_action("act-1-ab")
    assert result.ok is False
    assert "revoked" in result.error


def test_approve_surfaces_verifys_502_detail_verbatim(monkeypatch):
    """verify's two 502s differ in whether the budget was consumed -- the
    admin must see verify's own words, not a genericized message."""
    detail = "the handoff to the internal agent did not complete: the action MAY have executed."

    def fake_urlopen(req, timeout=None):
        return _FakeResponse(502, json.dumps({"detail": detail}).encode())

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.approve_action("act-1-ab")
    assert result.ok is False
    assert result.error == detail


def test_reject_posts_to_the_reject_path(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _FakeResponse(200, json.dumps({"action_id": "act-1-ab", "status": "rejected"}).encode())

    monkeypatch.setattr(tc.urllib.request, "urlopen", fake_urlopen)
    result = tc.reject_action("act-1-ab")
    assert result.ok is True
    assert captured["url"].endswith("/tier3/admin-approvals/act-1-ab/reject")


def test_approval_action_percent_encodes_action_id():
    # A "/"-bearing id must stay one path segment, same reasoning as
    # _grant_url's encoding test above.
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        return _FakeResponse(404, b"{}")

    import urllib.request as ur
    original = ur.urlopen
    ur.urlopen = fake_urlopen
    try:
        tc.approve_action("weird/../id")
    finally:
        ur.urlopen = original
    assert "/tier3/admin-approvals/weird%2F..%2Fid/approve" in captured["url"]
