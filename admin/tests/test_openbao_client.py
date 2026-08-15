"""Regression coverage for openbao_client.py: the never-raise contract, the
"skipped" no-op behavior when OpenBao isn't configured (the mechanism that
keeps local dev working with zero new mandatory .env values), and the real
outgoing request shape (method, path, X-Vault-Token header, KV v2 body
envelope) for each operation.
"""
from __future__ import annotations

import io
import json

import openbao_client as bao


class _FakeResponse:
    def __init__(self, status, body=b""):
        self.status = status
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _configure(monkeypatch, addr="http://openbao:8200", token="test-token"):
    monkeypatch.setattr(bao, "OPENBAO_ADDR", addr)
    monkeypatch.setattr(bao, "OPENBAO_TOKEN", token)


def test_configured_requires_both_addr_and_token(monkeypatch):
    # local dev's admin service sets neither env var -- confirms the module
    # treats that as unconfigured, and that either one alone isn't enough.
    monkeypatch.setattr(bao, "OPENBAO_ADDR", "")
    monkeypatch.setattr(bao, "OPENBAO_TOKEN", "")
    assert bao.configured() is False

    monkeypatch.setattr(bao, "OPENBAO_ADDR", "http://openbao:8200")
    monkeypatch.setattr(bao, "OPENBAO_TOKEN", "")
    assert bao.configured() is False

    monkeypatch.setattr(bao, "OPENBAO_ADDR", "")
    monkeypatch.setattr(bao, "OPENBAO_TOKEN", "some-token")
    assert bao.configured() is False

    monkeypatch.setattr(bao, "OPENBAO_ADDR", "http://openbao:8200")
    monkeypatch.setattr(bao, "OPENBAO_TOKEN", "some-token")
    assert bao.configured() is True


def test_every_public_function_is_a_noop_when_unconfigured(monkeypatch):
    monkeypatch.setattr(bao, "OPENBAO_ADDR", "")
    monkeypatch.setattr(bao, "OPENBAO_TOKEN", "")

    def fail_if_called(*a, **k):
        raise AssertionError("urlopen should never be called when OpenBao isn't configured")

    monkeypatch.setattr(bao.urllib.request, "urlopen", fail_if_called)

    write_result = bao.write_client_secret("some-client", "secret-value", "some-uuid")
    assert write_result.ok is True
    assert write_result.skipped is True

    read_result = bao.read_client_secret("some-client")
    assert read_result.ok is True
    assert read_result.skipped is True

    delete_result = bao.delete_client_secret("some-client")
    assert delete_result.ok is True
    assert delete_result.skipped is True


def test_bao_request_survives_malformed_urls(monkeypatch):
    _configure(monkeypatch)
    for url in ["not a url at all", "http://openbao:abc/x", "http://[invalid/x"]:
        status, body = bao._bao_request("GET", url)
        assert status == 0


def test_bao_request_survives_unreachable_host(monkeypatch):
    _configure(monkeypatch)
    status, body = bao._bao_request("GET", "http://127.0.0.1:1/v1/secret/data/x")
    assert status == 0


def test_write_client_secret_survives_unreachable_openbao(monkeypatch):
    monkeypatch.setattr(bao, "OPENBAO_ADDR", "http://127.0.0.1:1")
    monkeypatch.setattr(bao, "OPENBAO_TOKEN", "test-token")
    result = bao.write_client_secret("some-client", "secret-value", "some-uuid")
    assert result.ok is False
    assert result.skipped is False
    assert result.error


def test_write_client_secret_rejects_a_missing_secret_instead_of_writing_null(monkeypatch):
    # OpenBao's KV v2 API happily 200s a null client_secret -- confirmed
    # live during adversarial review. Without this guard, create_client()'s
    # documented secret=None fallback (Keycloak's secret-fetch GET itself
    # failing) would silently "succeed" here, and main.py's warning logic
    # (which only fires on ok=False) would never surface it.
    _configure(monkeypatch)

    def fail_if_called(*a, **k):
        raise AssertionError("urlopen should never be called for an empty/missing secret")

    monkeypatch.setattr(bao.urllib.request, "urlopen", fail_if_called)

    result = bao.write_client_secret("some-client", None, "some-uuid")
    assert result.ok is False
    assert result.skipped is False
    assert result.error

    result_empty_string = bao.write_client_secret("some-client", "", "some-uuid")
    assert result_empty_string.ok is False


def test_write_client_secret_sends_the_real_kv_v2_shape_and_auth_header(monkeypatch):
    _configure(monkeypatch, token="scoped-token-abc")
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["method"] = req.method
        captured["url"] = req.full_url
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        captured["body"] = json.loads(req.data)
        return _FakeResponse(200)

    monkeypatch.setattr(bao.urllib.request, "urlopen", fake_urlopen)

    result = bao.write_client_secret("acme-partner", "s3cr3t", "uuid-123")

    assert result.ok is True
    assert captured["method"] == "POST"
    assert captured["url"] == "http://openbao:8200/v1/secret/data/tier2-clients/acme-partner"
    assert captured["headers"]["x-vault-token"] == "scoped-token-abc"
    assert captured["body"] == {"data": {"client_secret": "s3cr3t", "keycloak_uuid": "uuid-123"}}


def test_read_client_secret_parses_the_kv_v2_envelope(monkeypatch):
    _configure(monkeypatch)

    def fake_urlopen(req, timeout=None):
        assert req.method == "GET"
        assert req.full_url == "http://openbao:8200/v1/secret/data/tier2-clients/acme-partner"
        assert {k.lower(): v for k, v in req.headers.items()}["x-vault-token"] == "test-token"
        payload = {"data": {"data": {"client_secret": "s3cr3t", "keycloak_uuid": "uuid-123"}, "metadata": {}}}
        return _FakeResponse(200, json.dumps(payload).encode())

    monkeypatch.setattr(bao.urllib.request, "urlopen", fake_urlopen)

    result = bao.read_client_secret("acme-partner")
    assert result.ok is True
    assert result.secret == "s3cr3t"
    assert result.not_found is False


def test_read_client_secret_not_found(monkeypatch):
    _configure(monkeypatch)

    def fake_urlopen(req, timeout=None):
        raise bao.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(bao.urllib.request, "urlopen", fake_urlopen)

    result = bao.read_client_secret("nonexistent-client")
    assert result.ok is True
    assert result.not_found is True
    assert result.secret is None


def test_delete_client_secret_hits_the_full_delete_metadata_endpoint(monkeypatch):
    _configure(monkeypatch)
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["method"] = req.method
        captured["url"] = req.full_url
        return _FakeResponse(204)

    monkeypatch.setattr(bao.urllib.request, "urlopen", fake_urlopen)

    result = bao.delete_client_secret("acme-partner")
    assert result.ok is True
    assert captured["method"] == "DELETE"
    assert captured["url"] == "http://openbao:8200/v1/secret/metadata/tier2-clients/acme-partner"


def test_delete_client_secret_tolerates_already_gone(monkeypatch):
    _configure(monkeypatch)

    def fake_urlopen(req, timeout=None):
        raise bao.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(bao.urllib.request, "urlopen", fake_urlopen)

    result = bao.delete_client_secret("already-gone")
    assert result.ok is True
