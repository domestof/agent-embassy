"""Regression coverage for keycloak_client.py: the never-raise contract on
malformed/unreachable input, the partner-shape filter, and -- the single
most important case -- that create_client() really does attach the
tier2-audience protocol mapper on every request it sends, since that
auto-attach is this module's entire reason for existing (a hand-edited
realm-export.json client missing it fails Tier 2 auth silently).
"""
from __future__ import annotations

import io
import json

import pytest

import keycloak_client as kc


def test_admin_request_survives_malformed_urls():
    # urllib.request.Request's own constructor (via its full_url setter)
    # raises ValueError for some malformed URLs -- confirmed live that this
    # happens OUTSIDE urlopen()'s call, so building the Request must happen
    # inside _admin_request's try block, not before it, or these raise
    # uncaught. Mirrors the exact bug class test_console.py's _get already
    # hit once (a different exception type, same "raised outside the try"
    # shape).
    for url in ["not a url at all", "http://keycloak:abc/x", "http://[invalid/x"]:
        status, headers, body = kc._admin_request("GET", url)
        assert status == 0
        assert headers == {}


def test_admin_request_survives_unreachable_host():
    status, headers, body = kc._admin_request("GET", "http://127.0.0.1:1/clients")
    assert status == 0


def test_admin_token_survives_unreachable_keycloak(monkeypatch):
    monkeypatch.setattr(kc, "_ADMIN_REALM_TOKEN_URL", "http://127.0.0.1:1/realms/master/protocol/openid-connect/token")
    token, err = kc._admin_token()
    assert token is None
    assert err
    assert kc.KEYCLOAK_ADMIN_PASSWORD not in err


@pytest.mark.parametrize(
    "fn,args",
    [
        (kc.list_clients, ()),
        (kc.create_client, ("some-client", "Some Client")),
        (kc.get_client, ("some-uuid",)),
        (kc.get_secret, ("some-uuid",)),
        (kc.regenerate_secret, ("some-uuid",)),
        (kc.delete_client, ("some-uuid",)),
        (kc.set_client_enabled, ("some-uuid", False)),
    ],
)
def test_every_public_function_degrades_gracefully_when_keycloak_unreachable(monkeypatch, fn, args):
    monkeypatch.setattr(kc, "_ADMIN_REALM_TOKEN_URL", "http://127.0.0.1:1/realms/master/protocol/openid-connect/token")
    result = fn(*args)
    assert result.ok is False
    assert result.error
    assert kc.KEYCLOAK_ADMIN_PASSWORD not in result.error


_PARTNER_SHAPE = {
    "id": "uuid-1",
    "clientId": "example-partner",
    "name": "Example partner",
    "enabled": True,
    "publicClient": False,
    "serviceAccountsEnabled": True,
    "standardFlowEnabled": False,
    "implicitFlowEnabled": False,
    "directAccessGrantsEnabled": False,
}


def test_is_partner_client_accepts_the_example_partner_shape():
    assert kc._is_partner_client(_PARTNER_SHAPE) is True


@pytest.mark.parametrize("client_id", sorted(kc._BUILTIN_CLIENT_IDS))
def test_is_partner_client_rejects_builtin_clients_even_if_shape_matched(client_id):
    rep = dict(_PARTNER_SHAPE, clientId=client_id)
    assert kc._is_partner_client(rep) is False


@pytest.mark.parametrize(
    "flipped_key",
    ["publicClient", "serviceAccountsEnabled", "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled"],
)
def test_is_partner_client_rejects_any_single_flag_deviation(flipped_key):
    rep = dict(_PARTNER_SHAPE)
    rep[flipped_key] = not rep[flipped_key]
    assert kc._is_partner_client(rep) is False


def test_has_audience_mapper_true_only_for_matching_mapper():
    rep_with = dict(
        _PARTNER_SHAPE,
        protocolMappers=[
            {
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": kc.TIER2_AUDIENCE, "access.token.claim": "true"},
            }
        ],
    )
    assert kc._has_audience_mapper(rep_with) is True

    rep_wrong_audience = dict(
        _PARTNER_SHAPE,
        protocolMappers=[
            {
                "protocolMapper": "oidc-audience-mapper",
                "config": {"included.custom.audience": "some-other-audience", "access.token.claim": "true"},
            }
        ],
    )
    assert kc._has_audience_mapper(rep_wrong_audience) is False

    rep_missing = dict(_PARTNER_SHAPE, protocolMappers=[])
    assert kc._has_audience_mapper(rep_missing) is False


def test_create_client_request_always_attaches_the_audience_mapper(monkeypatch):
    # This is the single most important test in this file: it's the literal
    # mechanism that makes the feature's core promise ("every client this UI
    # creates passes Tier 2 auth") true. Captures the real outgoing
    # urllib.request.Request rather than asserting on a mock return value,
    # so a regression here can't hide behind a stubbed response.
    captured = {}

    class _FakeResponse:
        def __init__(self, status, headers, body):
            self.status = status
            self.headers = headers
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        if "protocol/openid-connect/token" in req.full_url:
            return _FakeResponse(200, {}, json.dumps({"access_token": "fake-admin-token"}).encode())
        if req.method == "POST" and req.full_url.endswith("/clients"):
            captured["body"] = json.loads(req.data)
            return _FakeResponse(201, {"Location": f"{req.full_url}/new-uuid"}, b"")
        if req.method == "GET" and req.full_url.endswith("/new-uuid"):
            rep = dict(_PARTNER_SHAPE, id="new-uuid", clientId="new-partner", protocolMappers=captured["body"]["protocolMappers"])
            return _FakeResponse(200, {}, json.dumps(rep).encode())
        if req.method == "GET" and req.full_url.endswith("/client-secret"):
            return _FakeResponse(200, {}, json.dumps({"value": "generated-secret"}).encode())
        raise AssertionError(f"unexpected request: {req.method} {req.full_url}")

    monkeypatch.setattr(kc.urllib.request, "urlopen", fake_urlopen)

    result = kc.create_client("new-partner", "New Partner")

    assert result.ok is True
    assert result.secret == "generated-secret"
    assert result.client.has_audience_mapper is True

    mappers = captured["body"]["protocolMappers"]
    assert len(mappers) == 1
    mapper = mappers[0]
    assert mapper["protocolMapper"] == "oidc-audience-mapper"
    assert mapper["config"]["included.custom.audience"] == kc.TIER2_AUDIENCE
    assert mapper["config"]["access.token.claim"] == "true"
    assert mapper["config"]["id.token.claim"] == "false"
    # And the client shape itself matches example-partner's, not just the mapper:
    assert captured["body"]["publicClient"] is False
    assert captured["body"]["serviceAccountsEnabled"] is True
    assert captured["body"]["standardFlowEnabled"] is False
    assert captured["body"]["clientAuthenticatorType"] == "client-secret"


def test_create_client_duplicate_returns_clean_error_not_raw_keycloak_body(monkeypatch):
    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self.headers = {}
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        if "protocol/openid-connect/token" in req.full_url:
            return _FakeResponse(200, json.dumps({"access_token": "fake-admin-token"}).encode())
        raise kc.urllib.error.HTTPError(req.full_url, 409, "Conflict", {}, io.BytesIO(b'{"errorMessage": "Client dup-client already exists"}'))

    monkeypatch.setattr(kc.urllib.request, "urlopen", fake_urlopen)

    result = kc.create_client("dup-client", "Dup")
    assert result.ok is False
    assert "dup-client" in result.error


def test_set_client_enabled_sends_a_sparse_body_and_nothing_else(monkeypatch):
    # The whole point of this being a sparse {"enabled": ...} PUT rather than
    # a full representation re-send (verified against Keycloak's own
    # RepresentationToModel source, tag 26.7.1: omitted fields fall back to
    # the current model value, and secret-preservation logic keeps the
    # existing secret when none is sent) is that this call can't accidentally
    # touch the client's secret or protocol mappers. Captures the real
    # outgoing body rather than a stubbed return, same reasoning as
    # create_client's audience-mapper test above.
    captured = {}

    class _FakeResponse:
        def __init__(self, status, body=b""):
            self.status = status
            self.headers = {}
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        if "protocol/openid-connect/token" in req.full_url:
            return _FakeResponse(200, json.dumps({"access_token": "fake-admin-token"}).encode())
        if req.method == "GET" and req.full_url.endswith("/clients/uuid-1"):
            return _FakeResponse(200, json.dumps(_PARTNER_SHAPE).encode())
        if req.method == "PUT" and req.full_url.endswith("/clients/uuid-1"):
            captured["body"] = json.loads(req.data)
            return _FakeResponse(204)
        raise AssertionError(f"unexpected request: {req.method} {req.full_url}")

    monkeypatch.setattr(kc.urllib.request, "urlopen", fake_urlopen)

    result = kc.set_client_enabled("uuid-1", False)

    assert result.ok is True
    assert result.enabled is False
    assert captured["body"] == {"enabled": False}


def test_delete_client_returns_client_id_from_its_own_fetch(monkeypatch):
    # DeleteResult.client_id is populated from this function's own internal
    # get_client() call -- main.py's OpenBao cleanup relies on this instead
    # of making a second, redundant fetch of its own (a prior shape that was
    # also a silent-failure gap: found by adversarial review, 2026-08-12).
    # This is the unit-level check that the real body of delete_client()
    # actually sets it, not just the mocked-wholesale route tests in
    # test_main.py.
    class _FakeResponse:
        def __init__(self, status, body=b""):
            self.status = status
            self.headers = {}
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        if "protocol/openid-connect/token" in req.full_url:
            return _FakeResponse(200, json.dumps({"access_token": "fake-admin-token"}).encode())
        if req.method == "GET" and req.full_url.endswith("/clients/uuid-1"):
            return _FakeResponse(200, json.dumps(_PARTNER_SHAPE).encode())
        if req.method == "DELETE" and req.full_url.endswith("/clients/uuid-1"):
            return _FakeResponse(204)
        raise AssertionError(f"unexpected request: {req.method} {req.full_url}")

    monkeypatch.setattr(kc.urllib.request, "urlopen", fake_urlopen)

    result = kc.delete_client("uuid-1")

    assert result.ok is True
    assert result.not_found is False
    assert result.client_id == "example-partner"


def test_delete_client_leaves_client_id_none_when_not_found(monkeypatch):
    def fake_urlopen(req, timeout=None):
        if "protocol/openid-connect/token" in req.full_url:
            return_body = json.dumps({"access_token": "fake-admin-token"}).encode()

            class _Resp:
                def read(self_):
                    return return_body

                def __enter__(self_):
                    return self_

                def __exit__(self_, *exc):
                    return False

                status = 200

            return _Resp()
        raise kc.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(kc.urllib.request, "urlopen", fake_urlopen)

    result = kc.delete_client("nonexistent-uuid")
    assert result.ok is True
    assert result.not_found is True
    assert result.client_id is None


def test_set_client_enabled_not_found_for_unknown_uuid(monkeypatch):
    def fake_urlopen(req, timeout=None):
        if "protocol/openid-connect/token" in req.full_url:

            class _Resp:
                def read(self_):
                    return json.dumps({"access_token": "fake-admin-token"}).encode()

                def __enter__(self_):
                    return self_

                def __exit__(self_, *exc):
                    return False

                status = 200

            return _Resp()
        raise kc.urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))

    monkeypatch.setattr(kc.urllib.request, "urlopen", fake_urlopen)

    result = kc.set_client_enabled("nonexistent-uuid", False)
    assert result.ok is True
    assert result.not_found is True


def test_set_client_enabled_not_found_for_builtin_client(monkeypatch):
    # The re-check-per-UUID discipline every other per-UUID function in this
    # module already follows -- a built-in client's uuid, obtained some
    # other way, must not be manageable through this function either.
    class _FakeResponse:
        def __init__(self, status, body):
            self.status = status
            self.headers = {}
            self._body = body

        def read(self):
            return self._body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(req, timeout=None):
        if "protocol/openid-connect/token" in req.full_url:
            return _FakeResponse(200, json.dumps({"access_token": "fake-admin-token"}).encode())
        if req.method == "GET":
            builtin_rep = dict(_PARTNER_SHAPE, id="builtin-uuid", clientId="agent-embassy-tier2")
            return _FakeResponse(200, json.dumps(builtin_rep).encode())
        raise AssertionError("set_client_enabled must not PUT a built-in client")

    monkeypatch.setattr(kc.urllib.request, "urlopen", fake_urlopen)

    result = kc.set_client_enabled("builtin-uuid", False)
    assert result.ok is True
    assert result.not_found is True
