import time

import pytest
from fastapi.testclient import TestClient

import main as app_module


@pytest.fixture(autouse=True)
def fresh_store():
    """Every test gets an isolated in-memory store — the module-level
    singleton must not leak challenge/session/rate-limit state across
    tests."""
    app_module.store = app_module.Store()
    yield


@pytest.fixture
def client():
    return TestClient(app_module.app)


def test_challenge_issues_token(client):
    resp = client.post("/tier1/challenge", json={"domain": "example.com"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["domain"] == "example.com"
    assert len(body["token"]) > 20
    assert body["well_known_path"] == "/.well-known/agent-embassy-challenge.txt"


def test_challenge_rejects_invalid_domain(client):
    resp = client.post("/tier1/challenge", json={"domain": "1.2.3.4"})
    assert resp.status_code == 400


def test_challenge_is_rate_limited_per_ip(client):
    for _ in range(app_module.store.challenge_rate_limit_max):
        r = client.post("/tier1/challenge", json={"domain": "example.com"})
        assert r.status_code == 200
    r = client.post("/tier1/challenge", json={"domain": "example.com"})
    assert r.status_code == 429


def test_challenge_rate_limit_is_keyed_by_x_forwarded_for_not_the_tcp_peer(client):
    # verify has no published host port -- every external caller reaches it
    # through nginx, whose own container IP would otherwise be the only
    # thing request.client.host ever sees, collapsing every real caller into
    # one shared rate-limit bucket (confirmed live during adversarial
    # review). nginx sets this header to $remote_addr itself, so verify can
    # trust it as the real caller's address.
    max_requests = app_module.store.challenge_rate_limit_max
    for _ in range(max_requests):
        r = client.post(
            "/tier1/challenge", json={"domain": "example.com"}, headers={"X-Forwarded-For": "203.0.113.5"}
        )
        assert r.status_code == 200
    exhausted = client.post(
        "/tier1/challenge", json={"domain": "example.com"}, headers={"X-Forwarded-For": "203.0.113.5"}
    )
    assert exhausted.status_code == 429

    # A different caller (different X-Forwarded-For) has its own, unaffected budget.
    other_caller = client.post(
        "/tier1/challenge", json={"domain": "example.com"}, headers={"X-Forwarded-For": "203.0.113.9"}
    )
    assert other_caller.status_code == 200


def test_verify_is_rate_limited_per_ip(client, monkeypatch):
    # /tier1/verify triggers a real outbound fetch per call; without its own
    # limit a single challenge could be replayed as unlimited verify calls
    # for the whole challenge TTL, using this service as a repeat proxy.
    client.post("/tier1/challenge", json={"domain": "example.com"})
    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (403, b"wrong"))

    for _ in range(app_module.store.verify_rate_limit_max):
        r = client.post("/tier1/verify", json={"domain": "example.com"})
        assert r.status_code == 403
    r = client.post("/tier1/verify", json={"domain": "example.com"})
    assert r.status_code == 429


def test_verify_success_issues_session_that_check_accepts(client, monkeypatch):
    resp = client.post("/tier1/challenge", json={"domain": "example.com"})
    token = resp.json()["token"]

    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (200, token.encode()))

    verify_resp = client.post("/tier1/verify", json={"domain": "example.com"})
    assert verify_resp.status_code == 200
    session_token = verify_resp.json()["session_token"]

    check = client.get("/tier1/check", headers={"Authorization": f"Bearer {session_token}"})
    assert check.status_code == 200
    assert check.headers["X-Verified-Domain"] == "example.com"


def test_verify_rejects_wrong_token_content(client, monkeypatch):
    client.post("/tier1/challenge", json={"domain": "example.com"})
    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (200, b"wrong-token"))
    resp = client.post("/tier1/verify", json={"domain": "example.com"})
    assert resp.status_code == 403


def test_verify_without_prior_challenge_is_rejected(client):
    resp = client.post("/tier1/verify", json={"domain": "example.com"})
    assert resp.status_code == 404


def test_verify_rejects_expired_challenge(client, monkeypatch):
    resp = client.post("/tier1/challenge", json={"domain": "example.com"})
    token = resp.json()["token"]
    domain = "example.com"
    stored_token, _ = app_module.store.challenges[domain]
    app_module.store.challenges[domain] = (stored_token, time.time() - 1)  # force expiry

    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (200, token.encode()))
    verify_resp = client.post("/tier1/verify", json={"domain": domain})
    assert verify_resp.status_code == 404


def test_verify_fetch_failure_does_not_leak_internal_detail(client, monkeypatch):
    client.post("/tier1/challenge", json={"domain": "example.com"})

    def boom(domain):
        raise ValueError("private IP 10.0.0.5 refused connection on port 443")

    monkeypatch.setattr(app_module, "fetch_challenge_file", boom)
    resp = client.post("/tier1/verify", json={"domain": "example.com"})
    assert resp.status_code == 502
    assert "10.0.0.5" not in resp.text
    assert "refused" not in resp.text


def test_verify_redirect_is_treated_as_failure_not_success(client, monkeypatch):
    client.post("/tier1/challenge", json={"domain": "example.com"})
    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (302, b""))
    resp = client.post("/tier1/verify", json={"domain": "example.com"})
    assert resp.status_code == 403


def test_challenge_is_single_use(client, monkeypatch):
    resp = client.post("/tier1/challenge", json={"domain": "example.com"})
    token = resp.json()["token"]
    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (200, token.encode()))

    first = client.post("/tier1/verify", json={"domain": "example.com"})
    assert first.status_code == 200

    second = client.post("/tier1/verify", json={"domain": "example.com"})
    assert second.status_code == 404  # the consumed challenge cannot be replayed


def test_concurrent_challenge_reissue_only_the_latest_token_verifies(client, monkeypatch):
    # Two challenge calls for the same domain race; last write wins. Confirms
    # this is an availability quirk, not a security bypass — the stale first
    # token must NOT still verify successfully.
    first = client.post("/tier1/challenge", json={"domain": "example.com"})
    first_token = first.json()["token"]
    second = client.post("/tier1/challenge", json={"domain": "example.com"})
    second_token = second.json()["token"]
    assert first_token != second_token

    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (200, first_token.encode()))
    resp = client.post("/tier1/verify", json={"domain": "example.com"})
    assert resp.status_code == 403  # stale token doesn't match the currently stored one

    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (200, second_token.encode()))
    resp = client.post("/tier1/verify", json={"domain": "example.com"})
    assert resp.status_code == 200


def test_check_rejects_missing_or_unknown_token(client):
    resp = client.get("/tier1/check")
    assert resp.status_code == 401

    resp = client.get("/tier1/check", headers={"Authorization": "Bearer not-a-real-token"})
    assert resp.status_code == 401


def test_check_rejects_expired_session(client, monkeypatch):
    resp = client.post("/tier1/challenge", json={"domain": "example.com"})
    token = resp.json()["token"]
    monkeypatch.setattr(app_module, "fetch_challenge_file", lambda domain: (200, token.encode()))
    verify_resp = client.post("/tier1/verify", json={"domain": "example.com"})
    session_token = verify_resp.json()["session_token"]

    domain, _ = app_module.store.sessions[session_token]
    app_module.store.sessions[session_token] = (domain, time.time() - 1)  # force expiry

    check = client.get("/tier1/check", headers={"Authorization": f"Bearer {session_token}"})
    assert check.status_code == 401


VALID_CONFIG_BODY = {
    "challenge_ttl_seconds": 111,
    "session_ttl_seconds": 222,
    "challenge_rate_limit_max": 3,
    "challenge_rate_limit_window": 44,
    "verify_rate_limit_max": 5,
    "verify_rate_limit_window": 66,
}


def _admin_headers():
    return {"X-Admin-Token": app_module.ADMIN_INTERNAL_TOKEN}


def test_admin_config_get_requires_correct_token(client):
    resp = client.get("/tier1/admin-config")
    assert resp.status_code == 403

    resp = client.get("/tier1/admin-config", headers={"X-Admin-Token": "wrong"})
    assert resp.status_code == 403

    resp = client.get("/tier1/admin-config", headers=_admin_headers())
    assert resp.status_code == 200


def test_admin_config_put_requires_correct_token(client):
    resp = client.put("/tier1/admin-config", json=VALID_CONFIG_BODY)
    assert resp.status_code == 403

    resp = client.put(
        "/tier1/admin-config", json=VALID_CONFIG_BODY, headers={"X-Admin-Token": "wrong"}
    )
    assert resp.status_code == 403


def test_admin_config_get_returns_current_store_values(client):
    resp = client.get("/tier1/admin-config", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json() == {
        "challenge_ttl_seconds": app_module.store.challenge_ttl_seconds,
        "session_ttl_seconds": app_module.store.session_ttl_seconds,
        "challenge_rate_limit_max": app_module.store.challenge_rate_limit_max,
        "challenge_rate_limit_window": app_module.store.challenge_rate_limit_window,
        "verify_rate_limit_max": app_module.store.verify_rate_limit_max,
        "verify_rate_limit_window": app_module.store.verify_rate_limit_window,
    }


def test_admin_config_put_updates_store(client):
    resp = client.put("/tier1/admin-config", json=VALID_CONFIG_BODY, headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json() == VALID_CONFIG_BODY
    assert app_module.store.challenge_ttl_seconds == 111
    assert app_module.store.session_ttl_seconds == 222
    assert app_module.store.challenge_rate_limit_max == 3
    assert app_module.store.challenge_rate_limit_window == 44
    assert app_module.store.verify_rate_limit_max == 5
    assert app_module.store.verify_rate_limit_window == 66


@pytest.mark.parametrize(
    "field,bad_value",
    [
        ("challenge_ttl_seconds", 0),
        ("challenge_ttl_seconds", -5),
        ("session_ttl_seconds", 100000),  # over the 86400 bound
        ("challenge_rate_limit_max", 0),
        ("challenge_rate_limit_window", 0),
        ("verify_rate_limit_max", 100000),  # over the 10000 bound
    ],
)
def test_admin_config_put_rejects_out_of_bounds_values(client, field, bad_value):
    body = {**VALID_CONFIG_BODY, field: bad_value}
    resp = client.put("/tier1/admin-config", json=body, headers=_admin_headers())
    assert resp.status_code == 422
    # Rejected body must not have partially applied.
    assert getattr(app_module.store, field) != bad_value


def test_admin_config_put_applies_immediately_no_restart_needed(client):
    # The whole point of this endpoint: it changes live behavior in this
    # same process, not just a stored value nothing reads.
    body = {**VALID_CONFIG_BODY, "challenge_rate_limit_max": 2}
    resp = client.put("/tier1/admin-config", json=body, headers=_admin_headers())
    assert resp.status_code == 200

    r1 = client.post("/tier1/challenge", json={"domain": "example.com"})
    r2 = client.post("/tier1/challenge", json={"domain": "example.com"})
    r3 = client.post("/tier1/challenge", json={"domain": "example.com"})
    assert r1.status_code == 200
    assert r2.status_code == 200
    assert r3.status_code == 429
