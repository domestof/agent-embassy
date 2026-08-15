import time

import pytest
from fastapi.testclient import TestClient

import channels
import llm
import main as app_module
import rules


def _unreachable_llm(**kwargs):
    raise AssertionError("choose_channel must not be called when no LLM is configured")


@pytest.fixture(autouse=True)
def fresh_state():
    app_module._results.clear()
    app_module._decision_log.clear()
    yield


@pytest.fixture
def client():
    return TestClient(app_module.app)


def _agent_headers():
    return {"X-Agent-Token": app_module.AGENT_INTERNAL_TOKEN}


def _status_headers():
    return {"X-Agent-Status-Token": app_module.AGENT_STATUS_TOKEN}


def _envelope(amount_cents=100, item="Bath towels", action_id="act-1-abc", mode="within_mandate"):
    return {
        "action_id": action_id,
        "action_type": "order.place",
        "client_id": "example-partner",
        "requested_at": 1_700_000_000.0,
        "payload": {"item": item, "quantity": 2, "amount_cents": amount_cents},
        "mandate": {
            "mode": mode,
            "weekly_limit_cents": 40000,
            "used_cents": 0,
            "remaining_cents": 40000,
            "window_seconds": 604800,
            "approved_by": "admin" if mode == "approved_by_human" else None,
        },
    }


def stub_channel(monkeypatch, *, executed=True, reference="ERP-stub-1"):
    calls = []

    def fake_execute(channel, **kwargs):
        calls.append((channel, kwargs))
        return (executed, reference if executed else None)

    monkeypatch.setattr(channels, "execute", fake_execute)
    return calls


# --- token gating: two secrets, two edges, never interchangeable -----------


def test_actions_requires_agent_token(client):
    assert client.post("/internal/actions", json=_envelope()).status_code == 403
    assert (
        client.post("/internal/actions", json=_envelope(), headers={"X-Agent-Token": "wrong"}).status_code
        == 403
    )


def test_status_token_cannot_invoke_actions(client):
    """The admin-held status secret must be structurally unable to execute:
    presenting it (under either header name) on /internal/actions fails."""
    resp = client.post(
        "/internal/actions", json=_envelope(), headers={"X-Agent-Token": app_module.AGENT_STATUS_TOKEN}
    )
    assert resp.status_code == 403
    resp = client.post(
        "/internal/actions",
        json=_envelope(),
        headers={"X-Agent-Status-Token": app_module.AGENT_STATUS_TOKEN},
    )
    assert resp.status_code == 403


def test_agent_token_cannot_read_status(client):
    assert client.get("/internal/status").status_code == 403
    resp = client.get("/internal/status", headers={"X-Agent-Status-Token": app_module.AGENT_INTERNAL_TOKEN})
    assert resp.status_code == 403


# --- decision flow ----------------------------------------------------------


def test_rule_match_executes_via_channel(client, monkeypatch):
    calls = stub_channel(monkeypatch)
    resp = client.post("/internal/actions", json=_envelope(amount_cents=100), headers=_agent_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "executed"
    assert body["channel"] == "mock_erp"
    assert body["decided_by"] == "rules"
    assert body["reference"] == "ERP-stub-1"
    assert calls[0][0] == "mock_erp"


def test_above_rule_threshold_consults_llm(client, monkeypatch):
    stub_channel(monkeypatch, reference="SLACK-stub-1")
    monkeypatch.setattr(llm, "is_configured", lambda: True)
    monkeypatch.setattr(
        llm,
        "choose_channel",
        lambda **kwargs: llm.LlmOutcome(channel="slack_stub", prompt="p", raw_text='{"channel": "slack_stub"}'),
    )
    resp = client.post("/internal/actions", json=_envelope(amount_cents=50000), headers=_agent_headers())
    body = resp.json()
    assert body["status"] == "executed"
    assert body["channel"] == "slack_stub"
    assert body["decided_by"] == "llm"


def test_no_usable_llm_fails_never_guesses(client, monkeypatch):
    """Plan-review F6: an attacker who can derail the LLM must get a FAILED
    action, never a default channel of the attacker's choosing.

    Note this asserts the CONFIGURED-LLM path specifically: fallback_channel
    must not rescue it (see test_unconfigured_llm_uses_declared_fallback for
    the other half of that boundary)."""
    calls = stub_channel(monkeypatch)
    monkeypatch.setattr(llm, "is_configured", lambda: True)
    monkeypatch.setattr(
        llm, "choose_channel", lambda **kwargs: llm.LlmOutcome(channel=None, prompt="p", raw_text="banana")
    )
    resp = client.post("/internal/actions", json=_envelope(amount_cents=50000), headers=_agent_headers())
    body = resp.json()
    assert body["status"] == "failed"
    assert body["channel"] is None
    assert body["reference"] is None
    assert calls == [], "no channel may execute when routing is undecided"


def test_unconfigured_llm_uses_declared_fallback(client, monkeypatch):
    """The shipped default config (no AGENT_LLM_MODEL) must still execute an
    order above the first rule's ceiling -- the flagship illustrative example
    is a EUR 400/week mandate, i.e. entirely above it. Before the
    fallback_channel rule existed, every such order failed."""
    calls = stub_channel(monkeypatch)
    monkeypatch.setattr(llm, "is_configured", lambda: False)
    monkeypatch.setattr(
        llm, "choose_channel", _unreachable_llm, raising=True
    )
    resp = client.post("/internal/actions", json=_envelope(amount_cents=40000), headers=_agent_headers())
    body = resp.json()
    assert body["status"] == "executed"
    assert body["channel"] == "mock_erp"
    assert body["decided_by"] == "rules", "a deterministic fallback is a rules decision, not an LLM one"
    assert calls[0][0] == "mock_erp"


def test_unconfigured_llm_without_fallback_still_fails(client, monkeypatch):
    """fallback_channel is opt-in per rule: a deployment that doesn't declare
    one keeps the original fail-closed behavior."""
    calls = stub_channel(monkeypatch)
    monkeypatch.setattr(llm, "is_configured", lambda: False)
    monkeypatch.setattr(rules, "fallback_channel", lambda *a, **k: None)
    resp = client.post("/internal/actions", json=_envelope(amount_cents=40000), headers=_agent_headers())
    body = resp.json()
    assert body["status"] == "failed"
    assert body["channel"] is None
    assert calls == []


def test_channel_failure_reports_failed(client, monkeypatch):
    stub_channel(monkeypatch, executed=False)
    resp = client.post("/internal/actions", json=_envelope(amount_cents=100), headers=_agent_headers())
    body = resp.json()
    assert body["status"] == "failed"
    assert body["channel"] == "mock_erp"


def test_idempotent_replay_returns_original_without_reexecuting(client, monkeypatch):
    """verify retries the identical envelope once on timeout -- the second
    call must observe the first outcome, not run the channel again."""
    calls = stub_channel(monkeypatch)
    first = client.post("/internal/actions", json=_envelope(action_id="act-idem-1"), headers=_agent_headers())
    second = client.post("/internal/actions", json=_envelope(action_id="act-idem-1"), headers=_agent_headers())
    assert first.json() == second.json()
    assert len(calls) == 1


def test_concurrent_same_action_id_executes_channel_exactly_once(client, monkeypatch):
    """Post-build adversarial review, HIGH: verify's retry can arrive WHILE
    the first attempt is still inside channels.execute (it timed out at
    verify because it's slow). A non-atomic check-then-act let both dispatch
    -- the action executed twice on the exact timeout path the caller is
    told not to resubmit on. The per-action lock must serialize them so the
    channel runs once and both responses match."""
    import threading

    started = threading.Barrier(2)
    call_count = {"n": 0}
    lock = threading.Lock()

    def slow_execute(channel, **kwargs):
        with lock:
            call_count["n"] += 1
            n = call_count["n"]
        # Overlap the two requests: the first sits in the channel long
        # enough for the second (the retry) to arrive and try to dispatch.
        time.sleep(0.3)
        return (True, f"ERP-once-{n}")

    monkeypatch.setattr(channels, "execute", slow_execute)

    results = []

    def fire():
        started.wait()
        resp = client.post("/internal/actions", json=_envelope(action_id="act-race-1"), headers=_agent_headers())
        results.append(resp.json())

    threads = [threading.Thread(target=fire) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert call_count["n"] == 1, "the channel must execute exactly once for one action_id"
    assert results[0] == results[1], "both requests must return the same stored outcome"
    assert results[0]["reference"] == "ERP-once-1"


def test_invalid_payload_422s(client):
    envelope = _envelope()
    envelope["payload"] = {"item": "", "quantity": 0, "amount_cents": -5}
    resp = client.post("/internal/actions", json=envelope, headers=_agent_headers())
    assert resp.status_code == 422


def test_unknown_action_type_422s(client):
    envelope = _envelope()
    envelope["action_type"] = "invoice.pay"
    resp = client.post("/internal/actions", json=envelope, headers=_agent_headers())
    assert resp.status_code == 422


# --- decision log / status --------------------------------------------------


def test_status_exposes_decisions_and_config(client, monkeypatch):
    stub_channel(monkeypatch)
    client.post("/internal/actions", json=_envelope(action_id="act-log-1"), headers=_agent_headers())

    resp = client.get("/internal/status", headers=_status_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["rules"]["allowed_channels"] == ["mock_erp", "slack_stub", "email_stub"]
    assert body["llm"]["configured"] in (True, False)
    assert body["decisions"][0]["action_id"] == "act-log-1"
    assert body["decisions"][0]["executed"] is True


def test_decision_log_is_bounded(client, monkeypatch):
    stub_channel(monkeypatch)
    monkeypatch.setattr(app_module, "DECISION_LOG_MAX", 3)
    for i in range(6):
        client.post("/internal/actions", json=_envelope(action_id=f"act-cap-{i}"), headers=_agent_headers())
    resp = client.get("/internal/status", headers=_status_headers())
    decisions = resp.json()["decisions"]
    assert len(decisions) == 3
    assert decisions[0]["action_id"] == "act-cap-5"


def test_result_map_is_bounded(client, monkeypatch):
    stub_channel(monkeypatch)
    monkeypatch.setattr(app_module, "RESULT_MAP_MAX", 2)
    for i in range(4):
        client.post("/internal/actions", json=_envelope(action_id=f"act-map-{i}"), headers=_agent_headers())
    assert len(app_module._results) == 2


def test_no_secret_appears_in_responses(client, monkeypatch):
    stub_channel(monkeypatch)
    resp = client.post("/internal/actions", json=_envelope(), headers=_agent_headers())
    assert app_module.AGENT_INTERNAL_TOKEN not in resp.text
    assert app_module.AGENT_STATUS_TOKEN not in resp.text
    resp = client.get("/internal/status", headers=_status_headers())
    assert app_module.AGENT_INTERNAL_TOKEN not in resp.text
    assert app_module.AGENT_STATUS_TOKEN not in resp.text


def test_docs_are_disabled(client):
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
