import json

import pytest
from fastapi.testclient import TestClient

import introspection
import main as app_module

CLIENT_ID = "tier3-test-client"


@pytest.fixture(autouse=True)
def fresh_store():
    """Same isolation as test_main.py's fresh_store — the module-level
    singleton must not leak grants/audit/rate-limit state across tests."""
    app_module.store = app_module.Store()
    yield


@pytest.fixture
def client():
    return TestClient(app_module.app)


def _admin_headers():
    return {"X-Admin-Token": app_module.ADMIN_INTERNAL_TOKEN}


def _order_headers(token="valid-token"):
    return {"Authorization": f"Bearer {token}", "X-SSL-Client-Verify": "SUCCESS"}


def _order_body(amount_cents=1000, item="Bath towels", quantity=1):
    return {"item": item, "quantity": quantity, "amount_cents": amount_cents}


def stub_introspection(monkeypatch, *, active=True, client_id=CLIENT_ID, status=200, body=None):
    """Mocks only the network boundary (_post_introspect), mirroring how
    test_tier2.py's stub_jwks keeps everything downstream of the network
    call real — introspect_access_token's own parsing/active-check logic
    runs for real in every test below."""
    if body is None:
        body = json.dumps({"active": active, "client_id": client_id}).encode()
    monkeypatch.setattr(introspection, "_post_introspect", lambda token: (status, body))


def grant(client, weekly_limit_cents, client_id=CLIENT_ID):
    resp = client.put(
        f"/tier3/admin-grants/{client_id}",
        json={"weekly_limit_cents": weekly_limit_cents},
        headers=_admin_headers(),
    )
    assert resp.status_code == 200
    return resp.json()


def stub_handoff(monkeypatch, *, kind="ok", status="executed", channel="mock_erp", decided_by="rules", reference="ERP-test-1"):
    """Mocks only the verify->agent network boundary (execute_handoff),
    mirroring stub_introspection above — reserve-then-settle, budget math,
    the approval queue, and resolutions all run for real. Returns the list
    of envelopes the handler actually sent, for asserting on their shape."""
    calls = []

    def fake_execute(envelope):
        calls.append(envelope)
        return app_module.HandoffResult(
            kind=kind, status=status, channel=channel, decided_by=decided_by, reference=reference
        )

    monkeypatch.setattr(app_module, "execute_handoff", fake_execute)
    return calls


# --- admin-grants / admin-audit auth gating -------------------------------


def test_admin_grants_get_requires_correct_token(client):
    resp = client.get(f"/tier3/admin-grants/{CLIENT_ID}")
    assert resp.status_code == 403

    resp = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers={"X-Admin-Token": "wrong"})
    assert resp.status_code == 403

    resp = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers())
    assert resp.status_code == 200


def test_admin_grants_put_requires_correct_token(client):
    resp = client.put(f"/tier3/admin-grants/{CLIENT_ID}", json={"weekly_limit_cents": 1000})
    assert resp.status_code == 403


def test_admin_grants_delete_requires_correct_token(client):
    resp = client.delete(f"/tier3/admin-grants/{CLIENT_ID}")
    assert resp.status_code == 403


def test_admin_audit_requires_correct_token(client):
    resp = client.get("/tier3/admin-audit")
    assert resp.status_code == 403

    resp = client.get("/tier3/admin-audit", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json() == {"entries": []}


def test_admin_grants_get_with_no_grant_returns_null_limit_not_404(client):
    resp = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers())
    assert resp.status_code == 200
    body = resp.json()
    assert body["weekly_limit_cents"] is None
    assert body["remaining_cents"] is None
    assert body["used_cents"] == 0


# --- POST /tier3/orders: happy path and every rejection reason -----------


def test_order_within_limit_succeeds(client, monkeypatch):
    stub_introspection(monkeypatch)
    calls = stub_handoff(monkeypatch)
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(amount_cents=1000), headers=_order_headers())

    assert resp.status_code == 201
    body = resp.json()
    assert body["@type"] == "Order"
    assert body["orderStatus"] == "https://schema.org/OrderProcessing"
    assert body["remaining_cents"] == 4000
    assert body["orderNumber"] == "ERP-test-1"
    assert body["channel"] == "mock_erp"
    assert body["action_id"].startswith("act-")

    # The envelope the agent received: fixed schema, within_mandate mode,
    # budget state as of BEFORE this action's own reservation.
    assert len(calls) == 1
    envelope = calls[0]
    assert envelope["action_type"] == "order.place"
    assert envelope["client_id"] == CLIENT_ID
    assert envelope["mandate"]["mode"] == "within_mandate"
    assert envelope["mandate"]["weekly_limit_cents"] == 5000
    assert envelope["mandate"]["used_cents"] == 0
    assert envelope["mandate"]["approved_by"] is None


def test_order_over_limit_queues_for_approval_and_does_not_consume_budget(client, monkeypatch):
    """The step-10 two-mode contract change: over-mandate is 202-queued for
    human approval, not 403-rejected (the pre-pivot behavior)."""
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)

    # First order exactly exhausts the limit.
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=1000), headers=_order_headers())
    assert resp.status_code == 201

    # Second order has no budget left -> queued, not rejected.
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=1), headers=_order_headers())
    assert resp.status_code == 202
    body = resp.json()
    assert body["status"] == "pending_approval"
    assert body["status_path"] == f"/tier3/orders/{body['action_id']}"

    # A queued order must not itself count as usage — used_cents should
    # still reflect only the one accepted order until a human approves.
    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 1000
    assert status["remaining_cents"] == 0


def test_order_with_no_grant_rejected(client, monkeypatch):
    stub_introspection(monkeypatch)
    resp = client.post("/tier3/orders", json=_order_body(), headers=_order_headers())
    assert resp.status_code == 403
    assert "no Tier 3 grant" in resp.json()["detail"]


def test_order_revoked_token_rejected_and_audited_as_unknown_client(client, monkeypatch):
    """The revocation path: introspection returning active=false (a
    disabled/deleted Keycloak client, or a naturally expired token) must be
    rejected AND show up in the audit trail — this is the "immediate audit"
    half of Tier 3's requirements, not just the rejection itself."""
    stub_introspection(monkeypatch, active=False)
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(), headers=_order_headers())
    assert resp.status_code == 401

    audit = client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"]
    assert len(audit) == 1
    assert audit[0]["client_id"] == "unknown"
    assert audit[0]["outcome"] == "rejected"
    assert "introspection" in audit[0]["reason"]


def test_introspection_endpoint_down_fails_closed_not_500(client, monkeypatch):
    stub_introspection(monkeypatch, status=0, body=b"could not reach keycloak")
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(), headers=_order_headers())
    assert resp.status_code == 401


def test_introspection_endpoint_malformed_body_fails_closed(client, monkeypatch):
    stub_introspection(monkeypatch, status=200, body=b"not json")
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(), headers=_order_headers())
    assert resp.status_code == 401


def test_missing_client_verify_header_rejected(client, monkeypatch):
    stub_introspection(monkeypatch)
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(), headers={"Authorization": "Bearer x"})
    assert resp.status_code == 401

    audit = client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"]
    assert audit[0]["reason"] == "client certificate not verified"


def test_failed_client_verify_header_rejected(client, monkeypatch):
    stub_introspection(monkeypatch)
    grant(client, 5000)

    resp = client.post(
        "/tier3/orders",
        json=_order_body(),
        headers={"Authorization": "Bearer x", "X-SSL-Client-Verify": "FAILED:self signed certificate"},
    )
    assert resp.status_code == 401


def test_missing_bearer_token_rejected(client, monkeypatch):
    stub_introspection(monkeypatch)
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(), headers={"X-SSL-Client-Verify": "SUCCESS"})
    assert resp.status_code == 401


# --- immediate revocation: DELETE grant takes effect with no restart -----


def test_delete_grant_blocks_the_very_next_order_no_restart_needed(client, monkeypatch):
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
    assert resp.status_code == 201

    resp = client.delete(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json()["weekly_limit_cents"] is None

    resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
    assert resp.status_code == 403
    assert "no Tier 3 grant" in resp.json()["detail"]


# --- usage window ----------------------------------------------------------


def test_events_outside_the_window_stop_counting_toward_usage(client, monkeypatch):
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)

    resp = client.post("/tier3/orders", json=_order_body(amount_cents=1000), headers=_order_headers())
    assert resp.status_code == 201

    # Shrink the window to zero — the event just recorded is now outside it.
    app_module.store.tier3_window_seconds = 0

    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 0
    assert status["remaining_cents"] == 1000

    resp = client.post("/tier3/orders", json=_order_body(amount_cents=1000), headers=_order_headers())
    assert resp.status_code == 201


# --- no secret leakage ------------------------------------------------------


def test_introspection_secret_never_appears_in_any_response(client, monkeypatch):
    stub_introspection(monkeypatch, active=False)
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(), headers=_order_headers())
    assert introspection.TIER3_INTROSPECTION_SECRET not in resp.text

    resp = client.get("/tier3/admin-audit", headers=_admin_headers())
    assert introspection.TIER3_INTROSPECTION_SECRET not in resp.text


# --- regression: cross-tenant audit-buffer eviction (adversarial review) --


def test_audit_cap_is_per_client_and_cannot_evict_another_clients_usage(client, monkeypatch):
    """Found live during adversarial review: a client with NO Tier 3 grant
    at all (every rejected call still records an event) could spam rejected
    requests until a GLOBAL cap evicted a completely unrelated client's real
    accepted orders out of the buffer -- erasing that victim's audit history
    and, since tier3_used_cents only sums surviving events, silently
    refilling their spending budget. The cap must be per client_id."""
    app_module.store.tier3_audit_max = 3
    app_module.store.tier3_rate_limit_max = 1000  # isolate audit-eviction behavior from rate limiting
    stub_introspection(monkeypatch, client_id="victim")
    stub_handoff(monkeypatch)
    grant(client, 5000, client_id="victim")
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=500), headers=_order_headers())
    assert resp.status_code == 201

    # "attacker" has no grant at all -- every request is rejected -- and
    # sends far more than the cap's worth of junk events.
    stub_introspection(monkeypatch, client_id="attacker")
    for _ in range(10):
        resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
        assert resp.status_code == 403

    status = client.get("/tier3/admin-grants/victim", headers=_admin_headers()).json()
    assert status["used_cents"] == 500, "the victim's real spend must survive an unrelated client's flood"

    audit = client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"]
    victim_entries = [e for e in audit if e["client_id"] == "victim"]
    assert len(victim_entries) == 1
    assert victim_entries[0]["outcome"] == "accepted"


# --- regression: Tier 3's rate limit must not be Tier 1's in disguise ----


def test_orders_rate_limit_is_independent_of_tier1s_verify_rate_limit(client, monkeypatch):
    """Found live during adversarial review: /tier3/orders originally reused
    store.verify_rate_limit_max/window -- the same knob Tier 1's admin UI
    exposes as "Verify rate limit" with no mention of Tier 3 anywhere on
    that page. An admin raising Tier 1's limit for Tier 1 reasons silently
    loosened Tier 3's protection against hammering Keycloak's introspection
    endpoint too. The two must be independent."""
    stub_introspection(monkeypatch)
    grant(client, 1_000_000)

    # Loosen Tier 1's verify rate limit far past what Tier 3's own default
    # (10/60s) allows -- if the two were still coupled, this alone would let
    # every one of the requests below through.
    app_module.store.verify_rate_limit_max = 1000

    statuses = [
        client.post("/tier3/orders", json=_order_body(amount_cents=1), headers=_order_headers()).status_code
        for _ in range(15)
    ]
    assert 429 in statuses, "Tier 3's own rate limit must still trigger regardless of Tier 1's setting"


# --- step 10: handoff failure taxonomy (reserve-then-settle) ---------------


def test_agent_down_fails_closed_and_releases_budget(client, monkeypatch):
    stub_introspection(monkeypatch)
    grant(client, 5000)

    def down(envelope):
        return app_module.HandoffResult(kind="down")

    monkeypatch.setattr(app_module, "execute_handoff", down)
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=1000), headers=_order_headers())
    assert resp.status_code == 503

    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 0, "a not-executed action must not consume budget"

    audit = client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"]
    assert audit[0]["outcome"] == "rejected"
    assert "unavailable" in audit[0]["reason"]


def test_agent_reports_failed_releases_budget(client, monkeypatch):
    stub_introspection(monkeypatch)
    grant(client, 5000)

    def failed(envelope):
        return app_module.HandoffResult(kind="ok", status="failed")

    monkeypatch.setattr(app_module, "execute_handoff", failed)
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=1000), headers=_order_headers())
    assert resp.status_code == 502
    assert "not consumed" in resp.json()["detail"]

    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 0


def test_handoff_timeout_consumes_budget_and_warns_not_to_resubmit(client, monkeypatch):
    """The one branch where money fails closed by STANDING: a timed-out
    handoff may have executed, so the reservation is kept, the caller is
    told not to resubmit, and the audit row says execution is unknown."""
    stub_introspection(monkeypatch)
    grant(client, 5000)

    def unknown(envelope):
        return app_module.HandoffResult(kind="unknown")

    monkeypatch.setattr(app_module, "execute_handoff", unknown)
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=1000), headers=_order_headers())
    assert resp.status_code == 502
    assert "Do not resubmit" in resp.json()["detail"]

    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 1000, "an execution-unknown action must keep its reservation"

    audit = client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"]
    assert audit[0]["outcome"] == "accepted"
    assert "execution unknown" in audit[0]["reason"]


def test_concurrent_orders_cannot_jointly_exceed_the_mandate(client, monkeypatch):
    """Plan-review critical finding: without reserve-then-settle, N
    concurrent requests each sized at the full remaining budget all pass the
    check during the handoff window and all execute. With the lock, exactly
    one wins the reservation; the rest must queue (over-mandate), never
    execute."""
    import threading

    stub_introspection(monkeypatch)
    grant(client, 1000)
    app_module.store.tier3_rate_limit_max = 1000

    started = threading.Barrier(6)

    def slow_handoff(envelope):
        # A real handoff takes time; the barrier maximizes overlap so every
        # thread is inside the handler at once.
        return app_module.HandoffResult(
            kind="ok", status="executed", channel="mock_erp", decided_by="rules", reference="ERP-race"
        )

    monkeypatch.setattr(app_module, "execute_handoff", slow_handoff)

    results = []

    def place_order():
        started.wait()
        resp = client.post("/tier3/orders", json=_order_body(amount_cents=1000), headers=_order_headers())
        results.append(resp.status_code)

    threads = [threading.Thread(target=place_order) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert results.count(201) == 1, f"exactly one order may execute, got {results}"
    assert results.count(202) == 5, "the rest must queue for approval, not execute"

    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 1000, "the mandate must never be jointly exceeded"


# --- step 10: approval queue lifecycle -------------------------------------


def _queue_one(client, monkeypatch, amount_cents=2000, item="Exceptional order"):
    """Grant 1000, queue an over-mandate action, return its action_id."""
    resp = client.post(
        "/tier3/orders", json=_order_body(amount_cents=amount_cents, item=item), headers=_order_headers()
    )
    assert resp.status_code == 202
    return resp.json()["action_id"]


def test_queue_approve_executes_and_consumes_budget_once(client, monkeypatch):
    stub_introspection(monkeypatch)
    calls = stub_handoff(monkeypatch, reference="ERP-approved-1")
    grant(client, 1000)
    action_id = _queue_one(client, monkeypatch)

    pending = client.get("/tier3/admin-approvals", headers=_admin_headers()).json()["entries"]
    assert len(pending) == 1
    assert pending[0]["action_id"] == action_id
    assert pending[0]["grant"]["weekly_limit_cents"] == 1000

    resp = client.post(f"/tier3/admin-approvals/{action_id}/approve", headers=_admin_headers())
    assert resp.status_code == 200
    assert resp.json()["orderNumber"] == "ERP-approved-1"

    # The envelope carried the human approval, not autonomous mode.
    assert calls[-1]["mandate"]["mode"] == "approved_by_human"
    assert calls[-1]["mandate"]["approved_by"] == "admin"

    # Approved spend counts against the mandate (over-mandate by definition).
    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 2000

    # Double-approve: the entry was consumed; budget must not double.
    resp = client.post(f"/tier3/admin-approvals/{action_id}/approve", headers=_admin_headers())
    assert resp.status_code == 404
    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 2000


def test_approve_after_grant_revocation_refuses_409(client, monkeypatch):
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)
    action_id = _queue_one(client, monkeypatch)

    # Revoking the grant purges the pending entry entirely (F4b)...
    client.delete(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers())
    pending = client.get("/tier3/admin-approvals", headers=_admin_headers()).json()["entries"]
    assert pending == []

    # ...so approve finds nothing (404), and the caller's poll shows the
    # rejection rather than a dangling "queued".
    resp = client.post(f"/tier3/admin-approvals/{action_id}/approve", headers=_admin_headers())
    assert resp.status_code == 404

    poll = client.get(f"/tier3/orders/{action_id}", headers=_order_headers())
    assert poll.status_code == 200
    assert poll.json()["status"] == "rejected"
    assert "revoked" in poll.json()["detail"]


def test_approve_races_grant_revocation_409_when_entry_survives(client, monkeypatch):
    """The 409 path proper: the grant disappears but the entry is still in
    the queue (simulated directly, since DELETE grant normally purges it) --
    approval must refuse rather than execute for a revoked client."""
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)
    action_id = _queue_one(client, monkeypatch)

    # Simulate a revocation that raced past the purge (e.g. direct state
    # loss) -- the approval-time re-check is the last line of defense.
    del app_module.store.tier3_grants[CLIENT_ID]

    resp = client.post(f"/tier3/admin-approvals/{action_id}/approve", headers=_admin_headers())
    assert resp.status_code == 409

    poll = client.get(f"/tier3/orders/{action_id}", headers=_order_headers())
    assert poll.json()["status"] == "rejected"


def test_reject_then_poll_shows_rejected(client, monkeypatch):
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)
    action_id = _queue_one(client, monkeypatch)

    resp = client.post(f"/tier3/admin-approvals/{action_id}/reject", headers=_admin_headers())
    assert resp.status_code == 200

    poll = client.get(f"/tier3/orders/{action_id}", headers=_order_headers())
    assert poll.status_code == 200
    assert poll.json()["status"] == "rejected"

    # No budget was ever consumed for a rejected action.
    status = client.get(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers()).json()
    assert status["used_cents"] == 0


def test_pending_expiry_between_list_and_approve(client, monkeypatch):
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)
    action_id = _queue_one(client, monkeypatch)

    # Listed while alive...
    pending = client.get("/tier3/admin-approvals", headers=_admin_headers()).json()["entries"]
    assert len(pending) == 1

    # ...then the TTL elapses before the human clicks approve.
    app_module.store.tier3_pending[action_id].expires_at = 0

    resp = client.post(f"/tier3/admin-approvals/{action_id}/approve", headers=_admin_headers())
    assert resp.status_code == 404

    poll = client.get(f"/tier3/orders/{action_id}", headers=_order_headers())
    assert poll.json()["status"] == "expired"

    audit = client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"]
    assert any(e["outcome"] == "expired" and e["action_id"] == action_id for e in audit)


def test_expired_entries_do_not_block_the_pending_cap(client, monkeypatch):
    """Lazy prune must run BEFORE the cap check -- an expired entry must
    never hold a live queue slot (plan-review F9)."""
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)
    app_module.store.tier3_pending_max_per_client = 1
    app_module.store.tier3_rate_limit_max = 1000

    first = _queue_one(client, monkeypatch)
    # Cap is 1: a second queue attempt is refused while the first is alive.
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=2000), headers=_order_headers())
    assert resp.status_code == 403
    assert "awaiting approval" in resp.json()["detail"]

    # Expire the first -> the slot frees without any admin involvement.
    app_module.store.tier3_pending[first].expires_at = 0
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=2000), headers=_order_headers())
    assert resp.status_code == 202


def test_queue_full_is_audited_distinctly(client, monkeypatch):
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)
    app_module.store.tier3_pending_max_per_client = 1
    app_module.store.tier3_rate_limit_max = 1000

    _queue_one(client, monkeypatch)
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=2000), headers=_order_headers())
    assert resp.status_code == 403

    audit = client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"]
    assert audit[0]["reason"] == "pending-approval queue full for this client"


# --- step 10: the poll endpoint --------------------------------------------


def test_poll_mode1_action_shows_executed(client, monkeypatch):
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch, reference="ERP-poll-1")
    grant(client, 5000)

    resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
    action_id = resp.json()["action_id"]

    poll = client.get(f"/tier3/orders/{action_id}", headers=_order_headers())
    assert poll.status_code == 200
    body = poll.json()
    assert body["status"] == "executed"
    assert body["order_number"] == "ERP-poll-1"
    assert body["channel"] == "mock_erp"


def test_poll_unknown_id_404s(client, monkeypatch):
    stub_introspection(monkeypatch)
    resp = client.get("/tier3/orders/act-never-existed", headers=_order_headers())
    assert resp.status_code == 404


def test_poll_cross_client_denied_as_404(client, monkeypatch):
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 5000)
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
    action_id = resp.json()["action_id"]

    # Same action_id, introspected as a DIFFERENT client: identical 404 to
    # "never existed" -- no cross-client probing signal.
    stub_introspection(monkeypatch, client_id="someone-else")
    poll = client.get(f"/tier3/orders/{action_id}", headers=_order_headers())
    assert poll.status_code == 404


def test_poll_requires_mtls_and_bearer(client, monkeypatch):
    stub_introspection(monkeypatch)
    resp = client.get("/tier3/orders/act-x", headers={"Authorization": "Bearer x"})
    assert resp.status_code == 401
    resp = client.get("/tier3/orders/act-x", headers={"X-SSL-Client-Verify": "SUCCESS"})
    assert resp.status_code == 401


def test_poll_has_its_own_rate_bucket(client, monkeypatch):
    """Polling must neither share tier3_orders' bucket (a caller would 429
    its own order placement by polling) nor run unmetered (an amplifier at
    Keycloak's introspection endpoint)."""
    stub_introspection(monkeypatch)
    app_module.store.tier3_poll_rate_limit_max = 2

    assert client.get("/tier3/orders/act-x", headers=_order_headers()).status_code == 404
    assert client.get("/tier3/orders/act-x", headers=_order_headers()).status_code == 404
    assert client.get("/tier3/orders/act-x", headers=_order_headers()).status_code == 429

    # The order bucket is untouched by those three polls.
    stub_handoff(monkeypatch)
    grant(client, 5000)
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
    assert resp.status_code == 201


def test_polls_record_no_audit_events(client, monkeypatch):
    """A per-poll audit write would let a client evict its own accepted
    events at poll speed (refilling its budget via the documented cap
    residual) -- polls must be audit-silent on every path."""
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 5000)
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
    action_id = resp.json()["action_id"]

    before = len(client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"])
    for _ in range(5):
        client.get(f"/tier3/orders/{action_id}", headers=_order_headers())
    client.get("/tier3/orders/act-unknown", headers=_order_headers())
    after = len(client.get("/tier3/admin-audit", headers=_admin_headers()).json()["entries"])
    assert after == before


def test_poll_works_after_grant_revocation(client, monkeypatch):
    """A client whose mandate was revoked must still learn the fate of its
    already-resolved actions -- the poll chain deliberately has no grant
    check."""
    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 5000)
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
    action_id = resp.json()["action_id"]

    client.delete(f"/tier3/admin-grants/{CLIENT_ID}", headers=_admin_headers())
    poll = client.get(f"/tier3/orders/{action_id}", headers=_order_headers())
    assert poll.status_code == 200
    assert poll.json()["status"] == "executed"


# --- step 10: approvals auth + no secret leakage ---------------------------


def test_admin_approvals_require_correct_token(client, monkeypatch):
    assert client.get("/tier3/admin-approvals").status_code == 403
    assert client.post("/tier3/admin-approvals/act-x/approve").status_code == 403
    assert client.post("/tier3/admin-approvals/act-x/reject").status_code == 403
    assert (
        client.get("/tier3/admin-approvals", headers={"X-Admin-Token": "wrong"}).status_code == 403
    )


def test_agent_token_never_appears_in_any_response(client, monkeypatch):
    import agent_handoff

    stub_introspection(monkeypatch)
    stub_handoff(monkeypatch)
    grant(client, 1000)

    resp = client.post("/tier3/orders", json=_order_body(amount_cents=100), headers=_order_headers())
    assert agent_handoff.AGENT_INTERNAL_TOKEN not in resp.text
    resp = client.post("/tier3/orders", json=_order_body(amount_cents=5000), headers=_order_headers())
    assert agent_handoff.AGENT_INTERNAL_TOKEN not in resp.text
    resp = client.get("/tier3/admin-approvals", headers=_admin_headers())
    assert agent_handoff.AGENT_INTERNAL_TOKEN not in resp.text
