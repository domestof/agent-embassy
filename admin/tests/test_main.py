import json

import pytest
from fastapi.testclient import TestClient

import catalog_store
import keycloak_client
import main as app_module
import openbao_client
import tier1_client
import tier3_client

AUTH = ("testadmin", "testpass")

PRODUCT_DOC = {
    "@context": "https://schema.org",
    "@type": "ItemList",
    "itemListElement": [{"@type": "Product", "name": "Example product", "description": "Placeholder"}],
}
EMPTY_LIST_DOC = {"@context": "https://schema.org", "@type": "ItemList", "itemListElement": []}
MANIFEST_DOC = {
    "profile": "agent-embassy/0.1-draft",
    "last_updated": "2026-08-08",
    "entity": {"name": "Example Company", "tax_id": "NIF/CIF", "website": "https://example.com", "country": "ES"},
    "public_catalog": {"products": "/catalog/products.json"},
    "access_tiers": [
        {"tier": 0, "auth": "none", "rate_limit": "60/h"},
        {
            "tier": 1,
            "auth": "domain-challenge",
            "resources": {"contact": "/catalog/contact.json"},
            "session_ttl_seconds": 3600,
        },
    ],
    "security": {"gateway_required": True, "direct_llm_exposure": False, "audit_logging": True},
}


@pytest.fixture(autouse=True)
def stub_tier3_grant(monkeypatch):
    """_render_client_detail (main.py) now calls tier3_client.get_grant on
    every keycloak-client detail render — without this, every existing
    detail-route test below (there was no reason for any of them to know
    Tier 3 exists) would each make a real, failing urllib call to
    http://verify:8001 instead of a fast, deterministic "no grant" result.
    Tests that specifically care about a Tier 3 grant override this
    themselves via monkeypatch.setattr(tier3_client, "get_grant", ...)."""
    monkeypatch.setattr(
        tier3_client,
        "get_grant",
        lambda client_id: tier3_client.GrantResult(
            ok=True,
            values={"weekly_limit_cents": None, "used_cents": 0, "remaining_cents": None, "window_seconds": 604800},
        ),
    )


@pytest.fixture
def client(tmp_path, monkeypatch):
    files = {}
    for kind, doc in [
        ("products", PRODUCT_DOC),
        ("services", EMPTY_LIST_DOC),
        ("jobs", EMPTY_LIST_DOC),
        ("demand", EMPTY_LIST_DOC),
    ]:
        path = tmp_path / f"{kind}.json"
        path.write_text(json.dumps(doc))
        files[kind] = path
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(MANIFEST_DOC))

    monkeypatch.setattr(catalog_store, "FILES", files)
    monkeypatch.setattr(catalog_store, "MANIFEST_PATH", manifest_path)
    return TestClient(app_module.app)


def test_catalog_list_requires_auth(client):
    resp = client.get("/catalog/products")
    assert resp.status_code == 401


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_fastapi_auto_docs_routes_are_disabled(client, path):
    # These are mounted by FastAPI itself, not by any @app.get/@app.post in
    # this file, so Depends(verify_admin) never applies to them --
    # confirmed live that all three were reachable with zero credentials
    # and handed out the full route map (every path and form field name)
    # before docs_url/redoc_url/openapi_url were set to None in main.py.
    resp = client.get(path, auth=AUTH)
    assert resp.status_code == 404
    resp_noauth = client.get(path)
    assert resp_noauth.status_code == 404


def test_catalog_list_shows_seeded_item(client):
    resp = client.get("/catalog/products", auth=AUTH)
    assert resp.status_code == 200
    assert "Example product" in resp.text


def test_catalog_list_unknown_kind_404s(client):
    resp = client.get("/catalog/not-a-kind", auth=AUTH)
    assert resp.status_code == 404


def test_add_item_end_to_end(client):
    resp = client.post(
        "/catalog/products/new",
        auth=AUTH,
        data={"field__name": "New Widget", "field__description": "desc"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    items = catalog_store.list_items("products")
    assert len(items) == 2
    assert items[1]["name"] == "New Widget"


def test_add_item_missing_required_field_is_rejected(client):
    resp = client.post("/catalog/products/new", auth=AUTH, data={"field__name": ""})
    assert resp.status_code == 400
    assert len(catalog_store.list_items("products")) == 1  # nothing was written


def test_edit_item_end_to_end(client):
    resp = client.post(
        "/catalog/products/0/edit",
        auth=AUTH,
        data={"field__name": "Renamed", "field__description": "d"},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert catalog_store.list_items("products")[0]["name"] == "Renamed"


def test_edit_item_bad_index_404s(client):
    resp = client.get("/catalog/products/5/edit", auth=AUTH)
    assert resp.status_code == 404


def test_edit_item_negative_index_404s_instead_of_wrapping(client):
    # Plain Python list indexing treats -1 as "the last item," not "not
    # found" -- confirmed live that /catalog/products/-1/edit rendered the
    # last item's edit form. The `Path(ge=0)` constraint on `index` in
    # main.py rejects this before it ever reaches catalog_store.
    resp = client.get("/catalog/products/-1/edit", auth=AUTH)
    assert resp.status_code == 422


def test_delete_item_negative_index_404s_instead_of_wrapping(client):
    resp = client.post("/catalog/products/-1/delete", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 422
    assert len(catalog_store.list_items("products")) == 1  # nothing was deleted


def test_delete_item_end_to_end(client):
    resp = client.post("/catalog/products/0/delete", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 303
    assert catalog_store.list_items("products") == []


def test_manifest_edit_shows_tier0_only_editable(client):
    resp = client.get("/manifest", auth=AUTH)
    assert resp.status_code == 200
    assert "Example Company" in resp.text


def test_manifest_update_preserves_tier1_entry_untouched(client):
    resp = client.post(
        "/manifest",
        auth=AUTH,
        data={
            "entity__name": "New Name",
            "entity__tax_id": "NIF/CIF",
            "entity__website": "https://example.com",
            "entity__country": "ES",
            "rate_limit": "60/h",
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303
    doc = catalog_store.load_manifest()
    assert doc["entity"]["name"] == "New Name"
    tier1 = next(t for t in doc["access_tiers"] if t["tier"] == 1)
    assert tier1 == MANIFEST_DOC["access_tiers"][1]  # untouched by a Tier-0-only edit


def test_manifest_get_fails_closed_when_tier0_missing(client):
    # A hand-edited/corrupted manifest missing its tier-0 entry must not be
    # silently papered over (e.g. by fabricating one) -- main.py's
    # _tier0_entry raises instead. Confirmed live during adversarial review
    # that this really does surface as a 500, not a fabricated tier-0 entry
    # or a silent no-op.
    doc = json.loads(json.dumps(MANIFEST_DOC))
    doc["access_tiers"] = [t for t in doc["access_tiers"] if t["tier"] != 0]
    catalog_store.MANIFEST_PATH.write_text(json.dumps(doc))

    resp = client.get("/manifest", auth=AUTH)
    assert resp.status_code == 500


def test_manifest_post_fails_closed_when_tier0_missing_and_does_not_write(client):
    doc = json.loads(json.dumps(MANIFEST_DOC))
    doc["access_tiers"] = [t for t in doc["access_tiers"] if t["tier"] != 0]
    raw_before = json.dumps(doc)
    catalog_store.MANIFEST_PATH.write_text(raw_before)

    resp = client.post(
        "/manifest",
        auth=AUTH,
        data={"entity__name": "New Name", "rate_limit": "1/h"},
        follow_redirects=False,
    )
    assert resp.status_code == 500
    # The mutate callback must raise before catalog_store ever calls
    # _atomic_write -- the file on disk should be untouched, not a
    # half-mutated document missing tier 0.
    assert catalog_store.MANIFEST_PATH.read_text() == raw_before


def test_console_route_uses_test_console_module(client, monkeypatch):
    import test_console

    monkeypatch.setattr(test_console, "discover_resources", lambda: {"manifest": "/.well-known/agent-embassy.json"})
    monkeypatch.setattr(
        test_console,
        "run_check",
        lambda path: test_console.ConsoleResult(
            path=path, status=200, headers={}, raw_body="{}", pretty_body="{}", error=None
        ),
    )
    resp = client.post("/console/run", auth=AUTH, data={"path": "/.well-known/agent-embassy.json"})
    assert resp.status_code == 200
    assert "200" in resp.text


def test_monitoring_route_renders(client, monkeypatch):
    import log_tail

    monkeypatch.setattr(log_tail, "recent_catalog_requests", lambda: [])
    resp = client.get("/monitoring", auth=AUTH)
    assert resp.status_code == 200


def test_monitoring_shows_verified_domain_when_present(client, monkeypatch):
    """A Tier 1 session proved on a /catalog/contact.json hit must actually
    surface here -- see nginx/tier0-tier1-locations.conf's auth_request_set
    and admin/log_tail.py's regex: this is the one place that proof is
    consumed instead of being computed and discarded."""
    import log_tail

    entry = log_tail.LogEntry(
        ip="203.0.113.5",
        time="14/Aug/2026:10:39:40 +0000",
        method="GET",
        path="/catalog/contact.json",
        status=200,
        user_agent="some-agent",
        verified_domain="acme-example-partner.example.com",
    )
    monkeypatch.setattr(log_tail, "recent_catalog_requests", lambda: [entry])
    resp = client.get("/monitoring", auth=AUTH)
    assert resp.status_code == 200
    assert "acme-example-partner.example.com" in resp.text


def test_monitoring_shows_dash_when_domain_not_verified(client, monkeypatch):
    import log_tail

    entry = log_tail.LogEntry(
        ip="203.0.113.5",
        time="14/Aug/2026:10:39:40 +0000",
        method="GET",
        path="/catalog/products.json",
        status=200,
        user_agent="some-agent",
        verified_domain=None,
    )
    monkeypatch.setattr(log_tail, "recent_catalog_requests", lambda: [entry])
    resp = client.get("/monitoring", auth=AUTH)
    assert resp.status_code == 200
    assert "—" in resp.text


# --- Tier 2 Keycloak client management ---

_CLIENT = keycloak_client.ClientInfo(
    uuid="uuid-1", client_id="acme-partner", name="Acme", enabled=True, has_audience_mapper=True
)
_CLIENT_NO_MAPPER = keycloak_client.ClientInfo(
    uuid="uuid-2", client_id="legacy-partner", name="Legacy", enabled=True, has_audience_mapper=False
)


@pytest.mark.parametrize(
    "method,path",
    [
        ("get", "/keycloak-clients"),
        ("get", "/keycloak-clients/new"),
        ("post", "/keycloak-clients/new"),
        ("get", "/keycloak-clients/uuid-1"),
        ("post", "/keycloak-clients/uuid-1/reveal-secret"),
        ("post", "/keycloak-clients/uuid-1/regenerate-secret"),
        ("post", "/keycloak-clients/uuid-1/delete"),
    ],
)
def test_keycloak_client_routes_require_auth(client, method, path):
    resp = getattr(client, method)(path)
    assert resp.status_code == 401


def test_keycloak_clients_list_renders(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client, "list_clients", lambda: keycloak_client.ListResult(ok=True, clients=[_CLIENT])
    )
    resp = client.get("/keycloak-clients", auth=AUTH)
    assert resp.status_code == 200
    assert "acme-partner" in resp.text


def test_keycloak_clients_list_shows_error_banner_when_keycloak_down(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client,
        "list_clients",
        lambda: keycloak_client.ListResult(ok=False, clients=[], error="could not reach Keycloak"),
    )
    resp = client.get("/keycloak-clients", auth=AUTH)
    assert resp.status_code == 200  # degrades to a visible error, not a crash
    assert "could not reach Keycloak" in resp.text


def test_keycloak_client_create_rejects_bad_client_id_before_calling_create_client(client, monkeypatch):
    def _must_not_be_called(*args, **kwargs):
        raise AssertionError("create_client should not be called for locally-invalid input")

    monkeypatch.setattr(keycloak_client, "create_client", _must_not_be_called)
    resp = client.post("/keycloak-clients/new", auth=AUTH, data={"client_id": "@bad id!", "name": "x"})
    assert resp.status_code == 400


def test_keycloak_client_create_end_to_end(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client,
        "create_client",
        lambda client_id, name: keycloak_client.CreateResult(ok=True, client=_CLIENT, secret="s3cr3t"),
    )
    resp = client.post(
        "/keycloak-clients/new", auth=AUTH, data={"client_id": "acme-partner", "name": "Acme"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/keycloak-clients/uuid-1"


def test_keycloak_client_create_keycloak_failure_rerenders_form(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client,
        "create_client",
        lambda client_id, name: keycloak_client.CreateResult(ok=False, error="a client named 'acme-partner' already exists"),
    )
    resp = client.post("/keycloak-clients/new", auth=AUTH, data={"client_id": "acme-partner", "name": "Acme"})
    assert resp.status_code == 400
    assert "already exists" in resp.text


def test_keycloak_client_create_writes_the_secret_to_openbao(client, monkeypatch):
    captured = {}
    monkeypatch.setattr(
        keycloak_client,
        "create_client",
        lambda client_id, name: keycloak_client.CreateResult(ok=True, client=_CLIENT, secret="s3cr3t"),
    )

    def fake_write(client_id, secret, keycloak_uuid):
        captured["args"] = (client_id, secret, keycloak_uuid)
        return openbao_client.WriteResult(ok=True)

    monkeypatch.setattr(openbao_client, "write_client_secret", fake_write)
    resp = client.post(
        "/keycloak-clients/new", auth=AUTH, data={"client_id": "acme-partner", "name": "Acme"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/keycloak-clients/uuid-1"  # no warning query param on success
    assert captured["args"] == ("acme-partner", "s3cr3t", "uuid-1")


def test_keycloak_client_create_surfaces_a_warning_but_does_not_roll_back_on_openbao_failure(client, monkeypatch):
    # The core edge-case guarantee this feature depends on: a backup-copy
    # failure must never destroy the Keycloak client that was just created.
    monkeypatch.setattr(
        keycloak_client,
        "create_client",
        lambda client_id, name: keycloak_client.CreateResult(ok=True, client=_CLIENT, secret="s3cr3t"),
    )
    monkeypatch.setattr(
        openbao_client, "write_client_secret", lambda *a, **k: openbao_client.WriteResult(ok=False, error="unreachable")
    )
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    resp = client.post(
        "/keycloak-clients/new", auth=AUTH, data={"client_id": "acme-partner", "name": "Acme"}, follow_redirects=False
    )
    assert resp.status_code == 303  # client creation itself still succeeds
    assert resp.headers["location"] == "/keycloak-clients/uuid-1?openbao_warning=1"

    detail_resp = client.get(resp.headers["location"], auth=AUTH)
    assert detail_resp.status_code == 200
    assert "OpenBao" in detail_resp.text


def test_keycloak_client_create_with_no_secret_surfaces_openbao_warning(client, monkeypatch):
    # create_client() has a documented fallback where Keycloak's secret-fetch
    # GET itself fails: CreateResult(ok=True, client=..., secret=None) --
    # still a successful client creation, just no secret to mirror. This
    # must surface a warning, not silently look identical to a real
    # successful mirror write. Deliberately does NOT mock
    # openbao_client.write_client_secret itself -- that would only prove
    # main.py forwards whatever WriteResult it's handed, not that the real
    # None-secret guard (openbao_client.py, its own regression test covers
    # it in isolation) actually fires through the full route. OPENBAO_ADDR/
    # TOKEN are set here to simulate a configured (prod-like) admin service
    # -- local dev's real unconfigured state would return skipped=True
    # regardless of the secret, which is a different case already covered
    # by test_keycloak_client_create_openbao_skipped_shows_no_warning below.
    monkeypatch.setattr(openbao_client, "OPENBAO_ADDR", "http://openbao:8200")
    monkeypatch.setattr(openbao_client, "OPENBAO_TOKEN", "test-token")
    monkeypatch.setattr(
        keycloak_client,
        "create_client",
        lambda client_id, name: keycloak_client.CreateResult(ok=True, client=_CLIENT, secret=None),
    )
    resp = client.post(
        "/keycloak-clients/new", auth=AUTH, data={"client_id": "acme-partner", "name": "Acme"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/keycloak-clients/uuid-1?openbao_warning=1"


def test_keycloak_client_create_openbao_skipped_shows_no_warning(client, monkeypatch):
    # skipped=True (OpenBao not configured, e.g. local dev) is not a
    # failure -- must not surface a warning.
    monkeypatch.setattr(
        keycloak_client,
        "create_client",
        lambda client_id, name: keycloak_client.CreateResult(ok=True, client=_CLIENT, secret="s3cr3t"),
    )
    monkeypatch.setattr(openbao_client, "write_client_secret", lambda *a, **k: openbao_client.WriteResult(ok=True, skipped=True))
    resp = client.post(
        "/keycloak-clients/new", auth=AUTH, data={"client_id": "acme-partner", "name": "Acme"}, follow_redirects=False
    )
    assert resp.headers["location"] == "/keycloak-clients/uuid-1"


def test_keycloak_client_detail_not_found_404s(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, not_found=True)
    )
    resp = client.get("/keycloak-clients/nonexistent", auth=AUTH)
    assert resp.status_code == 404


def test_keycloak_client_detail_shows_missing_audience_mapper_warning(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT_NO_MAPPER)
    )
    resp = client.get("/keycloak-clients/uuid-2", auth=AUTH)
    assert resp.status_code == 200
    assert "missing" in resp.text


def test_keycloak_client_detail_does_not_show_present_mapper_as_missing(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    resp = client.get("/keycloak-clients/uuid-1", auth=AUTH)
    assert resp.status_code == 200
    assert "missing" not in resp.text


def test_keycloak_client_secret_not_shown_before_reveal(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    resp = client.get("/keycloak-clients/uuid-1", auth=AUTH)
    assert resp.status_code == 200
    assert "s3cr3t-should-never-appear-here" not in resp.text
    assert "Reveal secret" in resp.text


def test_keycloak_client_reveal_secret_shows_it(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    monkeypatch.setattr(
        keycloak_client, "get_secret", lambda uuid: keycloak_client.SecretResult(ok=True, secret="s3cr3t-value")
    )
    resp = client.post("/keycloak-clients/uuid-1/reveal-secret", auth=AUTH)
    assert resp.status_code == 200
    assert "s3cr3t-value" in resp.text


def test_keycloak_client_reveal_secret_writes_through_to_openbao(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    monkeypatch.setattr(
        keycloak_client, "get_secret", lambda uuid: keycloak_client.SecretResult(ok=True, secret="s3cr3t-value")
    )
    captured = {}

    def fake_write(client_id, secret, keycloak_uuid):
        captured["args"] = (client_id, secret, keycloak_uuid)
        return openbao_client.WriteResult(ok=True)

    monkeypatch.setattr(openbao_client, "write_client_secret", fake_write)
    resp = client.post("/keycloak-clients/uuid-1/reveal-secret", auth=AUTH)
    assert resp.status_code == 200
    assert captured["args"] == ("acme-partner", "s3cr3t-value", "uuid-1")
    assert "OpenBao" not in resp.text  # no warning on success


def test_keycloak_client_reveal_secret_surfaces_openbao_warning_on_failure(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    monkeypatch.setattr(
        keycloak_client, "get_secret", lambda uuid: keycloak_client.SecretResult(ok=True, secret="s3cr3t-value")
    )
    monkeypatch.setattr(
        openbao_client, "write_client_secret", lambda *a, **k: openbao_client.WriteResult(ok=False, error="unreachable")
    )
    resp = client.post("/keycloak-clients/uuid-1/reveal-secret", auth=AUTH)
    assert resp.status_code == 200  # the secret itself is still shown, this is non-blocking
    assert "s3cr3t-value" in resp.text
    assert "OpenBao" in resp.text


def test_keycloak_client_regenerate_secret_shows_new_secret(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    monkeypatch.setattr(
        keycloak_client, "regenerate_secret", lambda uuid: keycloak_client.SecretResult(ok=True, secret="new-secret")
    )
    resp = client.post("/keycloak-clients/uuid-1/regenerate-secret", auth=AUTH)
    assert resp.status_code == 200
    assert "new-secret" in resp.text


def test_keycloak_client_delete_end_to_end(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "delete_client", lambda uuid: keycloak_client.DeleteResult(ok=True))
    resp = client.post("/keycloak-clients/uuid-1/delete", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/keycloak-clients"


def test_keycloak_client_delete_cleans_up_openbao_best_effort(client, monkeypatch):
    # client_id comes straight from delete_client's own DeleteResult (its
    # internal get_client() fetch, not a separate one main.py used to make
    # -- see keycloak_client.delete_client's docstring for why that older
    # shape was a silent-failure gap).
    monkeypatch.setattr(
        keycloak_client, "delete_client", lambda uuid: keycloak_client.DeleteResult(ok=True, client_id="acme-partner")
    )
    captured = {}

    def fake_delete(client_id):
        captured["client_id"] = client_id
        return openbao_client.WriteResult(ok=True)

    monkeypatch.setattr(openbao_client, "delete_client_secret", fake_delete)
    resp = client.post("/keycloak-clients/uuid-1/delete", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 303
    assert captured["client_id"] == "acme-partner"


def test_keycloak_client_delete_succeeds_even_if_openbao_cleanup_fails(client, monkeypatch):
    # Best-effort: the Keycloak client is already gone (the security-relevant
    # fact) by the time this runs -- a failed OpenBao cleanup must not turn a
    # successful delete into an error response.
    monkeypatch.setattr(
        keycloak_client, "delete_client", lambda uuid: keycloak_client.DeleteResult(ok=True, client_id="acme-partner")
    )
    monkeypatch.setattr(
        openbao_client, "delete_client_secret", lambda client_id: openbao_client.WriteResult(ok=False, error="unreachable")
    )
    resp = client.post("/keycloak-clients/uuid-1/delete", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/keycloak-clients"


def test_keycloak_client_delete_not_found_404s(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client, "delete_client", lambda uuid: keycloak_client.DeleteResult(ok=True, not_found=True)
    )
    resp = client.post("/keycloak-clients/uuid-1/delete", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 404


def test_keycloak_client_mutating_routes_degrade_cleanly_when_keycloak_down(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=False, error="could not reach Keycloak")
    )
    monkeypatch.setattr(
        keycloak_client, "delete_client", lambda uuid: keycloak_client.DeleteResult(ok=False, error="could not reach Keycloak")
    )
    for method, path in [
        ("get", "/keycloak-clients/uuid-1"),
        ("post", "/keycloak-clients/uuid-1/reveal-secret"),
        ("post", "/keycloak-clients/uuid-1/regenerate-secret"),
        ("post", "/keycloak-clients/uuid-1/delete"),
    ]:
        resp = getattr(client, method)(path, auth=AUTH)
        assert resp.status_code == 502  # a deliberate upstream-failure status, never a bare 500
        assert "could not reach Keycloak" in resp.text


def test_keycloak_client_error_paths_never_leak_admin_credentials(client, monkeypatch):
    # Turns the adversarial-review question ("does any error path leak the
    # Keycloak admin password or a minted bearer token?") into an automated
    # check -- deliberately WITHOUT mocking keycloak_client's own functions,
    # so this exercises the real error-formatting code in keycloak_client.py,
    # not just main.py's plumbing of whatever `error` string a mock hands it.
    monkeypatch.setattr(
        keycloak_client, "_ADMIN_REALM_TOKEN_URL", "http://127.0.0.1:1/realms/master/protocol/openid-connect/token"
    )

    resp = client.get("/keycloak-clients", auth=AUTH)
    assert resp.status_code == 200  # degrades to a visible error, not a crash
    assert keycloak_client.KEYCLOAK_ADMIN_PASSWORD not in resp.text
    assert keycloak_client.KEYCLOAK_ADMIN_USERNAME not in resp.text

    resp = client.post("/keycloak-clients/new", auth=AUTH, data={"client_id": "acme-partner", "name": "Acme"})
    assert resp.status_code == 400
    assert keycloak_client.KEYCLOAK_ADMIN_PASSWORD not in resp.text


_TIER1_VALUES = {
    "challenge_ttl_seconds": 300,
    "session_ttl_seconds": 3600,
    "challenge_rate_limit_max": 10,
    "challenge_rate_limit_window": 60,
    "verify_rate_limit_max": 10,
    "verify_rate_limit_window": 60,
}


@pytest.mark.parametrize("method,path", [("get", "/tier1-config"), ("post", "/tier1-config")])
def test_tier1_config_routes_require_auth(client, method, path):
    resp = getattr(client, method)(path)
    assert resp.status_code == 401


def test_tier1_config_form_renders_current_values(client, monkeypatch):
    monkeypatch.setattr(
        tier1_client, "get_config", lambda: tier1_client.ConfigResult(ok=True, values=_TIER1_VALUES)
    )
    resp = client.get("/tier1-config", auth=AUTH)
    assert resp.status_code == 200
    assert "300" in resp.text
    assert "3600" in resp.text


def test_tier1_config_form_shows_error_banner_when_verify_down(client, monkeypatch):
    monkeypatch.setattr(
        tier1_client,
        "get_config",
        lambda: tier1_client.ConfigResult(ok=False, error="could not reach verify"),
    )
    resp = client.get("/tier1-config", auth=AUTH)
    assert resp.status_code == 502  # degrades to a visible error, not a crash
    assert "could not reach verify" in resp.text


def test_tier1_config_update_rejects_non_integer_before_calling_verify(client, monkeypatch):
    def _must_not_be_called(**kwargs):
        raise AssertionError("update_config should not be called for locally-invalid input")

    monkeypatch.setattr(tier1_client, "update_config", _must_not_be_called)
    data = {**_TIER1_VALUES, "challenge_ttl_seconds": "not-a-number"}
    resp = client.post("/tier1-config", auth=AUTH, data=data)
    assert resp.status_code == 400
    assert "challenge_ttl_seconds" in resp.text


def test_tier1_config_update_end_to_end(client, monkeypatch):
    captured = {}

    def fake_update(**kwargs):
        captured.update(kwargs)
        return tier1_client.ConfigResult(ok=True, values=kwargs)

    monkeypatch.setattr(tier1_client, "update_config", fake_update)
    resp = client.post("/tier1-config", auth=AUTH, data=_TIER1_VALUES, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/tier1-config"
    assert captured == _TIER1_VALUES


def test_tier1_config_update_verify_failure_rerenders_form(client, monkeypatch):
    monkeypatch.setattr(
        tier1_client,
        "update_config",
        lambda **kwargs: tier1_client.ConfigResult(ok=False, error="one or more values are out of the allowed range"),
    )
    resp = client.post("/tier1-config", auth=AUTH, data=_TIER1_VALUES)
    assert resp.status_code == 400
    assert "out of the allowed range" in resp.text


# --- Tier 3 demo (weekly grants, revoke/disable, audit) ---


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", "/keycloak-clients/uuid-1/tier3-grant"),
        ("post", "/keycloak-clients/uuid-1/tier3-grant/revoke"),
        ("post", "/keycloak-clients/uuid-1/disable"),
        ("post", "/keycloak-clients/uuid-1/enable"),
        ("get", "/tier3-audit"),
    ],
)
def test_tier3_routes_require_auth(client, method, path):
    resp = getattr(client, method)(path)
    assert resp.status_code == 401


def test_tier3_grant_set_end_to_end(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    captured = {}

    def fake_set_grant(client_id, weekly_limit_cents):
        captured["client_id"] = client_id
        captured["weekly_limit_cents"] = weekly_limit_cents
        return tier3_client.GrantResult(ok=True, values={})

    monkeypatch.setattr(tier3_client, "set_grant", fake_set_grant)
    resp = client.post(
        "/keycloak-clients/uuid-1/tier3-grant", auth=AUTH, data={"weekly_limit_eur": "400"}, follow_redirects=False
    )
    assert resp.status_code == 303
    assert resp.headers["location"] == "/keycloak-clients/uuid-1"
    # acme-partner (_CLIENT.client_id) -- verify is keyed by client_id, not
    # Keycloak's uuid -- and whole euros are converted to cents.
    assert captured == {"client_id": "acme-partner", "weekly_limit_cents": 40000}


def test_tier3_grant_set_rejects_non_integer_euros_before_calling_verify(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))

    def _must_not_be_called(*args, **kwargs):
        raise AssertionError("set_grant should not be called for locally-invalid input")

    monkeypatch.setattr(tier3_client, "set_grant", _must_not_be_called)
    resp = client.post("/keycloak-clients/uuid-1/tier3-grant", auth=AUTH, data={"weekly_limit_eur": "not-a-number"})
    assert resp.status_code == 400
    assert "whole number" in resp.text


def test_tier3_grant_set_unknown_client_404s(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, not_found=True))
    resp = client.post("/keycloak-clients/nonexistent/tier3-grant", auth=AUTH, data={"weekly_limit_eur": "10"})
    assert resp.status_code == 404


def test_tier3_grant_revoke_end_to_end(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    captured = {}
    monkeypatch.setattr(
        tier3_client,
        "revoke_grant",
        lambda client_id: (captured.setdefault("client_id", client_id), tier3_client.GrantResult(ok=True, values={}))[1],
    )
    resp = client.post("/keycloak-clients/uuid-1/tier3-grant/revoke", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 303
    assert captured["client_id"] == "acme-partner"


def test_keycloak_client_disable_end_to_end(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client, "set_client_enabled", lambda uuid, enabled: keycloak_client.EnabledResult(ok=True, enabled=enabled)
    )
    resp = client.post("/keycloak-clients/uuid-1/disable", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/keycloak-clients/uuid-1"


def test_keycloak_client_enable_end_to_end(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client, "set_client_enabled", lambda uuid, enabled: keycloak_client.EnabledResult(ok=True, enabled=enabled)
    )
    resp = client.post("/keycloak-clients/uuid-1/enable", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 303


def test_keycloak_client_disable_not_found_404s(client, monkeypatch):
    monkeypatch.setattr(
        keycloak_client, "set_client_enabled", lambda uuid, enabled: keycloak_client.EnabledResult(ok=True, not_found=True)
    )
    resp = client.post("/keycloak-clients/uuid-1/disable", auth=AUTH, follow_redirects=False)
    assert resp.status_code == 404


def test_keycloak_client_detail_shows_tier3_grant(client, monkeypatch):
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    monkeypatch.setattr(
        tier3_client,
        "get_grant",
        lambda client_id: tier3_client.GrantResult(
            ok=True, values={"weekly_limit_cents": 40000, "used_cents": 1000, "remaining_cents": 39000, "window_seconds": 604800}
        ),
    )
    resp = client.get("/keycloak-clients/uuid-1", auth=AUTH)
    assert resp.status_code == 200
    assert "400.00" in resp.text
    assert "Revoke Tier 3 access" in resp.text


def test_keycloak_client_detail_shows_no_grant_state(client, monkeypatch):
    # stub_tier3_grant (autouse) already returns weekly_limit_cents=None.
    monkeypatch.setattr(keycloak_client, "get_client", lambda uuid: keycloak_client.DetailResult(ok=True, client=_CLIENT))
    resp = client.get("/keycloak-clients/uuid-1", auth=AUTH)
    assert resp.status_code == 200
    assert "No Tier 3 grant" in resp.text
    assert "Revoke Tier 3 access" not in resp.text


def test_tier3_audit_renders(client, monkeypatch):
    monkeypatch.setattr(
        tier3_client,
        "list_audit",
        lambda: tier3_client.AuditResult(
            ok=True,
            entries=[
                {
                    "at": 1700000000.0,
                    "client_id": "acme-partner",
                    "item": "Bath towels",
                    "amount_cents": 1000,
                    "outcome": "accepted",
                    "reason": "within weekly limit",
                    "order_number": "AI-123-abc",
                }
            ],
        ),
    )
    resp = client.get("/tier3-audit", auth=AUTH)
    assert resp.status_code == 200
    assert "acme-partner" in resp.text
    assert "AI-123-abc" in resp.text


def test_tier3_audit_shows_error_banner_when_verify_down(client, monkeypatch):
    monkeypatch.setattr(
        tier3_client, "list_audit", lambda: tier3_client.AuditResult(ok=False, entries=[], error="could not reach verify")
    )
    resp = client.get("/tier3-audit", auth=AUTH)
    assert resp.status_code == 502
    assert "could not reach verify" in resp.text


# --- step 10: approvals + internal-agent pages ------------------------------


import agent_client


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/approvals"),
        ("POST", "/approvals/act-1-ab/approve"),
        ("POST", "/approvals/act-1-ab/reject"),
        ("GET", "/internal-agent"),
    ],
)
def test_step10_routes_require_auth(client, method, path):
    resp = client.request(method, path)
    assert resp.status_code == 401


def test_approvals_page_lists_pending_with_grant_state(client, monkeypatch):
    entries = [
        {
            "action_id": "act-1-ab",
            "client_id": "laundry-co",
            "item": "Towels",
            "quantity": 3,
            "amount_cents": 60000,
            "queued_at": 1.0,
            "expires_at": 2.0,
            "grant": {"client_id": "laundry-co", "weekly_limit_cents": 40000, "used_cents": 100, "remaining_cents": 39900, "window_seconds": 604800},
        }
    ]
    monkeypatch.setattr(
        tier3_client, "list_pending", lambda: tier3_client.ApprovalsResult(ok=True, entries=entries)
    )
    resp = client.get("/approvals", auth=AUTH)
    assert resp.status_code == 200
    assert "laundry-co" in resp.text
    assert "€600.00" in resp.text
    assert "€400.00" in resp.text  # the mandate limit, shown next to the entry
    assert "duplicate" not in resp.text


def test_approvals_page_marks_duplicates(client, monkeypatch):
    entry = {
        "action_id": "act-1-ab",
        "client_id": "laundry-co",
        "item": "Towels",
        "quantity": 3,
        "amount_cents": 60000,
        "queued_at": 1.0,
        "expires_at": 2.0,
        "grant": {"client_id": "laundry-co", "weekly_limit_cents": 40000, "used_cents": 0, "remaining_cents": 40000, "window_seconds": 604800},
    }
    twin = dict(entry, action_id="act-2-cd")
    monkeypatch.setattr(
        tier3_client, "list_pending", lambda: tier3_client.ApprovalsResult(ok=True, entries=[entry, twin])
    )
    resp = client.get("/approvals", auth=AUTH)
    assert resp.status_code == 200
    assert resp.text.count("duplicate") >= 2


def test_approvals_page_shows_revoked_mandate_badge(client, monkeypatch):
    entries = [
        {
            "action_id": "act-1-ab",
            "client_id": "laundry-co",
            "item": "Towels",
            "quantity": 3,
            "amount_cents": 60000,
            "queued_at": 1.0,
            "expires_at": 2.0,
            "grant": {"client_id": "laundry-co", "weekly_limit_cents": None, "used_cents": 0, "remaining_cents": None, "window_seconds": 604800},
        }
    ]
    monkeypatch.setattr(
        tier3_client, "list_pending", lambda: tier3_client.ApprovalsResult(ok=True, entries=entries)
    )
    resp = client.get("/approvals", auth=AUTH)
    assert "mandate revoked" in resp.text


def test_approve_success_rerenders_with_outcome(client, monkeypatch):
    monkeypatch.setattr(
        tier3_client,
        "approve_action",
        lambda action_id: tier3_client.ApprovalActionResult(
            ok=True, outcome={"orderNumber": "ERP-9", "channel": "mock_erp"}
        ),
    )
    monkeypatch.setattr(
        tier3_client, "list_pending", lambda: tier3_client.ApprovalsResult(ok=True, entries=[])
    )
    resp = client.post("/approvals/act-1-ab/approve", auth=AUTH)
    assert resp.status_code == 200
    assert "ERP-9" in resp.text


def test_approve_failure_surfaces_error(client, monkeypatch):
    monkeypatch.setattr(
        tier3_client,
        "approve_action",
        lambda action_id: tier3_client.ApprovalActionResult(ok=False, error="that action is no longer pending"),
    )
    monkeypatch.setattr(
        tier3_client, "list_pending", lambda: tier3_client.ApprovalsResult(ok=True, entries=[])
    )
    resp = client.post("/approvals/act-1-ab/approve", auth=AUTH)
    assert resp.status_code == 502
    assert "no longer pending" in resp.text


def test_reject_success_rerenders(client, monkeypatch):
    monkeypatch.setattr(
        tier3_client,
        "reject_action",
        lambda action_id: tier3_client.ApprovalActionResult(ok=True, outcome={"status": "rejected"}),
    )
    monkeypatch.setattr(
        tier3_client, "list_pending", lambda: tier3_client.ApprovalsResult(ok=True, entries=[])
    )
    resp = client.post("/approvals/act-1-ab/reject", auth=AUTH)
    assert resp.status_code == 200
    assert "Rejected" in resp.text


def test_approvals_page_degrades_when_verify_unreachable(client, monkeypatch):
    monkeypatch.setattr(
        tier3_client,
        "list_pending",
        lambda: tier3_client.ApprovalsResult(ok=False, entries=[], error="could not reach verify"),
    )
    resp = client.get("/approvals", auth=AUTH)
    assert resp.status_code == 502
    assert "could not reach verify" in resp.text


def test_internal_agent_page_renders_status(client, monkeypatch):
    monkeypatch.setattr(
        agent_client,
        "get_status",
        lambda: agent_client.AgentStatusResult(
            ok=True,
            rules={
                "path": "/app/rules.json",
                "allowed_channels": ["mock_erp", "slack_stub"],
                "rules": [{"action_type": "order.place", "max_amount_cents": 20000, "channel": "mock_erp"}],
            },
            llm={"configured": False, "model": None, "base_url": "http://litellm:4000"},
            decisions=[
                {
                    "at": 1.0,
                    "action_id": "act-1-ab",
                    "client_id": "laundry-co",
                    "item": "Towels",
                    "amount_cents": 500,
                    "mode": "within_mandate",
                    "decided_by": "rules",
                    "channel": "mock_erp",
                    "executed": True,
                    "llm_prompt": None,
                    "llm_raw": None,
                }
            ],
        ),
    )
    resp = client.get("/internal-agent", auth=AUTH)
    assert resp.status_code == 200
    assert "not configured" in resp.text
    assert "act-1-ab" in resp.text
    assert "mock_erp" in resp.text


def test_internal_agent_page_escapes_llm_raw_output(client, monkeypatch):
    """The decision log's llm_raw is caller-influenced text -- the page must
    render it escaped (Jinja2 autoescaping), never as markup."""
    monkeypatch.setattr(
        agent_client,
        "get_status",
        lambda: agent_client.AgentStatusResult(
            ok=True,
            rules={"path": "/app/rules.json", "allowed_channels": ["mock_erp"], "rules": []},
            llm={"configured": True, "model": "internal-agent-default", "base_url": "http://litellm:4000"},
            decisions=[
                {
                    "at": 1.0,
                    "action_id": "act-1-ab",
                    "client_id": "laundry-co",
                    "item": "<script>alert(1)</script>",
                    "amount_cents": 500,
                    "mode": "within_mandate",
                    "decided_by": None,
                    "channel": None,
                    "executed": False,
                    "llm_prompt": "p",
                    "llm_raw": '<img src=x onerror=alert(2)>',
                }
            ],
        ),
    )
    resp = client.get("/internal-agent", auth=AUTH)
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "<img src=x onerror=alert(2)>" not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_internal_agent_page_degrades_when_agent_unreachable(client, monkeypatch):
    monkeypatch.setattr(
        agent_client,
        "get_status",
        lambda: agent_client.AgentStatusResult(ok=False, error="could not reach the internal agent"),
    )
    resp = client.get("/internal-agent", auth=AUTH)
    assert resp.status_code == 502
    assert "could not reach the internal agent" in resp.text
