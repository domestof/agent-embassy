"""Admin UI: Tier 0 catalog CRUD, a live "preview as an agent" console,
catalog request activity, Tier 2 partner OAuth client management (via
Keycloak's real Admin REST API), Tier 1 config (TTL/rate-limit)
hot-reloading via verify's /tier1/admin-config endpoint (tier1_client.py),
and a Tier 3 feasibility demo (weekly spending grants + immediate
revoke/disable + an audit trail, via verify's /tier3/* endpoints,
tier3_client.py). A Tier 1 change or Tier 3 grant is NOT persisted -- both
live only in the running verify process's memory and revert to their
defaults on a restart; templates/tier1_config.html and the Tier 3 section of
keycloak_client_detail.html both say so directly. Tier 2's
certs/contact.json/order-status.json remain out of scope -- editing those
has no analogous hot-reload path and would either do nothing until a
restart or be actively misleading. The manifest editor below only ever
touches the Tier 0 slice of the manifest, never the Tier 1/2 entries sitting
in the same file. Server-rendered Jinja2, no SPA: this repo has no frontend
tooling anywhere else, and CRUD forms + a preview panel + a log table don't
need one.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Path, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import agent_client
import catalog_store
import keycloak_client
import log_tail
import openbao_client
import schema_types
import test_console
import tier1_client
import tier3_client
from auth import verify_admin

# docs_url/redoc_url/openapi_url=None: FastAPI mounts /docs, /redoc, and
# /openapi.json itself, outside the @app.get/@app.post routes below --
# Depends(verify_admin) on every one of *those* doesn't touch FastAPI's own
# auto-registered routes. Confirmed live during adversarial review: all
# three were reachable with zero credentials, handing out the full route
# map (every path, form field name like field__name/extra_name/
# entity__name, and response shape) to anyone who can reach port 8090 --
# the exact "only /health should be open" invariant this module otherwise
# holds. No pilot admin needs interactive API docs for a server-rendered
# HTML tool, so disabling is strictly a subtraction, not a missing feature.
app = FastAPI(title="agent-embassy-admin", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

KIND_LABELS = {
    "products": "Products",
    "services": "Services",
    "jobs": "Open positions",
    "demand": "Supplier needs",
}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def dashboard(request: Request, _admin: str = Depends(verify_admin)):
    return templates.TemplateResponse(request, "dashboard.html", {"kinds": KIND_LABELS})


def _require_kind(kind: str) -> str:
    if kind not in schema_types.KINDS:
        raise HTTPException(status_code=404, detail=f"unknown catalog kind {kind!r}")
    return schema_types.KINDS[kind]


@app.get("/catalog/{kind}")
def catalog_list(kind: str, request: Request, _admin: str = Depends(verify_admin)):
    _require_kind(kind)
    items = catalog_store.list_items(kind)
    return templates.TemplateResponse(
        request,
        "catalog_list.html",
        {"kind": kind, "label": KIND_LABELS[kind], "items": list(enumerate(items))},
    )


@app.get("/catalog/{kind}/new")
def catalog_new_form(kind: str, request: Request, _admin: str = Depends(verify_admin)):
    item_type = _require_kind(kind)
    return templates.TemplateResponse(
        request,
        "catalog_item_form.html",
        {
            "kind": kind,
            "label": KIND_LABELS[kind],
            "fields": schema_types.CORE_FIELDS[item_type],
            "item": {},
            "extra": [],
            "index": None,
            "error": None,
        },
    )


@app.post("/catalog/{kind}/new")
async def catalog_create(kind: str, request: Request, _admin: str = Depends(verify_admin)):
    item_type = _require_kind(kind)
    form = await request.form()
    item = schema_types.item_from_form(item_type, form)
    try:
        schema_types.validate_item(item)
    except schema_types.InvalidItem as exc:
        return templates.TemplateResponse(
            request,
            "catalog_item_form.html",
            {
                "kind": kind,
                "label": KIND_LABELS[kind],
                "fields": schema_types.CORE_FIELDS[item_type],
                "item": item,
                "extra": item.get("additionalProperty", []),
                "index": None,
                "error": str(exc),
            },
            status_code=400,
        )
    catalog_store.add_item(kind, item)
    return RedirectResponse(f"/catalog/{kind}", status_code=303)


@app.get("/catalog/{kind}/{index}/edit")
def catalog_edit_form(
    # ge=0: without this, FastAPI happily parses a negative path segment as
    # a valid int, and catalog_store's get_item/update_item/delete_item just
    # do plain Python list indexing -- `-1` silently means "the last item",
    # not "not found". Confirmed live during adversarial review:
    # GET /catalog/products/-1/edit rendered the last item's edit form
    # instead of 404ing. Same fix applied to catalog_update/catalog_delete
    # below.
    kind: str, request: Request, index: int = Path(ge=0), _admin: str = Depends(verify_admin)
):
    item_type = _require_kind(kind)
    try:
        item = catalog_store.get_item(kind, index)
    except IndexError:
        raise HTTPException(status_code=404, detail="no such item")
    return templates.TemplateResponse(
        request,
        "catalog_item_form.html",
        {
            "kind": kind,
            "label": KIND_LABELS[kind],
            "fields": schema_types.CORE_FIELDS[item_type],
            "item": item,
            "extra": item.get("additionalProperty", []),
            "index": index,
            "error": None,
        },
    )


@app.post("/catalog/{kind}/{index}/edit")
async def catalog_update(
    kind: str, request: Request, index: int = Path(ge=0), _admin: str = Depends(verify_admin)
):
    item_type = _require_kind(kind)
    try:
        existing = catalog_store.get_item(kind, index)
    except IndexError:
        raise HTTPException(status_code=404, detail="no such item")

    form = await request.form()
    item = schema_types.item_from_form(item_type, form, existing=existing)
    try:
        schema_types.validate_item(item)
    except schema_types.InvalidItem as exc:
        return templates.TemplateResponse(
            request,
            "catalog_item_form.html",
            {
                "kind": kind,
                "label": KIND_LABELS[kind],
                "fields": schema_types.CORE_FIELDS[item_type],
                "item": item,
                "extra": item.get("additionalProperty", []),
                "index": index,
                "error": str(exc),
            },
            status_code=400,
        )

    try:
        catalog_store.update_item(kind, index, item)
    except IndexError:
        raise HTTPException(status_code=404, detail="no such item")
    return RedirectResponse(f"/catalog/{kind}", status_code=303)


@app.post("/catalog/{kind}/{index}/delete")
def catalog_delete(kind: str, index: int = Path(ge=0), _admin: str = Depends(verify_admin)):
    _require_kind(kind)
    try:
        catalog_store.delete_item(kind, index)
    except IndexError:
        raise HTTPException(status_code=404, detail="no such item")
    return RedirectResponse(f"/catalog/{kind}", status_code=303)


def _tier0_entry(doc: dict) -> dict:
    for tier in doc.get("access_tiers", []):
        if tier.get("tier") == 0:
            return tier
    # Absence means a corrupted/hand-edited manifest, not something to
    # silently paper over by fabricating an entry.
    raise HTTPException(status_code=500, detail="manifest has no tier 0 entry")


@app.get("/manifest")
def manifest_edit_form(request: Request, _admin: str = Depends(verify_admin)):
    doc = catalog_store.load_manifest()
    return templates.TemplateResponse(request, "manifest_edit.html", {"doc": doc, "tier0": _tier0_entry(doc), "error": None})


@app.post("/manifest")
async def manifest_update(request: Request, _admin: str = Depends(verify_admin)):
    form = await request.form()

    def mutate(doc: dict) -> None:
        # Touches ONLY entity/{tier0.rate_limit,tier0.extra}/security/
        # last_updated — every other key (access_tiers[1]/[2], public_catalog,
        # ...) is left exactly as loaded. This is the round-trip-safety
        # invariant the admin-UI plan requires and admin/tests/test_main.py
        # asserts directly.
        entity = doc.setdefault("entity", {})
        for key in ("name", "tax_id", "website", "country"):
            entity[key] = form.get(f"entity__{key}", "").strip()

        tier0 = _tier0_entry(doc)
        tier0["rate_limit"] = form.get("rate_limit", "").strip()
        names = form.getlist("extra_name")
        values = form.getlist("extra_value")
        extra = {name.strip(): value.strip() for name, value in zip(names, values) if name.strip()}
        if extra:
            tier0["extra"] = extra
        else:
            tier0.pop("extra", None)

        security = doc.setdefault("security", {})
        for key in ("gateway_required", "direct_llm_exposure", "audit_logging"):
            security[key] = form.get(f"security__{key}") == "on"

        doc["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    catalog_store.update_manifest(mutate)
    return RedirectResponse("/manifest", status_code=303)


@app.get("/tier1-config")
def tier1_config_form(request: Request, _admin: str = Depends(verify_admin)):
    result = tier1_client.get_config()
    return templates.TemplateResponse(
        request,
        "tier1_config.html",
        {"values": result.values or {}, "error": result.error},
        status_code=200 if result.ok else 502,
    )


@app.post("/tier1-config")
async def tier1_config_update(request: Request, _admin: str = Depends(verify_admin)):
    form = await request.form()
    raw_values = {field: form.get(field, "").strip() for field in tier1_client.CONFIG_FIELDS}

    parsed = {}
    bad_fields = []
    for field, raw in raw_values.items():
        try:
            parsed[field] = int(raw)
        except ValueError:
            bad_fields.append(field)
    if bad_fields:
        return templates.TemplateResponse(
            request,
            "tier1_config.html",
            {"values": raw_values, "error": f"must be whole numbers: {', '.join(bad_fields)}"},
            status_code=400,
        )

    result = tier1_client.update_config(**parsed)
    if not result.ok:
        return templates.TemplateResponse(
            request, "tier1_config.html", {"values": raw_values, "error": result.error}, status_code=400
        )
    return RedirectResponse("/tier1-config", status_code=303)


@app.get("/console")
def console(request: Request, _admin: str = Depends(verify_admin)):
    resources = test_console.discover_resources()
    return templates.TemplateResponse(request, "console.html", {"resources": resources, "result": None})


@app.post("/console/run")
async def console_run(request: Request, _admin: str = Depends(verify_admin)):
    form = await request.form()
    path = form.get("path", "").strip()
    resources = test_console.discover_resources()
    result = test_console.run_check(path) if path else None
    return templates.TemplateResponse(
        request, "console.html", {"resources": resources, "result": result, "selected": path}
    )


@app.get("/monitoring")
def monitoring(request: Request, _admin: str = Depends(verify_admin)):
    entries = log_tail.recent_catalog_requests()
    return templates.TemplateResponse(request, "monitoring.html", {"entries": entries})


_CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


@app.get("/keycloak-clients")
def keycloak_clients_list(request: Request, _admin: str = Depends(verify_admin)):
    result = keycloak_client.list_clients()
    return templates.TemplateResponse(
        request, "keycloak_clients_list.html", {"clients": result.clients, "error": result.error}
    )


@app.get("/keycloak-clients/new")
def keycloak_client_new_form(request: Request, _admin: str = Depends(verify_admin)):
    return templates.TemplateResponse(
        request, "keycloak_client_form.html", {"client_id": "", "name": "", "error": None}
    )


@app.post("/keycloak-clients/new")
async def keycloak_client_create(request: Request, _admin: str = Depends(verify_admin)):
    form = await request.form()
    client_id = form.get("client_id", "").strip()
    name = form.get("name", "").strip()
    if not _CLIENT_ID_RE.match(client_id):
        return templates.TemplateResponse(
            request,
            "keycloak_client_form.html",
            {
                "client_id": client_id,
                "name": name,
                "error": "client ID must be 1-255 characters: letters, numbers, '.', '_', '-', starting with a letter or number",
            },
            status_code=400,
        )
    result = keycloak_client.create_client(client_id, name)
    if not result.ok or result.client is None:
        return templates.TemplateResponse(
            request,
            "keycloak_client_form.html",
            {"client_id": client_id, "name": name, "error": result.error},
            status_code=400,
        )
    # OpenBao is a mirror/backup of the secret, never the source of truth --
    # a write failure here must never roll back or delete the Keycloak
    # client that was just created (that would destroy a working credential
    # over a backup-copy failure, and the partner may already have been
    # handed the secret in this same response). The secret is still shown
    # once below regardless, and always independently re-fetchable via
    # Keycloak's own reveal-secret route. A failed write just surfaces a
    # non-blocking warning with a concrete retry action.
    bao_result = openbao_client.write_client_secret(result.client.client_id, result.secret, result.client.uuid)
    warning_qs = "" if (bao_result.ok or bao_result.skipped) else "?openbao_warning=1"
    return RedirectResponse(f"/keycloak-clients/{result.client.uuid}{warning_qs}", status_code=303)


def _render_client_detail(
    request: Request, client_uuid: str, client, error, secret, status_code: int = 200, openbao_warning: bool = False
):
    # tier3_grant is fetched here, in the one place all five detail-rendering
    # routes below share, rather than threading it through every call site.
    # None when there's no client to look a grant up for; otherwise a
    # tier3_client.GrantResult (its own .ok/.error cover verify being
    # unreachable -- the template renders that state too, it isn't fatal to
    # the rest of this page).
    tier3_grant = tier3_client.get_grant(client.client_id) if client else None
    return templates.TemplateResponse(
        request,
        "keycloak_client_detail.html",
        {
            "client": client,
            "client_uuid": client_uuid,
            "error": error,
            "secret": secret,
            "tier3_grant": tier3_grant,
            "openbao_warning": openbao_warning,
        },
        status_code=status_code,
    )


@app.get("/keycloak-clients/{client_uuid}")
def keycloak_client_detail(client_uuid: str, request: Request, _admin: str = Depends(verify_admin)):
    result = keycloak_client.get_client(client_uuid)
    if result.not_found:
        raise HTTPException(status_code=404, detail="no such client")
    openbao_warning = request.query_params.get("openbao_warning") == "1"
    return _render_client_detail(
        request, client_uuid, result.client, result.error, None, 200 if result.ok else 502, openbao_warning=openbao_warning
    )


@app.post("/keycloak-clients/{client_uuid}/reveal-secret")
def keycloak_client_reveal_secret(client_uuid: str, request: Request, _admin: str = Depends(verify_admin)):
    detail = keycloak_client.get_client(client_uuid)
    if detail.not_found:
        raise HTTPException(status_code=404, detail="no such client")
    if not detail.ok:
        return _render_client_detail(request, client_uuid, None, detail.error, None, 502)
    secret_result = keycloak_client.get_secret(client_uuid)
    if secret_result.not_found:
        raise HTTPException(status_code=404, detail="no such client")
    # Write-through refresh to OpenBao -- this doubles as the retry path for
    # a create-time write that failed (see keycloak_client_create above), no
    # separate retry endpoint needed.
    openbao_warning = False
    if secret_result.ok and secret_result.secret:
        bao_result = openbao_client.write_client_secret(detail.client.client_id, secret_result.secret, client_uuid)
        openbao_warning = not (bao_result.ok or bao_result.skipped)
    return _render_client_detail(
        request,
        client_uuid,
        detail.client,
        secret_result.error,
        secret_result.secret,
        200 if secret_result.ok else 502,
        openbao_warning=openbao_warning,
    )


@app.post("/keycloak-clients/{client_uuid}/regenerate-secret")
def keycloak_client_regenerate_secret(client_uuid: str, request: Request, _admin: str = Depends(verify_admin)):
    detail = keycloak_client.get_client(client_uuid)
    if detail.not_found:
        raise HTTPException(status_code=404, detail="no such client")
    if not detail.ok:
        return _render_client_detail(request, client_uuid, None, detail.error, None, 502)
    secret_result = keycloak_client.regenerate_secret(client_uuid)
    if secret_result.not_found:
        raise HTTPException(status_code=404, detail="no such client")
    # Without this, OpenBao would keep mirroring the now-invalidated old
    # secret after a regeneration -- worse than not having a mirror at all,
    # since a reader of OpenBao would get a credential Keycloak already
    # rejects. Same write-through as reveal-secret above.
    openbao_warning = False
    if secret_result.ok and secret_result.secret:
        bao_result = openbao_client.write_client_secret(detail.client.client_id, secret_result.secret, client_uuid)
        openbao_warning = not (bao_result.ok or bao_result.skipped)
    return _render_client_detail(
        request,
        client_uuid,
        detail.client,
        secret_result.error,
        secret_result.secret,
        200 if secret_result.ok else 502,
        openbao_warning=openbao_warning,
    )


@app.post("/keycloak-clients/{client_uuid}/delete")
def keycloak_client_delete(client_uuid: str, request: Request, _admin: str = Depends(verify_admin)):
    result = keycloak_client.delete_client(client_uuid)
    if result.not_found:
        raise HTTPException(status_code=404, detail="no such client")
    if not result.ok:
        return _render_client_detail(request, client_uuid, None, result.error, None, 502)
    # result.client_id comes from delete_client's own internal fetch -- no
    # separate pre-fetch needed (a prior version made one, which was both a
    # redundant Keycloak Admin API round-trip and a silent-failure gap: if
    # that pre-fetch errored for a reason other than not-found while the
    # delete itself still succeeded, client_id was lost and OpenBao cleanup
    # below was skipped with zero warning, unlike every other OpenBao
    # failure path in this codebase -- found by adversarial review,
    # 2026-08-11). Best-effort, failure still not surfaced here: the
    # Keycloak client is already gone, which is the security-relevant fact;
    # a stale OpenBao entry left behind is a cleanup nicety, not something
    # worth blocking or warning about on an otherwise-successful delete.
    if result.client_id:
        openbao_client.delete_client_secret(result.client_id)
    return RedirectResponse("/keycloak-clients", status_code=303)


def _tier3_client_id(client_uuid: str, request: Request):
    """Every Tier 3 route below is keyed by verify's client_id, not
    Keycloak's uuid -- fetches the client first (the same not_found/!ok/ok
    three-way branch every other per-UUID route here uses) so an unknown or
    non-partner uuid 404s before anything touches verify."""
    detail = keycloak_client.get_client(client_uuid)
    if detail.not_found:
        raise HTTPException(status_code=404, detail="no such client")
    if not detail.ok or detail.client is None:
        return None, _render_client_detail(request, client_uuid, None, detail.error, None, 502)
    return detail.client.client_id, None


@app.post("/keycloak-clients/{client_uuid}/tier3-grant")
async def keycloak_client_tier3_grant_set(client_uuid: str, request: Request, _admin: str = Depends(verify_admin)):
    client_id, error_response = _tier3_client_id(client_uuid, request)
    if error_response is not None:
        return error_response

    form = await request.form()
    raw = form.get("weekly_limit_eur", "").strip()
    try:
        # Whole euros only, per the illustrative example (€400/week) -- no
        # cents in the form, `* 100` right before calling verify.
        weekly_limit_eur = int(raw)
    except ValueError:
        detail = keycloak_client.get_client(client_uuid)
        return _render_client_detail(
            request, client_uuid, detail.client, "weekly limit must be a whole number of euros", None, 400
        )

    result = tier3_client.set_grant(client_id, weekly_limit_eur * 100)
    if not result.ok:
        detail = keycloak_client.get_client(client_uuid)
        return _render_client_detail(request, client_uuid, detail.client, result.error, None, 400)
    return RedirectResponse(f"/keycloak-clients/{client_uuid}", status_code=303)


@app.post("/keycloak-clients/{client_uuid}/tier3-grant/revoke")
def keycloak_client_tier3_grant_revoke(client_uuid: str, request: Request, _admin: str = Depends(verify_admin)):
    client_id, error_response = _tier3_client_id(client_uuid, request)
    if error_response is not None:
        return error_response

    result = tier3_client.revoke_grant(client_id)
    if not result.ok:
        detail = keycloak_client.get_client(client_uuid)
        return _render_client_detail(request, client_uuid, detail.client, result.error, None, 400)
    return RedirectResponse(f"/keycloak-clients/{client_uuid}", status_code=303)


def _set_enabled(client_uuid: str, request: Request, enabled: bool):
    result = keycloak_client.set_client_enabled(client_uuid, enabled)
    if result.not_found:
        raise HTTPException(status_code=404, detail="no such client")
    if not result.ok:
        return _render_client_detail(request, client_uuid, None, result.error, None, 502)
    return RedirectResponse(f"/keycloak-clients/{client_uuid}", status_code=303)


@app.post("/keycloak-clients/{client_uuid}/disable")
def keycloak_client_disable(client_uuid: str, request: Request, _admin: str = Depends(verify_admin)):
    # This is the actual, demoable revocation lever for the Tier 3 demo: a
    # disabled client's already-issued, unexpired tokens are rejected by
    # verify/introspection.py on the very next Tier 3 request -- unlike
    # Tier 2, which stays valid until the token's own natural expiry (see
    # verify/keycloak_auth.py). See keycloak_client.set_client_enabled's
    # docstring for why regenerate-secret is NOT an equivalent control.
    return _set_enabled(client_uuid, request, False)


@app.post("/keycloak-clients/{client_uuid}/enable")
def keycloak_client_enable(client_uuid: str, request: Request, _admin: str = Depends(verify_admin)):
    return _set_enabled(client_uuid, request, True)


@app.get("/tier3-audit")
def tier3_audit(request: Request, _admin: str = Depends(verify_admin)):
    result = tier3_client.list_audit()
    return templates.TemplateResponse(
        request,
        "tier3_audit.html",
        {"entries": result.entries or [], "error": result.error},
        status_code=200 if result.ok else 502,
    )


def _render_approvals(request: Request, *, message: str | None = None, error: str | None = None, status_code: int = 200):
    result = tier3_client.list_pending()
    entries = result.entries or []
    # Mark identical (client, item, amount) entries: each is individually
    # approvable by design (no idempotency keys), so the badge is the
    # human's guard against two admins signing off the same real-world
    # request twice.
    counts: dict[tuple, int] = {}
    for e in entries:
        key = (e.get("client_id"), e.get("item"), e.get("amount_cents"))
        counts[key] = counts.get(key, 0) + 1
    for e in entries:
        e["duplicate"] = counts[(e.get("client_id"), e.get("item"), e.get("amount_cents"))] > 1
    return templates.TemplateResponse(
        request,
        "approvals.html",
        {"entries": entries, "message": message, "error": error or result.error},
        status_code=status_code if result.ok else 502,
    )


@app.get("/approvals")
def approvals(request: Request, _admin: str = Depends(verify_admin)):
    return _render_approvals(request)


@app.post("/approvals/{action_id}/approve")
def approvals_approve(action_id: str, request: Request, _admin: str = Depends(verify_admin)):
    result = tier3_client.approve_action(action_id)
    if result.ok:
        reference = (result.outcome or {}).get("orderNumber", "")
        channel = (result.outcome or {}).get("channel", "")
        return _render_approvals(
            request, message=f"Approved and executed via {channel} (order {reference})."
        )
    return _render_approvals(request, error=result.error, status_code=502)


@app.post("/approvals/{action_id}/reject")
def approvals_reject(action_id: str, request: Request, _admin: str = Depends(verify_admin)):
    result = tier3_client.reject_action(action_id)
    if result.ok:
        return _render_approvals(request, message="Rejected — the partner's next status poll will see it.")
    return _render_approvals(request, error=result.error, status_code=502)


@app.get("/internal-agent")
def internal_agent(request: Request, _admin: str = Depends(verify_admin)):
    result = agent_client.get_status()
    return templates.TemplateResponse(
        request,
        "internal_agent.html",
        {"rules": result.rules, "llm": result.llm, "decisions": result.decisions or [], "error": result.error},
        status_code=200 if result.ok else 502,
    )
