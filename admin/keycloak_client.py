"""Keycloak Admin REST API wrapper for Tier 2 partner OAuth client lifecycle
(list/create/view-secret/regenerate-secret/delete). Replaces the previous
"hand-edit keycloak/realm-export.json + docker compose up" workflow, whose
biggest footgun this module exists to close: a client created without the
`tier2-audience` protocol mapper (aud=TIER2_AUDIENCE) fails Tier 2 auth
silently -- verify/keycloak_auth.py collapses that into the same generic
"invalid token" as every other failure. create_client() below always
attaches that mapper, so the failure mode structurally can't happen for
anything created here.

Same never-raise contract as test_console.py's _get(): every public function
returns a result dataclass, never propagates an exception. No caching of the
Keycloak admin bearer token -- this sits behind a human clicking buttons, not
a hot path, so a fresh token per call (one extra ~50ms POST) is simpler than
tracking expiry/mid-use-401 retry/concurrency safety for a credential that's
more sensitive than a cached public key would be.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_BASE_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "agent-embassy")
TIER2_AUDIENCE = os.environ.get("TIER2_AUDIENCE", "agent-embassy-tier2")

KEYCLOAK_ADMIN_USERNAME = os.environ.get("KEYCLOAK_ADMIN_USERNAME", "")
KEYCLOAK_ADMIN_PASSWORD = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")

# Fail closed at import, same reasoning as auth.py's ADMIN_UI_USERNAME/
# PASSWORD check: an unset credential defaulting to "" would just mean every
# admin-token request fails with a confusing 401 from Keycloak instead of a
# clear startup error naming the actual problem.
if not KEYCLOAK_ADMIN_USERNAME or not KEYCLOAK_ADMIN_PASSWORD:
    raise RuntimeError("KEYCLOAK_ADMIN_USERNAME and KEYCLOAK_ADMIN_PASSWORD must both be set (see .env.example)")

# Keycloak's own built-in clients, present in every realm regardless of what
# this project adds -- plus agent-embassy-tier2, this project's OWN client
# (keycloak/realm-export.json), whose sole purpose is verify/introspection.py
# authenticating to Keycloak's token-introspection endpoint for the Tier 3
# demo. Defense-in-depth on top of the shape check in _is_partner_client()
# below -- belt and suspenders, not the primary mechanism (that check alone
# already rejects it: serviceAccountsEnabled is False for this client,
# unlike every partner client create_client() produces).
_BUILTIN_CLIENT_IDS = {
    "account",
    "account-console",
    "admin-cli",
    "broker",
    "realm-management",
    "security-admin-console",
    "agent-embassy-tier2",
}

_ADMIN_REALM_TOKEN_URL = f"{KEYCLOAK_BASE_URL}/realms/master/protocol/openid-connect/token"
_CLIENTS_URL = f"{KEYCLOAK_BASE_URL}/admin/realms/{KEYCLOAK_REALM}/clients"


@dataclass
class ClientInfo:
    uuid: str  # Keycloak's internal client id (used in API paths)
    client_id: str  # the OAuth client_id string a partner authenticates with
    name: str
    enabled: bool
    has_audience_mapper: bool  # True iff an oidc-audience-mapper minting TIER2_AUDIENCE is present


@dataclass
class ListResult:
    ok: bool
    clients: list[ClientInfo]
    error: str | None = None


@dataclass
class DetailResult:
    ok: bool
    client: ClientInfo | None = None
    not_found: bool = False
    error: str | None = None


@dataclass
class CreateResult:
    ok: bool
    client: ClientInfo | None = None
    secret: str | None = None
    error: str | None = None


@dataclass
class SecretResult:
    ok: bool
    secret: str | None = None
    not_found: bool = False
    error: str | None = None


@dataclass
class DeleteResult:
    ok: bool
    not_found: bool = False
    error: str | None = None
    # Populated from this function's own internal get_client() call below --
    # main.py's OpenBao cleanup needs it (OpenBao's key is client_id, not
    # Keycloak's uuid) but has no reason to make its own separate fetch for
    # something this function already has; a second, redundant fetch was
    # also a silent-failure gap (2026-08-11 adversarial review): if that
    # separate pre-fetch errored for a reason other than not-found while
    # delete_client() itself still succeeded, main.py had no client_id left
    # to clean up OpenBao with, and nothing surfaced a warning for it, unlike
    # every other OpenBao failure path in this codebase.
    client_id: str | None = None


@dataclass
class EnabledResult:
    ok: bool
    enabled: bool | None = None
    not_found: bool = False
    error: str | None = None


def _admin_request(method: str, url: str, token: str | None = None, body: dict | None = None) -> tuple[int, dict, bytes]:
    """Same (status, headers, raw_bytes) contract as test_console._get:
    status=0 on any failure that never got an HTTP response at all. Catches
    HTTPError/URLError/bare Exception -- the last catches, among other
    things, ValueError, which urllib.request.Request's own constructor
    raises (via its full_url setter) for some malformed `url` values (e.g.
    "not a url at all" -> "unknown url type", or a stray "[" -> "Invalid
    IPv6 URL") -- confirmed live. Request(...) construction is therefore
    kept INSIDE this try block, not before it (a bare-500 bug this exact
    shape already burned test_console.py's _get once, via a different
    exception type raised from a different call): building the request
    outside the try would let that ValueError propagate uncaught.
    """
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, method=method, headers=headers, data=data)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()
    except urllib.error.URLError as exc:
        return 0, {}, str(exc.reason).encode()
    except Exception as exc:
        return 0, {}, str(exc).encode()


def _admin_token() -> tuple[str | None, str]:
    """Returns (token, error) -- exactly one is non-None/non-empty. `error`
    is always a fixed short message plus HTTP status, never Keycloak's raw
    response body or anything containing KEYCLOAK_ADMIN_PASSWORD -- that
    password must never reach an HTML error page or a log line.
    """
    try:
        form = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": KEYCLOAK_ADMIN_USERNAME,
                "password": KEYCLOAK_ADMIN_PASSWORD,
            }
        ).encode()
        req = urllib.request.Request(
            _ADMIN_REALM_TOKEN_URL,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=form,
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read())
            return body["access_token"], ""
    except urllib.error.HTTPError as exc:
        return None, f"could not authenticate to Keycloak admin API (HTTP {exc.code})"
    except urllib.error.URLError:
        return None, "could not reach Keycloak"
    except Exception:
        return None, "could not authenticate to Keycloak admin API"


def _has_audience_mapper(rep: dict) -> bool:
    for mapper in rep.get("protocolMappers") or []:
        if mapper.get("protocolMapper") != "oidc-audience-mapper":
            continue
        config = mapper.get("config") or {}
        if config.get("included.custom.audience") == TIER2_AUDIENCE and config.get("access.token.claim") == "true":
            return True
    return False


def _is_partner_client(rep: dict) -> bool:
    """A client counts as a Tier 2 partner client for this UI's purposes if
    it has exactly the shape example-partner (keycloak/realm-export.json)
    and everything create_client() below produces: confidential,
    client-credentials-only, no interactive flows. This is a SHAPE check,
    not a tag -- deliberately, since tagging would require also updating the
    static example-partner entry and adds a second mechanism for no real
    benefit. _BUILTIN_CLIENT_IDS is defense-in-depth on top of this, not the
    primary mechanism: confirmed live against a real Keycloak 26.7.1 realm
    that no built-in client happens to match this shape, but the explicit
    denylist means a future Keycloak version doing so wouldn't silently
    change what this UI considers manageable.

    Callers that operate on a single client by UUID (get_client, get_secret,
    regenerate_secret, delete_client) MUST re-check this on the fetched
    representation, not just rely on the list view's filter -- otherwise an
    admin who obtains a built-in client's UUID some other way (e.g.
    Keycloak's own admin console) could delete/regenerate it purely because
    the per-UUID routes never re-validated what the list view already
    filtered out.
    """
    if rep.get("clientId") in _BUILTIN_CLIENT_IDS:
        return False
    return (
        rep.get("publicClient") is False
        and rep.get("serviceAccountsEnabled") is True
        and rep.get("standardFlowEnabled") is False
        and rep.get("implicitFlowEnabled") is False
        and rep.get("directAccessGrantsEnabled") is False
    )


def _to_client_info(rep: dict) -> ClientInfo:
    return ClientInfo(
        uuid=rep["id"],
        client_id=rep["clientId"],
        name=rep.get("name") or rep["clientId"],
        enabled=bool(rep.get("enabled")),
        has_audience_mapper=_has_audience_mapper(rep),
    )


def list_clients() -> ListResult:
    token, err = _admin_token()
    if token is None:
        return ListResult(ok=False, clients=[], error=err)
    status, _headers, body = _admin_request("GET", _CLIENTS_URL, token)
    if status != 200:
        return ListResult(ok=False, clients=[], error=f"Keycloak returned HTTP {status} listing clients")
    try:
        reps = json.loads(body)
    except json.JSONDecodeError:
        return ListResult(ok=False, clients=[], error="Keycloak returned an unparseable client list")
    clients = [_to_client_info(rep) for rep in reps if _is_partner_client(rep)]
    return ListResult(ok=True, clients=clients)


def create_client(client_id: str, name: str) -> CreateResult:
    token, err = _admin_token()
    if token is None:
        return CreateResult(ok=False, error=err)

    # Byte-for-byte the shape of example-partner in keycloak/realm-export.json,
    # parametrized by TIER2_AUDIENCE. The protocolMappers entry is the whole
    # point of this function existing -- see module docstring.
    body = {
        "clientId": client_id,
        "name": name or client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": True,
        "clientAuthenticatorType": "client-secret",
        "protocolMappers": [
            {
                "name": "tier2-audience",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.custom.audience": TIER2_AUDIENCE,
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                },
            }
        ],
    }
    status, headers, resp_body = _admin_request("POST", _CLIENTS_URL, token, body)
    if status == 409:
        return CreateResult(ok=False, error=f"a client named {client_id!r} already exists")
    if status != 201:
        return CreateResult(ok=False, error=f"Keycloak returned HTTP {status} creating the client")

    location = headers.get("Location") or headers.get("location") or ""
    uuid = location.rstrip("/").rsplit("/", 1)[-1]
    if not uuid:
        return CreateResult(ok=False, error="client was created but Keycloak did not return its id")

    # get_client()/get_secret() each re-authenticate and re-fetch as a
    # defense-in-depth measure for standalone calls (see _is_partner_client's
    # docstring) -- here we just created this exact client ourselves in the
    # same call, so a single re-fetch (for the ClientInfo shape) plus one
    # direct secret fetch on the token already in hand is enough; no need to
    # pay for get_secret()'s own redundant re-verification round trip.
    detail_result = get_client(uuid)
    if not detail_result.ok or detail_result.client is None:
        return CreateResult(ok=False, error="client was created but could not be re-fetched")
    secret_status, _secret_headers, secret_body = _admin_request("GET", f"{_CLIENTS_URL}/{uuid}/client-secret", token)
    secret = None
    if secret_status == 200:
        try:
            secret = json.loads(secret_body).get("value")
        except json.JSONDecodeError:
            secret = None
    return CreateResult(ok=True, client=detail_result.client, secret=secret)


def get_client(uuid: str) -> DetailResult:
    token, err = _admin_token()
    if token is None:
        return DetailResult(ok=False, error=err)
    status, _headers, body = _admin_request("GET", f"{_CLIENTS_URL}/{uuid}", token)
    if status == 404:
        return DetailResult(ok=True, not_found=True)
    if status != 200:
        return DetailResult(ok=False, error=f"Keycloak returned HTTP {status} fetching the client")
    try:
        rep = json.loads(body)
    except json.JSONDecodeError:
        return DetailResult(ok=False, error="Keycloak returned an unparseable client")
    if not _is_partner_client(rep):
        return DetailResult(ok=True, not_found=True)
    return DetailResult(ok=True, client=_to_client_info(rep))


def get_secret(uuid: str) -> SecretResult:
    detail = get_client(uuid)
    if detail.not_found:
        return SecretResult(ok=True, not_found=True)
    if not detail.ok:
        return SecretResult(ok=False, error=detail.error)

    token, err = _admin_token()
    if token is None:
        return SecretResult(ok=False, error=err)
    status, _headers, body = _admin_request("GET", f"{_CLIENTS_URL}/{uuid}/client-secret", token)
    if status != 200:
        return SecretResult(ok=False, error=f"Keycloak returned HTTP {status} fetching the secret")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return SecretResult(ok=False, error="Keycloak returned an unparseable secret")
    return SecretResult(ok=True, secret=parsed.get("value"))


def regenerate_secret(uuid: str) -> SecretResult:
    detail = get_client(uuid)
    if detail.not_found:
        return SecretResult(ok=True, not_found=True)
    if not detail.ok:
        return SecretResult(ok=False, error=detail.error)

    token, err = _admin_token()
    if token is None:
        return SecretResult(ok=False, error=err)
    status, _headers, body = _admin_request("POST", f"{_CLIENTS_URL}/{uuid}/client-secret", token)
    if status != 200:
        return SecretResult(ok=False, error=f"Keycloak returned HTTP {status} regenerating the secret")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return SecretResult(ok=False, error="Keycloak returned an unparseable secret")
    return SecretResult(ok=True, secret=parsed.get("value"))


def delete_client(uuid: str) -> DeleteResult:
    detail = get_client(uuid)
    if detail.not_found:
        return DeleteResult(ok=True, not_found=True)
    if not detail.ok:
        return DeleteResult(ok=False, error=detail.error)

    token, err = _admin_token()
    if token is None:
        return DeleteResult(ok=False, error=err)
    status, _headers, _body = _admin_request("DELETE", f"{_CLIENTS_URL}/{uuid}", token)
    if status not in (204, 404):
        return DeleteResult(ok=False, error=f"Keycloak returned HTTP {status} deleting the client")
    return DeleteResult(ok=True, client_id=detail.client.client_id)


def set_client_enabled(uuid: str, enabled: bool) -> EnabledResult:
    """Added for the Tier 3 demo: this is the actual revocation lever --
    disabling a client here makes verify/introspection.py's next check for
    it return active=false immediately (confirmed against Keycloak's own
    source, tag 26.7.1: ClientModel.isEnabled() is checked in
    verifyClient() before any session/audience logic). regenerate_secret()
    above is NOT a revocation control despite looking like one: Keycloak's
    introspection endpoint never re-checks a token against the client's
    current secret, only its signature/expiry/audience/enabled state -- an
    already-issued token keeps working after a secret regeneration.

    Sends a sparse body, {"enabled": enabled} only -- confirmed against
    Keycloak's RepresentationToModel source (same tag): updateClientProperties
    falls back to the current model value for every field omitted from the
    representation, and its secret-preservation logic explicitly keeps the
    existing secret when none is sent. So this touches enabled and nothing
    else -- not the secret, not protocol mappers, not any other field.
    """
    detail = get_client(uuid)
    if detail.not_found:
        return EnabledResult(ok=True, not_found=True)
    if not detail.ok:
        return EnabledResult(ok=False, error=detail.error)

    token, err = _admin_token()
    if token is None:
        return EnabledResult(ok=False, error=err)
    status, _headers, _body = _admin_request("PUT", f"{_CLIENTS_URL}/{uuid}", token, {"enabled": enabled})
    if status != 204:
        return EnabledResult(ok=False, error=f"Keycloak returned HTTP {status} updating the client")
    return EnabledResult(ok=True, enabled=enabled)
