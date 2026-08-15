"""OpenBao KV v2 wrapper for storing Tier 2 partner client secrets as a
durable mirror of what Keycloak already holds as the source of truth (see
keycloak_client.py). OpenBao is never authoritative: a write failure here
never blocks or rolls back a Keycloak client create/reveal/delete, and the
secret is always independently re-fetchable from Keycloak regardless of
OpenBao's state -- see the callers in main.py for how failures surface
(a visible, non-blocking warning, never an error page).

Same never-raise contract as keycloak_client._admin_request: every public
function returns a result dataclass, Request(...) construction stays inside
the try block (see that module's docstring for the exact bug shape this
avoids -- it has already bitten this codebase twice).

Unlike keycloak_client.py, this module does NOT fail closed at import when
unconfigured: local dev's admin service doesn't set OPENBAO_ADDR/TOKEN at
all (OpenBao writes are a new capability dev doesn't need to exercise by
default, unlike Keycloak client creation which dev already exercises), and
must keep working with zero new mandatory .env values. configured() is
False in that case and every public function below returns a `skipped`
result without attempting any network call.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

OPENBAO_ADDR = os.environ.get("OPENBAO_ADDR", "")
OPENBAO_TOKEN = os.environ.get("OPENBAO_TOKEN", "")

# KV v2 mount path -- must match openbao/SETUP.md's `bao secrets enable
# -path=secret kv-v2` step.
_KV_MOUNT = "secret"


def configured() -> bool:
    return bool(OPENBAO_ADDR and OPENBAO_TOKEN)


@dataclass
class WriteResult:
    ok: bool
    skipped: bool = False  # True when configured() is False -- not an error, just "not wired up here"
    error: str | None = None


@dataclass
class ReadResult:
    ok: bool
    secret: str | None = None
    not_found: bool = False
    skipped: bool = False
    error: str | None = None


def _data_url(client_id: str) -> str:
    return f"{OPENBAO_ADDR}/v1/{_KV_MOUNT}/data/tier2-clients/{client_id}"


def _metadata_url(client_id: str) -> str:
    return f"{OPENBAO_ADDR}/v1/{_KV_MOUNT}/metadata/tier2-clients/{client_id}"


def _bao_request(method: str, url: str, body: dict | None = None) -> tuple[int, bytes]:
    """Same (status, raw_bytes) contract as keycloak_client._admin_request,
    minus headers (no caller here needs them). status=0 on any failure that
    never got an HTTP response at all.
    """
    try:
        headers = {"X-Vault-Token": OPENBAO_TOKEN}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        req = urllib.request.Request(url, method=method, headers=headers, data=data)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        return 0, str(exc.reason).encode()
    except Exception as exc:
        return 0, str(exc).encode()


def write_client_secret(client_id: str, secret: str, keycloak_uuid: str) -> WriteResult:
    if not configured():
        return WriteResult(ok=True, skipped=True)
    if not secret:
        # OpenBao's KV v2 API happily accepts and 200s a null client_secret
        # -- confirmed live during adversarial review -- so without this
        # guard a caller passing None (e.g. create_client()'s documented
        # fallback when Keycloak's secret-fetch GET itself fails) gets back
        # ok=True, and main.py's warning logic (ok or skipped -> no
        # warning) never fires for what's actually a real, silent failure.
        return WriteResult(ok=False, error="refusing to write an empty/missing secret to OpenBao")
    body = {"data": {"client_secret": secret, "keycloak_uuid": keycloak_uuid}}
    status, _body = _bao_request("POST", _data_url(client_id), body)
    if status not in (200, 204):
        return WriteResult(ok=False, error=f"OpenBao returned HTTP {status} writing the secret")
    return WriteResult(ok=True)


def read_client_secret(client_id: str) -> ReadResult:
    if not configured():
        return ReadResult(ok=True, skipped=True)
    status, body = _bao_request("GET", _data_url(client_id))
    if status == 404:
        return ReadResult(ok=True, not_found=True)
    if status != 200:
        return ReadResult(ok=False, error=f"OpenBao returned HTTP {status} reading the secret")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return ReadResult(ok=False, error="OpenBao returned an unparseable secret")
    # KV v2 envelope: {"data": {"data": {...}, "metadata": {...}}}
    inner = (parsed.get("data") or {}).get("data") or {}
    secret = inner.get("client_secret")
    if secret is None:
        return ReadResult(ok=False, error="OpenBao's response had no client_secret field")
    return ReadResult(ok=True, secret=secret)


def delete_client_secret(client_id: str) -> WriteResult:
    if not configured():
        return WriteResult(ok=True, skipped=True)
    # Full delete (metadata endpoint), not KV v2's soft-delete data endpoint
    # -- a removed Keycloak client's secret has no reason to linger even as
    # a recoverable version history.
    status, _body = _bao_request("DELETE", _metadata_url(client_id))
    if status not in (200, 204, 404):
        return WriteResult(ok=False, error=f"OpenBao returned HTTP {status} deleting the secret")
    return WriteResult(ok=True)
