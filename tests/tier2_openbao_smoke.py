#!/usr/bin/env python3
"""Real end-to-end smoke test for the OpenBao mirror of Tier 2 partner
client secrets (admin/openbao_client.py).

Creates a partner OAuth client through the admin UI's real HTTP surface
(same as tests/tier2_admin_smoke.py), then independently reads the secret
back directly from OpenBao's own API — via `docker compose exec openbao
bao kv get`, OpenBao's own CLI, not a reimplementation of
openbao_client.py's HTTP call — and asserts it matches exactly what the
admin UI's own response returned. Complements tier2_admin_smoke.py's
"created client authenticates for real" proof with "the OpenBao mirror
genuinely holds what the UI showed," the same write-here-read-there
pattern tests/admin_smoke.py established for Tier 0.

Deletes the client at the end (best-effort) and confirms OpenBao's copy is
gone too, mirroring tier2_admin_smoke.py's cleanup-is-verified-not-assumed
style.

PRECONDITION, unlike every other smoke test in this directory: this only
proves anything against a stack started with the production overlay AND
after the one-time openbao/SETUP.md runbook (raft storage enabled, KV v2
mounted, a scoped token minted) — local dev's admin service never sets
OPENBAO_ADDR/OPENBAO_TOKEN at all, so OpenBao writes are silently skipped
there (by design, see openbao_client.py) and this test would find nothing
to read back. Run against a live prod-overlay stack:

    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
    # ... run openbao/SETUP.md once ...
    ADMIN_UI_PASSWORD=<value from .env> OPENBAO_TOKEN=<value from .env> \\
        python3 tests/tier2_openbao_smoke.py
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ADMIN_BASE_URL = os.environ.get("ADMIN_BASE_URL", "http://localhost:8090")
ADMIN_UI_USERNAME = os.environ.get("ADMIN_UI_USERNAME", "admin")
ADMIN_UI_PASSWORD = os.environ.get("ADMIN_UI_PASSWORD", "")
OPENBAO_TOKEN = os.environ.get("OPENBAO_TOKEN", "")

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)
    return condition


def _auth_header() -> str:
    token = base64.b64encode(f"{ADMIN_UI_USERNAME}:{ADMIN_UI_PASSWORD}".encode()).decode()
    return f"Basic {token}"


def admin_request(method: str, path: str, data: dict | None = None) -> tuple[int, str, str]:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(
        ADMIN_BASE_URL + path,
        data=body,
        method=method,
        headers={"Authorization": _auth_header(), "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.url, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.url or "", exc.read().decode()


def read_secret_via_bao_cli(client_id: str) -> dict:
    """Independent read path: OpenBao's own `bao` CLI inside the openbao
    container, not admin/openbao_client.py's HTTP code -- a regression in
    that module couldn't make this check pass for the wrong reason."""
    result = subprocess.run(
        [
            "docker", "compose", "exec", "-T",
            # BAO_ADDR is required, not just BAO_TOKEN -- the `bao` CLI
            # defaults to https://127.0.0.1:8200 regardless of what the
            # server's own listener config says, confirmed live (fails
            # with "server gave HTTP response to HTTPS client" otherwise);
            # openbao.hcl's listener has tls_disable = true (see its own
            # comment for why).
            "-e", "BAO_ADDR=http://127.0.0.1:8200",
            "-e", f"BAO_TOKEN={OPENBAO_TOKEN}",
            "openbao", "bao", "kv", "get", "-format=json", f"secret/tier2-clients/{client_id}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        return {"ok": False, "error": f"bao kv get failed: {result.stderr.strip()}"}
    try:
        parsed = json.loads(result.stdout)
        return {"ok": True, "data": parsed["data"]["data"]}
    except (json.JSONDecodeError, KeyError) as exc:
        return {"ok": False, "error": f"unparseable output: {exc}: {result.stdout!r}"}


def secret_is_gone_via_bao_cli(client_id: str) -> bool:
    result = subprocess.run(
        [
            "docker", "compose", "exec", "-T",
            # BAO_ADDR is required, not just BAO_TOKEN -- the `bao` CLI
            # defaults to https://127.0.0.1:8200 regardless of what the
            # server's own listener config says, confirmed live (fails
            # with "server gave HTTP response to HTTPS client" otherwise);
            # openbao.hcl's listener has tls_disable = true (see its own
            # comment for why).
            "-e", "BAO_ADDR=http://127.0.0.1:8200",
            "-e", f"BAO_TOKEN={OPENBAO_TOKEN}",
            "openbao", "bao", "kv", "get", "-format=json", f"secret/tier2-clients/{client_id}",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    # `bao kv get` on a fully-deleted (metadata-deleted) KV v2 path exits
    # non-zero -- confirmed against OpenBao's own CLI behavior, not assumed.
    return result.returncode != 0


def main() -> int:
    if not ADMIN_UI_PASSWORD:
        print("Set ADMIN_UI_PASSWORD (matching the running stack's .env) before running this.")
        return 1
    if not OPENBAO_TOKEN:
        print("Set OPENBAO_TOKEN (matching the running stack's .env) before running this.")
        return 1

    marker = f"openbao-smoke-{int(time.time())}"
    print(f"Creating a marker partner client ({marker!r}) via the admin UI at {ADMIN_BASE_URL}\n")

    client_uuid = None
    ui_secret = None
    try:
        status, final_url, _body = admin_request("POST", "/keycloak-clients/new", {"client_id": marker, "name": "OpenBao smoke test"})
        if not check("admin create-client POST succeeds", status == 200, f"got {status} at {final_url}"):
            return 1
        match = re.search(r"/keycloak-clients/([^/?]+)", final_url)
        client_uuid = match.group(1) if match else None
        if not check("new client's UUID recovered from redirect", bool(client_uuid), f"final_url={final_url}"):
            return 1
        check("no OpenBao warning on the create response", "openbao_warning" not in final_url, f"final_url={final_url}")

        status, _url, body = admin_request("POST", f"/keycloak-clients/{client_uuid}/reveal-secret")
        check("reveal-secret POST succeeds", status == 200, f"got {status}")
        secret_match = re.search(r"<pre>(.*?)</pre>", body, re.DOTALL)
        ui_secret = secret_match.group(1).strip() if secret_match else None
        if not check("secret recovered from the admin UI's own response", bool(ui_secret)):
            return 1

        bao_read = read_secret_via_bao_cli(marker)
        if not check("OpenBao independently has an entry for this client", bao_read.get("ok") is True, json.dumps(bao_read)):
            return 1
        bao_data = bao_read["data"]
        check(
            "OpenBao's mirrored secret matches exactly what the admin UI returned",
            bao_data.get("client_secret") == ui_secret,
            f"openbao={bao_data.get('client_secret')!r} ui={ui_secret!r}",
        )
        check("OpenBao's entry records the Keycloak UUID too", bao_data.get("keycloak_uuid") == client_uuid, json.dumps(bao_data))

    finally:
        if client_uuid:
            status, _url, _body = admin_request("POST", f"/keycloak-clients/{client_uuid}/delete")
            check("cleanup: marker client deleted", status == 200, f"got {status}")
            check("cleanup verified: OpenBao's mirrored secret is gone too", secret_is_gone_via_bao_cli(marker))

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All checks passed — the admin UI's OpenBao mirror genuinely holds what it showed, live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
