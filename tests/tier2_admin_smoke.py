#!/usr/bin/env python3
"""Real end-to-end smoke test for Tier 2 partner client management in the
admin UI.

Creates a partner OAuth client through the admin UI's real HTTP surface,
reveals its secret through that same surface, mints a real access token
against Keycloak's token endpoint with it, then — the core proof — runs
`docker compose exec verify` to invoke the ACTUAL
verify/keycloak_auth.validate_access_token() inside the already-running
`verify` container, proving the client this feature created is genuinely
spec-conformant for Tier 2, not just "looks right" by this feature's own
account. Complements tests/admin_smoke.py's Tier 0 write-then-read-back
proof with the Tier 2 create-then-actually-authenticate-with-it proof.

Deletes the client at the end (best-effort, unlike admin_smoke.py's marker
product which is left behind — a live OAuth-credentialed client is a worse
thing to leave lying around than a spurious catalog entry).

Run against a live stack:
    docker compose up -d
    ADMIN_UI_PASSWORD=<value from your .env> python3 tests/tier2_admin_smoke.py
    docker compose down
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
KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_HOST_BASE_URL", "http://localhost:8082")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "agent-embassy")
ADMIN_UI_USERNAME = os.environ.get("ADMIN_UI_USERNAME", "admin")
ADMIN_UI_PASSWORD = os.environ.get("ADMIN_UI_PASSWORD", "")

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
    """Returns (final_status, final_url, body). urllib follows the 303
    redirects the admin UI issues on success automatically, so `final_url`
    is where a create/delete actually landed -- used below to recover the
    new client's UUID without parsing HTML for it."""
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


def keycloak_token(client_id: str, client_secret: str) -> tuple[int, str]:
    form = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    ).encode()
    req = urllib.request.Request(
        f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token",
        data=form,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read())
            return 200, body.get("access_token", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def validate_token_inside_verify_container(token: str) -> dict:
    """Invokes the real verify/keycloak_auth.validate_access_token() inside
    the already-running `verify` container -- the strongest available proof
    that a client this feature created is genuinely spec-conformant, not a
    reimplementation of the check that could drift from the real one. The
    token is passed via argv, not interpolated into the -c string, so it
    never needs shell-escaping; it IS briefly visible via `ps` on the host
    while this subprocess runs -- an accepted tradeoff for a local/CI smoke
    test against a throwaway client deleted moments later, same posture as
    verify's own documented mTLS/session-resumption residual risks."""
    code = (
        "import sys, json\n"
        "from keycloak_auth import validate_access_token, InvalidToken\n"
        "try:\n"
        "    claims = validate_access_token(sys.argv[1])\n"
        "    print(json.dumps({'ok': True, 'aud': claims.get('aud'), 'iss': claims.get('iss'), 'sub': claims.get('sub')}))\n"
        "except InvalidToken as exc:\n"
        "    print(json.dumps({'ok': False, 'error': str(exc)}))\n"
    )
    result = subprocess.run(
        ["docker", "compose", "exec", "-T", "verify", "python3", "-c", code, token],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode != 0:
        return {"ok": False, "error": f"exec failed: {result.stderr.strip()}"}
    try:
        return json.loads(result.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return {"ok": False, "error": f"unparseable output: {result.stdout!r} {result.stderr!r}"}


def main() -> int:
    if not ADMIN_UI_PASSWORD:
        print("Set ADMIN_UI_PASSWORD (matching the running stack's .env) before running this.")
        return 1

    marker = f"tier2-smoke-{int(time.time())}"
    print(f"Creating a marker partner client ({marker!r}) via the admin UI at {ADMIN_BASE_URL}\n")

    client_uuid = None
    secret = None
    try:
        status, final_url, _body = admin_request("POST", "/keycloak-clients/new", {"client_id": marker, "name": "Tier 2 smoke test"})
        if not check("admin create-client POST succeeds", status == 200, f"got {status} at {final_url}"):
            return 1
        match = re.search(r"/keycloak-clients/([^/]+)$", final_url)
        client_uuid = match.group(1) if match else None
        if not check("new client's UUID recovered from redirect", bool(client_uuid), f"final_url={final_url}"):
            return 1

        status, _url, body = admin_request("POST", f"/keycloak-clients/{client_uuid}/reveal-secret")
        check("reveal-secret POST succeeds", status == 200, f"got {status}")
        secret_match = re.search(r"<pre>(.*?)</pre>", body, re.DOTALL)
        secret = secret_match.group(1).strip() if secret_match else None
        if not check("secret recovered from the admin UI's own response", bool(secret)):
            return 1

        status, _url, body = admin_request("GET", f"/keycloak-clients/{client_uuid}")
        check(
            "admin UI shows the audience mapper as present, with zero manual steps",
            "missing" not in body and "present" in body,
        )

        status, token_or_err = keycloak_token(marker, secret)
        if not check("minted a real access token from Keycloak for the created client", status == 200, f"got {status}: {token_or_err}"):
            return 1
        token = token_or_err

        result = validate_token_inside_verify_container(token)
        check(
            "verify's REAL validate_access_token() (inside the running container) accepts the token",
            result.get("ok") is True,
            json.dumps(result),
        )
        if result.get("ok"):
            check("token's aud claim includes agent-embassy-tier2", "agent-embassy-tier2" in (result.get("aud") or []))
            print(f"    claims: aud={result.get('aud')!r} iss={result.get('iss')!r} sub={result.get('sub')!r}")

    finally:
        if client_uuid:
            status, _url, _body = admin_request("POST", f"/keycloak-clients/{client_uuid}/delete")
            check("cleanup: marker client deleted", status == 200, f"got {status}")

            status, token_or_err = keycloak_token(marker, secret or "")
            check("cleanup verified: Keycloak now rejects the deleted client's credentials", status != 200, f"got {status}")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All checks passed — a client created through the admin UI is genuinely spec-conformant for Tier 2, live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
