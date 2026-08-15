#!/usr/bin/env python3
"""Real end-to-end smoke test for the Tier 3 feasibility demo.

Creates a partner OAuth client through the admin UI's real HTTP surface
(mirrors tier2_admin_smoke.py), grants it a small weekly spending limit
through that same surface, mints a real access token from Keycloak, and
places real mock orders over the live mTLS :443 listener. The headline
check -- the entire reason this feature exists -- comes after that: disable
the client through the admin UI, then confirm that with the SAME
still-unexpired token and client certificate, Tier 3 now rejects the very
next request (401, via Keycloak's real token-introspection endpoint) while
Tier 2's own order-status.json (local JWKS validation, no revocation check)
still accepts it. Same token, same connection, same moment, two different
answers -- that contrast is the demoable proof this repo previously lacked.

Run against a live stack:
    docker compose up -d
    ./certs/generate-dev-certs.sh   # if not already done
    ADMIN_UI_PASSWORD=<value from your .env> python3 tests/tier3_demo_smoke.py
    docker compose down
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

ADMIN_BASE_URL = os.environ.get("ADMIN_BASE_URL", "http://localhost:8090")
KEYCLOAK_BASE_URL = os.environ.get("KEYCLOAK_HOST_BASE_URL", "http://localhost:8082")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "agent-embassy")
ADMIN_UI_USERNAME = os.environ.get("ADMIN_UI_USERNAME", "admin")
ADMIN_UI_PASSWORD = os.environ.get("ADMIN_UI_PASSWORD", "")
MTLS_HOST = os.environ.get("MTLS_HOST", "localhost")
MTLS_PORT = int(os.environ.get("MTLS_PORT", "8443"))
PLAIN_PORT = int(os.environ.get("PLAIN_PORT", "8080"))
CA_CERT = os.environ.get("CA_CERT", "certs/ca.crt")
CLIENT_CERT = os.environ.get("CLIENT_CERT", "certs/client-example-partner.crt")
CLIENT_KEY = os.environ.get("CLIENT_KEY", "certs/client-example-partner.key")

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


def _mtls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA_CERT)
    ctx.load_cert_chain(certfile=CLIENT_CERT, keyfile=CLIENT_KEY)
    # certs/server.crt is CN=localhost with no SAN -- curl (see README) and
    # OpenSSL fall back to CN when no SAN is present, but Python's ssl
    # module is stricter and rejects it under check_hostname. Disabling
    # check_hostname here does NOT disable certificate verification --
    # verify_mode stays CERT_REQUIRED (the default create_default_context
    # sets), so the connection still fails closed against any cert not
    # signed by ca.crt. Only the hostname-vs-cert-name comparison is
    # skipped, which is exactly what curl already does implicitly for a
    # SAN-less cert.
    ctx.check_hostname = False
    return ctx


def tier3_order(token: str | None, item: str, amount_cents: int) -> tuple[int, dict | str]:
    """Reuses the example partner's cert (its CN is unrelated to the OAuth
    client_id in the bearer token -- nginx's mTLS listener only checks the
    certificate's signature against ca.crt, never binds it to a specific
    OAuth client) with whichever token the caller supplies, straight to the
    live mTLS :443 listener (host port MTLS_PORT)."""
    conn = http.client.HTTPSConnection(MTLS_HOST, MTLS_PORT, context=_mtls_context(), timeout=10)
    headers = {"Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps({"item": item, "quantity": 1, "amount_cents": amount_cents}).encode()
    conn.request("POST", "/tier3/orders", body=body, headers=headers)
    resp = conn.getresponse()
    status = resp.status
    raw = resp.read()
    conn.close()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw.decode(errors="replace")


def tier2_order_status(token: str) -> int:
    conn = http.client.HTTPSConnection(MTLS_HOST, MTLS_PORT, context=_mtls_context(), timeout=10)
    conn.request("GET", "/catalog/order-status.json", headers={"Authorization": f"Bearer {token}"})
    resp = conn.getresponse()
    status = resp.status
    resp.read()
    conn.close()
    return status


def plain_tier3_probe() -> int:
    """Confirms /tier3/orders is never exposed on the plaintext :80 listener
    (host port PLAIN_PORT), mTLS or not."""
    conn = http.client.HTTPConnection(MTLS_HOST, PLAIN_PORT, timeout=10)
    conn.request("POST", "/tier3/orders", body=b"{}", headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    status = resp.status
    resp.read()
    conn.close()
    return status


def main() -> int:
    if not ADMIN_UI_PASSWORD:
        print("Set ADMIN_UI_PASSWORD (matching the running stack's .env) before running this.")
        return 1

    marker = f"tier3-smoke-{int(time.time())}"
    print(f"Creating a marker partner client ({marker!r}) via the admin UI at {ADMIN_BASE_URL}\n")

    client_uuid = None
    secret = None
    token = None
    try:
        status, final_url, _body = admin_request(
            "POST", "/keycloak-clients/new", {"client_id": marker, "name": "Tier 3 smoke test"}
        )
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

        status, _url, body = admin_request(
            "POST", f"/keycloak-clients/{client_uuid}/tier3-grant", {"weekly_limit_eur": "10"}
        )
        check("set a €10 weekly Tier 3 limit via the admin UI", status == 200, f"got {status}")

        status, token_or_err = keycloak_token(marker, secret)
        if not check("minted a real access token from Keycloak for the created client", status == 200, f"got {status}: {token_or_err}"):
            return 1
        token = token_or_err

        status, resp_body = tier3_order(token, "Bath towels (24-pack)", 500)
        if check("order within the €10 limit is accepted (201)", status == 201, f"got {status}: {resp_body}"):
            order_number = resp_body.get("orderNumber") if isinstance(resp_body, dict) else None
            check("accepted order has a schema.org Order shape", isinstance(resp_body, dict) and resp_body.get("@type") == "Order")
        else:
            order_number = None

        # Two-mode contract: over-mandate is QUEUED for human
        # approval (202), not 403-rejected -- see ARCHITECTURE.md and
        # tests/tier3_agent_smoke.py for the full queue->approve->execute
        # loop this smoke test deliberately doesn't repeat.
        status, resp_body = tier3_order(token, "Bath towels (24-pack)", 600)
        check(
            "second order pushing past the €10 limit is queued for approval (202)",
            status == 202 and isinstance(resp_body, dict) and resp_body.get("status") == "pending_approval",
            f"got {status}: {resp_body}",
        )

        status = plain_tier3_probe()
        check("/tier3/orders is not exposed on the plaintext :80 listener (404)", status == 404, f"got {status}")

        # urllib follows the 303 redirect automatically (see admin_request's
        # docstring) -- status is the FINAL status after landing back on the
        # detail page, same as the create-client check above.
        status, _url, _body = admin_request("POST", f"/keycloak-clients/{client_uuid}/disable")
        if not check("disabled the client via the admin UI", status == 200, f"got {status}"):
            return 1

        # The headline check: SAME token, SAME certificate, immediately
        # after disabling -- Tier 3 (introspection) must now reject it,
        # while Tier 2 (local JWKS validation, no revocation check) still
        # accepts it. This contrast, not either check alone, is the proof
        # the whole feature exists to deliver.
        status, resp_body = tier3_order(token, "Bath towels (24-pack)", 100)
        check(
            "Tier 3 rejects the same still-unexpired token immediately after disable (401)",
            status == 401,
            f"got {status}: {resp_body}",
        )
        tier2_status = tier2_order_status(token)
        check(
            "Tier 2 still accepts the SAME token (200) -- proves the gap Tier 3 closes is real, not assumed",
            tier2_status == 200,
            f"got {tier2_status}",
        )

        status, _url, body = admin_request("GET", "/tier3-audit")
        if check("admin UI's Tier 3 audit page renders", status == 200, f"got {status}"):
            check("audit log shows the accepted order", bool(order_number) and order_number in body)
            check("audit log shows the over-mandate action as queued", "awaiting human approval" in body)
            check("audit log shows the post-revocation rejection", "introspection" in body)

    finally:
        if client_uuid:
            admin_request("POST", f"/keycloak-clients/{client_uuid}/tier3-grant/revoke")
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

    print("All checks passed — Tier 3's grant/limit/revocation/audit demo is genuinely live, not just documented.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
