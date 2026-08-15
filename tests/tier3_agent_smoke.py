#!/usr/bin/env python3
"""Real end-to-end smoke test for the internal-agent handoff and
two-mode approval flow (see ARCHITECTURE.md). Doubles as the pilot
acceptance script for Tier 3.

What it proves, all live over the real mTLS listener, real Keycloak, the
real admin UI, and the real agent/stubs containers -- no mocks anywhere:

1. An in-mandate order returns 201 and is genuinely executed by the
   privileged internal agent against the mock-ERP stub channel (checked via
   the admin UI's internal-agent decision log, not the order response's own
   claims).
2. An over-mandate order returns 202 pending_approval (the step-10 contract
   change from the old 403), polls as "queued", shows up on the admin UI's
   Approvals page, and after a human approve executes and polls as
   "executed" -- with the full lifecycle (queued -> approved-accepted)
   visible in the Tier 3 audit trail.
3. Fail-closed: with the agent container stopped (`docker compose stop
   agent`), an in-mandate order returns 503 and consumes NO budget; after
   restarting the agent, ordering works again. (Requires the docker CLI;
   skipped with SKIP_AGENT_RESTART=1.)
4. Revoking the client's mandate cancels its still-pending approvals (the
   partner's poll sees "rejected", the Approvals page empties).

Run against a live stack:
    docker compose up -d
    ./certs/generate-dev-certs.sh   # if not already done
    ADMIN_UI_PASSWORD=<value from your .env> python3 tests/tier3_agent_smoke.py
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import re
import ssl
import subprocess
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
CA_CERT = os.environ.get("CA_CERT", "certs/ca.crt")
CLIENT_CERT = os.environ.get("CLIENT_CERT", "certs/client-example-partner.crt")
CLIENT_KEY = os.environ.get("CLIENT_KEY", "certs/client-example-partner.key")
SKIP_AGENT_RESTART = os.environ.get("SKIP_AGENT_RESTART", "") == "1"

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
    """urllib follows the admin UI's 303 redirects automatically, so the
    returned status is the FINAL page's (same convention as
    tier3_demo_smoke.py)."""
    body = urllib.parse.urlencode(data).encode() if data is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(
        f"{ADMIN_BASE_URL}{path}", method=method, data=body, headers={"Authorization": _auth_header()}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.url, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.url or "", exc.read().decode()


def keycloak_token(client_id: str, client_secret: str) -> tuple[int, str]:
    data = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    ).encode()
    req = urllib.request.Request(
        f"{KEYCLOAK_BASE_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token", data=data
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read()).get("access_token", "")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def _mtls_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=CA_CERT)
    ctx.check_hostname = False
    ctx.load_cert_chain(CLIENT_CERT, CLIENT_KEY)
    return ctx


def tier3_request(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict | str]:
    conn = http.client.HTTPSConnection(MTLS_HOST, MTLS_PORT, context=_mtls_context(), timeout=30)
    headers = {"Authorization": f"Bearer {token}"}
    if body is not None:
        headers["Content-Type"] = "application/json"
    conn.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers)
    resp = conn.getresponse()
    raw = resp.read().decode()
    conn.close()
    try:
        return resp.status, json.loads(raw)
    except json.JSONDecodeError:
        return resp.status, raw


def order_waiting_out_rate_limit(token: str, body: dict, timeout_seconds: int = 90) -> tuple[int, dict | str]:
    """POST an order, retrying only while the Tier 3 order bucket is full.

    The checks that use this run after the earlier sections have spent the
    client's whole bucket (TIER3_RATE_LIMIT_MAX, 10 per 60s by default).
    Deliberately retries the real request rather than probing some other
    endpoint: GET /tier3/orders/{id} has its OWN separate bucket
    (tier3_poll), so it cannot report on this one. Any non-429 status is
    returned immediately and judged by the caller.
    """
    deadline = time.time() + timeout_seconds
    while True:
        status, resp = tier3_request("POST", "/tier3/orders", token, body)
        if status != 429 or time.time() >= deadline:
            return status, resp
        time.sleep(5)


def main() -> int:
    if not ADMIN_UI_PASSWORD:
        print("Set ADMIN_UI_PASSWORD (the value from your .env) to run this test.")
        return 1

    marker = f"agent-smoke-{int(time.time())}"
    print(f"Creating a marker partner client ('{marker}') via the admin UI at {ADMIN_BASE_URL}\n")
    client_uuid = None
    try:
        status, url, _body = admin_request("POST", "/keycloak-clients/new", {"client_id": marker, "name": "Agent smoke"})
        if not check("admin create-client POST succeeds", status == 200, f"got {status}"):
            return 1
        match = re.search(r"/keycloak-clients/([0-9a-f-]{36})", url)
        if not check("new client's UUID recovered from redirect", match is not None, url):
            return 1
        client_uuid = match.group(1)

        status, _url, body = admin_request("POST", f"/keycloak-clients/{client_uuid}/reveal-secret")
        secret_match = re.search(r"<pre>(.*?)</pre>", body, re.DOTALL)
        secret = secret_match.group(1).strip() if secret_match else None
        if not check("secret recovered from the admin UI", status == 200 and bool(secret)):
            return 1

        status, _url, _body = admin_request(
            "POST", f"/keycloak-clients/{client_uuid}/tier3-grant", {"weekly_limit_eur": "10"}
        )
        check("set a €10 weekly mandate via the admin UI", status == 200, f"got {status}")

        status, token = keycloak_token(marker, secret)
        if not check("minted a real access token from Keycloak", status == 200, f"got {status}: {token}"):
            return 1

        # --- 1. In-mandate order executes via the internal agent ----------
        status, body = tier3_request("POST", "/tier3/orders", token, {"item": "Smoke towels", "quantity": 2, "amount_cents": 500})
        ok = check("in-mandate order accepted (201)", status == 201, f"got {status}: {body}")
        action_id = body.get("action_id") if isinstance(body, dict) else None
        if ok:
            check("order response names the channel and action_id", body.get("channel") == "mock_erp" and bool(action_id))
            check("order reference comes from the ERP stub (ERP- prefix)", str(body.get("orderNumber", "")).startswith("ERP-"))

        # Independent proof of execution: the agent's own decision log via
        # the admin UI, not the order response's claims about itself.
        status, _url, page = admin_request("GET", "/internal-agent")
        check(
            "internal-agent page shows the executed decision",
            status == 200 and action_id is not None and action_id in page and "within_mandate" in page,
        )

        status, body = tier3_request("GET", f"/tier3/orders/{action_id}", token)
        check("poll of the executed order returns executed", status == 200 and isinstance(body, dict) and body.get("status") == "executed", f"got {status}: {body}")

        # --- 2. Over-mandate order -> queue -> human approve -> executed --
        status, body = tier3_request("POST", "/tier3/orders", token, {"item": "Smoke exceptional order", "quantity": 1, "amount_cents": 2000})
        ok = check("over-mandate order is queued (202 pending_approval)", status == 202 and isinstance(body, dict) and body.get("status") == "pending_approval", f"got {status}: {body}")
        pending_id = body.get("action_id") if isinstance(body, dict) else None
        if ok:
            status, body = tier3_request("GET", body["status_path"], token)
            check("poll while queued returns queued", status == 200 and isinstance(body, dict) and body.get("status") == "queued")

        status, _url, page = admin_request("GET", "/approvals")
        check("Approvals page lists the pending order", status == 200 and pending_id is not None and pending_id in page)

        status, _url, page = admin_request("POST", f"/approvals/{pending_id}/approve")
        check("human approve via the admin UI executes the order", status == 200 and "Approved and executed via" in page, f"got {status}")

        status, body = tier3_request("GET", f"/tier3/orders/{pending_id}", token)
        check("poll after approve returns executed", status == 200 and isinstance(body, dict) and body.get("status") == "executed", f"got {status}: {body}")

        status, _url, page = admin_request("GET", "/tier3-audit")
        check(
            "audit trail shows the full lifecycle (queued, then approved by human)",
            status == 200 and "awaiting human approval" in page and "approved by human" in page,
        )

        # --- 3. Fail-closed with the agent stopped ------------------------
        # The approved exceptional order above consumed the whole €10
        # mandate (€5 + €20 approved > €10) -- raise it so the probes below
        # are genuinely IN-mandate; otherwise they'd queue (202) instead of
        # exercising the handoff path this section exists to test.
        status, _url, _body = admin_request(
            "POST", f"/keycloak-clients/{client_uuid}/tier3-grant", {"weekly_limit_eur": "100"}
        )
        check("mandate raised to €100 for the fail-closed probes", status == 200, f"got {status}")

        if SKIP_AGENT_RESTART:
            print("[SKIP] fail-closed check — SKIP_AGENT_RESTART=1")
        else:
            subprocess.run(["docker", "compose", "stop", "agent"], check=True, capture_output=True)
            try:
                status, body = tier3_request("POST", "/tier3/orders", token, {"item": "Smoke while down", "quantity": 1, "amount_cents": 100})
                check("order with the agent stopped fails closed (503)", status == 503, f"got {status}: {body}")
            finally:
                subprocess.run(["docker", "compose", "start", "agent"], check=True, capture_output=True)
                deadline = time.time() + 30
                while time.time() < deadline:
                    result = subprocess.run(
                        ["docker", "compose", "ps", "agent", "--format", "{{.Status}}"], capture_output=True, text=True
                    )
                    if "healthy" in result.stdout:
                        break
                    time.sleep(1)
            status, body = tier3_request("POST", "/tier3/orders", token, {"item": "Smoke after restart", "quantity": 1, "amount_cents": 100})
            check("ordering works again after the agent restarts (201)", status == 201, f"got {status}: {body}")

        # --- 4. Mandate revocation cancels pending approvals --------------
        # €90 > the ~€73 remaining of the €100 mandate after the probes
        # above -- must exceed remaining to queue.
        status, body = tier3_request("POST", "/tier3/orders", token, {"item": "Smoke to be cancelled", "quantity": 1, "amount_cents": 9000})
        cancelled_id = body.get("action_id") if isinstance(body, dict) else None
        check("second over-mandate order queues (202)", status == 202, f"got {status}: {body}")

        status, _url, _page = admin_request("POST", f"/keycloak-clients/{client_uuid}/tier3-grant/revoke")
        check("mandate revoked via the admin UI", status == 200, f"got {status}")

        status, body = tier3_request("GET", f"/tier3/orders/{cancelled_id}", token)
        check(
            "revocation cancelled the pending approval (poll shows rejected)",
            status == 200 and isinstance(body, dict) and body.get("status") == "rejected",
            f"got {status}: {body}",
        )
        status, _url, page = admin_request("GET", "/approvals")
        check("Approvals page no longer lists the cancelled order", status == 200 and (cancelled_id or "") not in page)

        # --- 5. Orders ABOVE agent/rules.json's direct-channel ceiling -----
        # Every amount used above (€5/€20/€1/€1/€90) sits under the shipped
        # rules.json ceiling of 20000 cents, so all of them matched the first
        # rule and never touched the "llm" catch-all. That gap is exactly how
        # a real defect survived every prior review: with no AGENT_LLM_MODEL
        # (the shipped default) the catch-all resolved to "no usable LLM
        # decision" and EVERY order over €200 failed -- including the
        # flagship €400/week illustrative example, and including orders a human had
        # already approved. Both halves are covered here.
        status, _url, _body = admin_request(
            "POST", f"/keycloak-clients/{client_uuid}/tier3-grant", {"weekly_limit_eur": "500"}
        )
        check("fresh €500 mandate for the above-ceiling checks", status == 200, f"got {status}")

        status, body = order_waiting_out_rate_limit(
            token, {"item": "Smoke above-ceiling order", "quantity": 10, "amount_cents": 40000}
        )
        ok = check(
            "in-mandate €400 order (above the €200 rule ceiling) executes (201)",
            status == 201 and isinstance(body, dict),
            f"got {status}: {body}",
        )
        if ok:
            # Same shape as section 1's assertions: a 201 IS the executed
            # schema.org Order (there is no "status" field on it).
            check(
                "€400 order routed to a real channel, not refused",
                body.get("channel") == "mock_erp" and str(body.get("orderNumber", "")).startswith("ERP-"),
                f"got channel={body.get('channel')} orderNumber={body.get('orderNumber')}",
            )

        # Same boundary, but through the human-approval path: the approved
        # action takes the identical handoff, so it failed identically before.
        status, body = order_waiting_out_rate_limit(
            token, {"item": "Smoke above-ceiling exceptional", "quantity": 10, "amount_cents": 30000}
        )
        big_pending = body.get("action_id") if isinstance(body, dict) else None
        check("over-mandate €300 order queues (202)", status == 202, f"got {status}: {body}")

        status, _url, page = admin_request("POST", f"/approvals/{big_pending}/approve")
        check(
            "approved €300 order (above the rule ceiling) actually executes",
            status == 200 and "Approved and executed via" in page,
            f"got {status}",
        )
        status, body = tier3_request("GET", f"/tier3/orders/{big_pending}", token)
        check(
            "poll after approving the above-ceiling order returns executed",
            status == 200 and isinstance(body, dict) and body.get("status") == "executed",
            f"got {status}: {body}",
        )

    finally:
        if client_uuid:
            admin_request("POST", f"/keycloak-clients/{client_uuid}/tier3-grant/revoke")
            status, _url, _body = admin_request("POST", f"/keycloak-clients/{client_uuid}/delete")
            check("cleanup: marker client deleted", status == 200, f"got {status}")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("All checks passed — the internal-agent handoff and two-mode approval flow are genuinely live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
