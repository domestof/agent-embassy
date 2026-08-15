#!/usr/bin/env python3
"""Smoke test for Tier 0/1 wrapped as MCP tools through LiteLLM.

Speaks raw MCP JSON-RPC over HTTP (POST /mcp/, stdlib urllib only — no `mcp`
SDK dependency) against the live LiteLLM proxy, the same "real HTTP against
the running stack, no mocks" convention every other smoke test in this repo
follows (see tests/tier0_two_party.py, tests/tier1_config_smoke.py).

Two request-shape quirks this script has to handle, both confirmed live
during design rather than assumed from docs:

  - LiteLLM's MCP endpoint responds as `text/event-stream` (SSE) even for a
    single stateless, non-`initialize` JSON-RPC call — _read_sse_json()
    pulls the one `data:` line out of the body.
  - LiteLLM's OpenAPI-tool dispatch returns `response.text` from the wrapped
    backend WITHOUT checking its HTTP status, and wraps that as a
    *successful* MCP result (`isError: false`) even for a 401. Every check
    below that cares about auth failure asserts on body CONTENT, never on
    `isError` — an agent calling get_contact with no token sees a
    "successful" tool call whose content is nginx's 401 error page. This is
    a real UX wart of the underlying feature, not a bug in this script.

Two headers matter and are easy to confuse: `x-litellm-api-key` (LiteLLM's
own admission — anyone reaching /mcp needs this) and `Authorization`
(forwarded UNTOUCHED to the wrapped Tier 0/1 backend — this is the whole
per-caller identity mechanism, see litellm/config.yaml's `extra_headers`).
Putting the LiteLLM key in `Authorization` just means the wrong value
reaches nginx (harmless, but wrong) — never conflate the two.

A real Tier 1 session token cannot be minted locally: verify/security.py's
domain-challenge fetch does a real TLS GET against a real domain's
`.well-known` path, and nothing in this repo provides a dev bypass (the
same reason tests/tier0_two_party.py only ever asserts the 401 side of
Tier 1). This script runs a smaller "default mode" without one, and an
additional "decisive mode" — the actual proof that per-caller identity
survives the MCP hop — when TIER1_SESSION_TOKEN is set.

Run against a live stack:
    docker compose up -d
    LITELLM_MASTER_KEY=<value from your .env> python3 tests/mcp_tier0_tier1_smoke.py

    # Decisive mode (recommended): obtain a real token first via the
    # documented Tier 1 flow (README "Running Tier 1 locally") against a
    # domain you control, then:
    LITELLM_MASTER_KEY=<...> TIER1_SESSION_TOKEN=<...> python3 tests/mcp_tier0_tier1_smoke.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

LITELLM_BASE_URL = os.environ.get("LITELLM_BASE_URL", "http://localhost:4000")
STATIC_BASE_URL = os.environ.get("STATIC_BASE_URL", "http://localhost:8080")
LITELLM_MASTER_KEY = os.environ.get("LITELLM_MASTER_KEY", "")
TIER1_SESSION_TOKEN = os.environ.get("TIER1_SESSION_TOKEN")

EXPECTED_TOOLS = {
    "agent_embassy-get_manifest",
    "agent_embassy-get_products",
    "agent_embassy-get_services",
    "agent_embassy-get_open_positions",
    "agent_embassy-get_supplier_needs",
    "agent_embassy-tier1_challenge",
    "agent_embassy-tier1_verify",
    "agent_embassy-get_contact",
}

failures: list[str] = []
_next_id = 0


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)
    return condition


def skip(label: str, reason: str) -> None:
    print(f"[SKIP] {label} — {reason}")


def _read_sse_json(body: bytes) -> dict:
    for line in body.decode(errors="replace").splitlines():
        if line.startswith("data:"):
            return json.loads(line[len("data:") :].strip())
    raise ValueError(f"no SSE 'data:' line found in response body: {body!r}")


def mcp_request(method: str, params: dict, *, session_token: str | None = None) -> dict:
    global _next_id
    _next_id += 1
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "x-litellm-api-key": f"Bearer {LITELLM_MASTER_KEY}",
    }
    # Only set when explicitly provided -- absence must mean absence, not an
    # empty-string header, so the wrapped backend genuinely sees no token.
    if session_token is not None:
        headers["Authorization"] = f"Bearer {session_token}"
    body = json.dumps({"jsonrpc": "2.0", "id": _next_id, "method": method, "params": params}).encode()
    req = urllib.request.Request(f"{LITELLM_BASE_URL}/mcp/", data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        raw = exc.read()
    return _read_sse_json(raw)


def call_tool(name: str, arguments: dict, *, session_token: str | None = None) -> dict:
    resp = mcp_request("tools/call", {"name": name, "arguments": arguments}, session_token=session_token)
    result = resp.get("result")
    if result is None:
        raise RuntimeError(f"tool call {name!r} failed at the JSON-RPC level: {resp}")
    return result


def tool_text(result: dict) -> str:
    return "".join(part.get("text", "") for part in result.get("content", []) if part.get("type") == "text")


def http_get(base: str, path: str) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(base + path, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def main() -> int:
    if not LITELLM_MASTER_KEY:
        print("Set LITELLM_MASTER_KEY (matching the running stack's .env) before running this.")
        return 1

    print(f"Talking raw MCP JSON-RPC to LiteLLM at {LITELLM_BASE_URL}/mcp/\n")

    # --- tools/list -----------------------------------------------------
    resp = mcp_request("tools/list", {})
    tools = {t["name"] for t in resp.get("result", {}).get("tools", [])}
    check("tools/list returns all 8 expected Tier 0/1 tools", EXPECTED_TOOLS <= tools, f"got {sorted(tools)}")

    # --- Tier 0 tools return real schema.org catalog data ---------------
    for tool in ["get_products", "get_services", "get_open_positions", "get_supplier_needs"]:
        result = call_tool(f"agent_embassy-{tool}", {})
        try:
            doc = json.loads(tool_text(result))
        except json.JSONDecodeError as exc:
            check(f"{tool} returns valid JSON via MCP", False, str(exc))
            continue
        check(f"{tool} returns valid JSON via MCP", True)
        check(
            f"{tool} is schema.org-shaped with at least one item",
            doc.get("@context") == "https://schema.org" and bool(doc.get("itemListElement")),
        )

    # --- MCP path and direct :8080 path serve the same manifest truth ---
    mcp_result = call_tool("agent_embassy-get_manifest", {})
    mcp_manifest = json.loads(tool_text(mcp_result))
    direct_status, direct_body = http_get(STATIC_BASE_URL, "/.well-known/agent-embassy.json")
    check("direct :8080 manifest fetch succeeds (for comparison)", direct_status == 200, f"got {direct_status}")
    direct_manifest = json.loads(direct_body) if direct_status == 200 else {}
    check(
        "manifest via MCP matches the direct :8080 fetch",
        mcp_manifest.get("public_catalog") == direct_manifest.get("public_catalog"),
    )

    # --- POST body nesting: {"body": {"domain": ...}}, not top-level ----
    challenge = call_tool("agent_embassy-tier1_challenge", {"body": {"domain": "example.org"}})
    try:
        challenge_doc = json.loads(tool_text(challenge))
    except json.JSONDecodeError as exc:
        check("tier1_challenge returns valid JSON via MCP", False, str(exc))
        challenge_doc = {}
    else:
        check("tier1_challenge returns valid JSON via MCP", True)
    check(
        "tier1_challenge returns a real token and well-known path",
        bool(challenge_doc.get("token")) and challenge_doc.get("well_known_path", "").endswith("challenge.txt"),
        f"got {challenge_doc}",
    )

    # --- The boundary: get_contact must fail closed, and "success" here
    # means nothing -- assert on CONTENT, never on isError (see module
    # docstring: a 401 comes back as a "successful" MCP result).
    no_token_result = call_tool("agent_embassy-get_contact", {})
    no_token_text = tool_text(no_token_result)
    check(
        "get_contact with no Authorization fails closed (401 content, not contact data)",
        "401" in no_token_text and "contactType" not in no_token_text,
        no_token_text[:200],
    )

    bad_token_result = call_tool("agent_embassy-get_contact", {}, session_token="not-a-real-session-token")
    bad_token_text = tool_text(bad_token_result)
    check(
        "get_contact with a garbage Authorization also fails closed",
        "401" in bad_token_text and "contactType" not in bad_token_text,
        bad_token_text[:200],
    )

    # --- Decisive mode: proves the result tracks EACH call's own header,
    # not a cached/shared credential -- the actual difference between
    # per-caller passthrough and a static credential.
    if TIER1_SESSION_TOKEN:
        real_result = call_tool("agent_embassy-get_contact", {}, session_token=TIER1_SESSION_TOKEN)
        real_text = tool_text(real_result)
        got_real_contact = check(
            "get_contact with a REAL Tier 1 session token returns real contact data",
            '"@type": "ContactPoint"' in real_text or "contactType" in real_text,
            real_text[:300],
        )
        if got_real_contact:
            immediately_after_result = call_tool(
                "agent_embassy-get_contact", {}, session_token="a-different-garbage-token"
            )
            immediately_after_text = tool_text(immediately_after_result)
            check(
                "the VERY NEXT call, same process, garbage token, fails closed again "
                "(proves per-call passthrough, not a cached/shared credential)",
                "401" in immediately_after_text and "contactType" not in immediately_after_text,
                immediately_after_text[:200],
            )
    else:
        skip(
            "decisive mode (real Tier 1 token proof)",
            "TIER1_SESSION_TOKEN not set -- obtain one via the real challenge/verify flow "
            "against a domain you control (README 'Running Tier 1 locally') and re-run with it set",
        )

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All checks passed — Tier 0/1 are genuinely reachable as MCP tools through LiteLLM.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
