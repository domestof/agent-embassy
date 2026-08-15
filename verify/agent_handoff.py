"""Tier 3 handoff to the privileged internal agent (see ARCHITECTURE.md).

verify never executes a Tier 3 action itself: it authenticates, checks the
mandate, reserves budget, and hands a fixed-schema envelope to the internal
`agent` container over the internal Docker network. The agent decides the
execution channel (rules first, LLM only for channel choice) and reports
back. This module is the single mockable network boundary for that hop --
mirrors introspection.py's shape.

Failure taxonomy, load-bearing because money is involved (see the order
handler in main.py for how each maps to budget settlement):

- "ok"      -- HTTP 200 with a valid body; status is "executed" or "failed".
- "down"    -- connection refused, or a non-200 response. The agent did NOT
               execute (it never runs an action before answering 200), so the
               caller's budget reservation is safe to release.
- "unknown" -- timeout after the request was sent, or a 200 whose body can't
               be parsed. The agent MAY have executed (a malformed 200 almost
               certainly means it did), so the reservation must STAND.

On timeout the identical envelope is retried once before giving up: verify
mints the action_id before the handoff and the agent is idempotent on it
(bounded result map), so a retry can only ever fetch the original outcome,
never execute twice. This collapses most transient timeouts into resolved
outcomes instead of "execution unknown" audit rows.
"""
from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass

# Fail closed at import, same reasoning as main.py's ADMIN_INTERNAL_TOKEN:
# a missing value would otherwise mean every handoff 403s at the agent with
# no clue why. Deliberately a DIFFERENT secret from ADMIN_INTERNAL_TOKEN --
# this one authorizes execution (verify -> agent), and the agent must never
# hold a token verify itself accepts (see ARCHITECTURE.md's trust chain).
AGENT_INTERNAL_TOKEN = os.environ.get("AGENT_INTERNAL_TOKEN", "")
if not AGENT_INTERNAL_TOKEN:
    raise RuntimeError("AGENT_INTERNAL_TOKEN must be set (see .env.example)")

AGENT_BASE_URL = os.environ.get("AGENT_BASE_URL", "http://agent:8010")
# Per-attempt timeout. The agent's own internal deadlines (LLM ~5s + stub
# ~2s, see agent/main.py) are budgeted to finish well inside one attempt, so
# a timeout here means process hang or network loss, not routine slowness.
# Worst case wall time for one handoff: 2 attempts x 10s. admin's
# approve/reject client timeout is sized above that (see admin/tier3_client).
HANDOFF_TIMEOUT_SECONDS = int(os.environ.get("HANDOFF_TIMEOUT_SECONDS", "10"))
_MAX_RESPONSE_BYTES = 64 * 1024

_VALID_STATUSES = {"executed", "failed"}
_VALID_DECIDED_BY = {"rules", "llm"}


@dataclass
class HandoffResult:
    kind: str  # "ok" | "down" | "unknown"
    status: str | None = None  # "executed" | "failed", only when kind == "ok"
    channel: str | None = None
    decided_by: str | None = None
    reference: str | None = None


def _post_action(envelope: dict) -> tuple[str, int, bytes]:
    """One attempt. Returns (transport, http_status, body) where transport is
    "response" (got an HTTP response, any status), "timeout", or "down".
    Request(...) construction stays INSIDE the try block -- its constructor
    can itself raise ValueError for a malformed URL, the bug shape this repo
    has now hit three times (test_console, keycloak_client, introspection)."""
    try:
        req = urllib.request.Request(
            f"{AGENT_BASE_URL}/internal/actions",
            method="POST",
            data=json.dumps(envelope).encode(),
            headers={
                "X-Agent-Token": AGENT_INTERNAL_TOKEN,
                "Content-Type": "application/json",
            },
        )
        with urllib.request.urlopen(req, timeout=HANDOFF_TIMEOUT_SECONDS) as resp:
            return "response", resp.status, resp.read(_MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        return "response", exc.code, exc.read()
    except urllib.error.URLError as exc:
        # urllib wraps a socket timeout in URLError(reason=TimeoutError).
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            return "timeout", 0, b""
        return "down", 0, b""
    except (socket.timeout, TimeoutError):
        # A timeout during body read arrives bare, not URLError-wrapped.
        return "timeout", 0, b""
    except Exception:
        return "down", 0, b""


def _parse_ok_body(body: bytes, expected_action_id: str) -> HandoffResult | None:
    """Strict validation of a 200 body. Returns None when the body is not a
    well-formed handoff response -- which the caller must treat as "unknown"
    (the agent very likely executed and the response got mangled), NOT as
    "down"."""
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("action_id") != expected_action_id:
        return None
    status = data.get("status")
    if status not in _VALID_STATUSES:
        return None
    channel = data.get("channel")
    decided_by = data.get("decided_by")
    reference = data.get("reference")
    if status == "executed":
        if not isinstance(channel, str) or decided_by not in _VALID_DECIDED_BY:
            return None
        if not isinstance(reference, str) or not reference:
            return None
    return HandoffResult(
        kind="ok",
        status=status,
        channel=channel if isinstance(channel, str) else None,
        decided_by=decided_by if isinstance(decided_by, str) else None,
        reference=reference if isinstance(reference, str) else None,
    )


def execute_handoff(envelope: dict) -> HandoffResult:
    """POSTs the envelope to the agent; retries the IDENTICAL envelope once
    on timeout (safe -- the agent is idempotent on action_id)."""
    transport, status, body = _post_action(envelope)
    if transport == "timeout":
        transport, status, body = _post_action(envelope)
        if transport == "timeout":
            return HandoffResult(kind="unknown")
    if transport == "down":
        return HandoffResult(kind="down")
    if status != 200:
        return HandoffResult(kind="down")
    parsed = _parse_ok_body(body, envelope.get("action_id", ""))
    if parsed is None:
        return HandoffResult(kind="unknown")
    return parsed
