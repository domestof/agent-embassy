"""Channel dispatch: one real HTTP hop per execution, against the stubs
container -- a real network boundary so the routing demo is honest (the
agent genuinely delivers the action somewhere), without pretending any real
ERP/Slack/email exists (see ../stubs/main.py's disclaimers).

A channel call that fails or times out is reported as NOT executed
(status "failed" upstream, so verify releases the budget reservation).
Accepted residual, documented not hidden: a stub-call timeout is
technically ambiguous the same way verify's own handoff timeout is -- the
stub might have recorded the delivery -- but unlike the verify->agent hop
(cross-container, budget-bearing, retried and reconciled), this is an
intra-demo hop to a stub with no real-world side effects, so the demo
treats it as a plain failure instead of building a second
reservation/reconciliation layer. Revisit only when a channel becomes a
real external system.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

STUBS_BASE_URL = os.environ.get("STUBS_BASE_URL", "http://stubs:8020")
CHANNEL_TIMEOUT_SECONDS = int(os.environ.get("AGENT_CHANNEL_TIMEOUT_SECONDS", "2"))
_MAX_RESPONSE_BYTES = 64 * 1024


def _post(path: str, payload: dict) -> tuple[bool, str | None]:
    try:
        req = urllib.request.Request(
            f"{STUBS_BASE_URL}{path}",
            method="POST",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=CHANNEL_TIMEOUT_SECONDS) as resp:
            body = json.loads(resp.read(_MAX_RESPONSE_BYTES))
        reference = body.get("reference")
        if not isinstance(reference, str) or not reference:
            return False, None
        return True, reference
    except Exception:
        return False, None


def execute(
    channel: str, *, action_id: str, client_id: str, item: str, quantity: int, amount_cents: int
) -> tuple[bool, str | None]:
    """Dispatch to one stub channel. Returns (executed, reference)."""
    if channel == "mock_erp":
        return _post(
            "/mock-erp/orders",
            {
                "action_id": action_id,
                "client_id": client_id,
                "item": item,
                "quantity": quantity,
                "amount_cents": amount_cents,
            },
        )
    if channel == "slack_stub":
        return _post(
            "/slack/webhook",
            {
                "action_id": action_id,
                "text": (
                    f"Order {action_id} from {client_id}: {quantity} x {item} "
                    f"for EUR {amount_cents / 100:.2f} -- needs manual handling"
                ),
            },
        )
    if channel == "email_stub":
        return _post(
            "/email/send",
            {
                "action_id": action_id,
                "to": "operations@example.invalid",
                "subject": f"Order {action_id} from {client_id}",
                "body": f"{quantity} x {item} for EUR {amount_cents / 100:.2f}",
            },
        )
    # Unknown channel name: rules.py validates at import, so reaching this
    # means a code bug, not config -- refuse rather than guess.
    return False, None
