"""The privileged internal agent (see ARCHITECTURE.md).

Receives Tier 3 action handoffs from `verify` (the gateway) as fixed-schema
envelopes -- NEVER raw external traffic -- and executes each one against an
internal channel (mock ERP / Slack stub / email stub, see ../stubs/). The
routing decision is rules-first (rules.py, human-edited rules.json); an LLM
(llm.py, via the already-deployed LiteLLM) is consulted ONLY when a rule
explicitly delegates to it, and its entire authority is choosing one channel
from the rule file's allowlist. There is deliberately NO implicit default
channel: no matching rule, or a CONFIGURED LLM returning nothing usable,
means the action FAILS (verify then releases the budget reservation) -- an
implicit fallback would let an attacker choose the channel by derailing the
LLM, which is far easier than forcing a specific output (found at plan-stage
adversarial review). The one explicit exception is a rule's optional
"fallback_channel", which applies only when this deployment has no LLM
configured at all -- a boot-time fact no caller can influence. See rules.py.

Part of the product, but architecturally separate from the gateway: this
container holds NO token verify accepts, so compromising it (it's the one
component that ingests attacker-influenced text) yields no authority over
grants, approvals, or audit. Its inbound contract is exactly two endpoints:

- POST /internal/actions  -- verify only (X-Agent-Token). Idempotent on
  action_id: a bounded result map returns the original outcome for a retried
  envelope, so verify's retry-on-timeout can never execute twice.
- GET  /internal/status   -- admin UI only (X-Agent-Status-Token), read-only:
  rules summary, LLM configuration, and the decision log (queryable by
  action_id -- the reconciliation path for verify's "execution unknown"
  audit rows).

A company can replace this whole container with its own agent as long as it
honors the same contract.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

import channels
import llm
import rules

# Two secrets, two edges, fail closed at import (same reasoning as verify's
# ADMIN_INTERNAL_TOKEN). AGENT_INTERNAL_TOKEN authorizes execution and is
# held by verify only; AGENT_STATUS_TOKEN authorizes read-only observation
# and is held by admin only. Deliberately NOT one shared secret: the admin
# UI must be structurally unable to invoke executions, and this container
# must hold nothing that grants authority over verify.
AGENT_INTERNAL_TOKEN = os.environ.get("AGENT_INTERNAL_TOKEN", "")
if not AGENT_INTERNAL_TOKEN:
    raise RuntimeError("AGENT_INTERNAL_TOKEN must be set (see .env.example)")
AGENT_STATUS_TOKEN = os.environ.get("AGENT_STATUS_TOKEN", "")
if not AGENT_STATUS_TOKEN:
    raise RuntimeError("AGENT_STATUS_TOKEN must be set (see .env.example)")

# Bounded idempotency + decision-log storage. In-memory, single-instance --
# the same accepted Store tradeoff as verify's.
RESULT_MAP_MAX = int(os.environ.get("AGENT_RESULT_MAP_MAX", "500"))
DECISION_LOG_MAX = int(os.environ.get("AGENT_DECISION_LOG_MAX", "500"))

app = FastAPI(title="agent-embassy-internal-agent", docs_url=None, redoc_url=None, openapi_url=None)

_results: dict[str, dict] = {}  # action_id -> response body already returned
_decision_log: list[dict] = []  # newest last; bounded

# Idempotency must be ATOMIC, not check-then-act. verify retries the
# identical envelope once on a handoff timeout, and that retry can arrive
# WHILE the first attempt is still inside channels.execute (the first
# attempt timed out at verify precisely because it was slow). A bare
# `_results.get() is None` check followed by a later `_store_result` lets
# both requests pass the check and both dispatch -- executing the action
# TWICE, on the exact timeout path the caller is told not to resubmit on
# (found by post-build adversarial review, reproduced live 3/3). A
# per-action_id lock, held across channels.execute, closes it: same-action
# requests serialize (the retry blocks until the first stores its outcome,
# then returns it), distinct orders take distinct locks and never block
# each other. _registry_lock is a short-held leaf lock guarding the two
# dicts' structure; nothing acquires a per-action lock while holding it, so
# there is no lock-ordering deadlock.
_registry_lock = threading.Lock()
_action_locks: dict[str, threading.Lock] = {}


def _action_lock(action_id: str) -> threading.Lock:
    with _registry_lock:
        lock = _action_locks.get(action_id)
        if lock is None:
            lock = threading.Lock()
            _action_locks[action_id] = lock
        return lock


class Mandate(BaseModel):
    mode: Literal["within_mandate", "approved_by_human"]
    weekly_limit_cents: int = Field(gt=0)
    used_cents: int = Field(ge=0)
    remaining_cents: int = Field(ge=0)
    window_seconds: int = Field(gt=0)
    approved_by: str | None = None


class ActionEnvelope(BaseModel):
    # Mirrors verify's Tier3OrderRequest bounds -- the envelope is built by
    # verify from an already-validated request, but this service re-validates
    # because its contract must hold for ANY caller holding the token, not
    # just today's verify.
    action_id: str = Field(min_length=1, max_length=64)
    action_type: Literal["order.place"]
    client_id: str = Field(min_length=1, max_length=200)
    requested_at: float
    payload: dict
    mandate: Mandate


class OrderPayload(BaseModel):
    item: str = Field(min_length=1, max_length=200)
    quantity: int = Field(gt=0, le=10_000)
    amount_cents: int = Field(gt=0, le=1_000_000)


def _require_agent_token(x_agent_token: str | None) -> None:
    if not x_agent_token or not secrets.compare_digest(x_agent_token, AGENT_INTERNAL_TOKEN):
        raise HTTPException(status_code=403, detail="forbidden")


def _require_status_token(x_agent_status_token: str | None) -> None:
    if not x_agent_status_token or not secrets.compare_digest(x_agent_status_token, AGENT_STATUS_TOKEN):
        raise HTTPException(status_code=403, detail="forbidden")


def _log_decision(entry: dict) -> None:
    _decision_log.append(entry)
    if len(_decision_log) > DECISION_LOG_MAX:
        del _decision_log[: len(_decision_log) - DECISION_LOG_MAX]


def _store_result(action_id: str, body: dict) -> dict:
    with _registry_lock:
        _results[action_id] = body
        if len(_results) > RESULT_MAP_MAX:
            for key in list(_results)[: len(_results) - RESULT_MAP_MAX]:
                del _results[key]
        # Keep the per-action lock table bounded in lockstep with _results so
        # it can't grow without bound over a long-running deployment. The
        # action we just stored (and any other still in _results) keeps its
        # lock; the same single-instance in-memory bound already accepted for
        # _results applies (an in-flight distinct action not yet stored would
        # only be affected past RESULT_MAP_MAX concurrent distinct actions,
        # unreachable under Tier 3's rate limit + mandate gating).
        for key in [k for k in _action_locks if k not in _results]:
            del _action_locks[key]
    return body


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/internal/actions")
def execute_action(envelope: ActionEnvelope, x_agent_token: str | None = Header(default=None)):
    _require_agent_token(x_agent_token)

    # Payload validation first: cheap, no side effects, and a 422 must not
    # create a per-action lock entry.
    try:
        payload = OrderPayload(**envelope.payload)
    except Exception:
        raise HTTPException(status_code=422, detail="invalid payload for order.place")

    # The idempotency check AND the execution live inside the per-action
    # lock, so a retry of the same action_id can never dispatch a second
    # time (see the lock's definition above for the double-execution bug
    # this closes). Distinct action_ids take distinct locks and run fully
    # concurrently.
    with _action_lock(envelope.action_id):
        existing = _results.get(envelope.action_id)
        if existing is not None:
            return existing
        return _store_result(envelope.action_id, _decide_and_execute(envelope, payload))


def _decide_and_execute(envelope: ActionEnvelope, payload: OrderPayload) -> dict:
    """Routing (rules first, LLM only where a rule delegates) + channel
    dispatch + decision-log write. Called only while holding the action's
    lock, so it runs at most once per action_id."""
    decision = rules.evaluate(envelope.action_type, payload.amount_cents)
    decided_by = "rules"
    channel: str | None = None
    llm_prompt: str | None = None
    llm_raw: str | None = None

    if decision == "llm" and not llm.is_configured():
        # This deployment has no LLM at all (the dev-stack default). The
        # rule may name a deterministic fallback for exactly this case; if
        # it doesn't, channel stays None and the action fails as before.
        # Attacker-unreachable: whether a model is configured is fixed at
        # boot, so this branch cannot be entered by derailing anything --
        # which is why it does NOT apply to a configured LLM that answers
        # unusably (see rules.py's docstring).
        channel = rules.fallback_channel(envelope.action_type, payload.amount_cents)
    elif decision == "llm":
        # The LLM's ONLY authority: pick one channel from the allowlist.
        # Anything unusable (unreachable, unparseable output, a channel not
        # in the list) comes back as None -- and None here means FAIL, never
        # a guessed default and never the fallback above (see docstring).
        outcome = llm.choose_channel(
            item=payload.item,
            quantity=payload.quantity,
            amount_cents=payload.amount_cents,
            allowed_channels=rules.allowed_channels(),
        )
        llm_prompt = outcome.prompt
        llm_raw = outcome.raw_text
        if outcome.channel is not None:
            channel = outcome.channel
            decided_by = "llm"
    elif decision is not None:
        channel = decision

    if channel is None:
        body = {
            "action_id": envelope.action_id,
            "status": "failed",
            "channel": None,
            "decided_by": None,
            "reference": None,
            "detail": "no routing rule matched and no usable LLM decision -- refused, not guessed",
        }
        _log_decision(
            {
                "at": time.time(),
                "action_id": envelope.action_id,
                "client_id": envelope.client_id,
                "item": payload.item,
                "amount_cents": payload.amount_cents,
                "mode": envelope.mandate.mode,
                "decided_by": None,
                "channel": None,
                "executed": False,
                "detail": "no rule matched; no usable LLM decision",
                "llm_prompt": llm_prompt,
                "llm_raw": llm_raw,
            }
        )
        return body

    executed, reference = channels.execute(
        channel,
        action_id=envelope.action_id,
        client_id=envelope.client_id,
        item=payload.item,
        quantity=payload.quantity,
        amount_cents=payload.amount_cents,
    )

    if not executed:
        body = {
            "action_id": envelope.action_id,
            "status": "failed",
            "channel": channel,
            "decided_by": decided_by,
            "reference": None,
            "detail": f"channel {channel} did not accept the action",
        }
    else:
        body = {
            "action_id": envelope.action_id,
            "status": "executed",
            "channel": channel,
            "decided_by": decided_by,
            "reference": reference,
            "detail": (
                "Executed against an illustrative stub channel -- no real ERP/Slack/email "
                "is connected (see ARCHITECTURE.md)."
            ),
        }

    _log_decision(
        {
            "at": time.time(),
            "action_id": envelope.action_id,
            "client_id": envelope.client_id,
            "item": payload.item,
            "amount_cents": payload.amount_cents,
            "mode": envelope.mandate.mode,
            "decided_by": decided_by,
            "channel": channel,
            "executed": executed,
            "detail": body["detail"],
            "llm_prompt": llm_prompt,
            "llm_raw": llm_raw,
        }
    )
    return body


@app.get("/internal/status")
def status(x_agent_status_token: str | None = Header(default=None)):
    """Read-only observability for the admin UI. The decision log includes
    the LLM prompt and raw output per decision -- that raw output is
    caller-influenced text and is rendered ESCAPED and labeled untrusted by
    the admin page; it never reaches any caller-facing response or audit
    reason (see verify's _settle_handoff)."""
    _require_status_token(x_agent_status_token)
    return {
        "rules": rules.summary(),
        "llm": llm.summary(),
        "decisions": list(reversed(_decision_log)),
    }
