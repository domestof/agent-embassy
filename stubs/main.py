"""Illustrative execution-channel stubs (see ARCHITECTURE.md).

Three endpoints shaped like the three kinds of internal destination the
privileged internal agent can route a Tier 3 action to -- an ERP order API,
a Slack-style incoming webhook, and an email send -- so the agent's routing
demo crosses a REAL network boundary and leaves an inspectable delivery
record, without pretending any real system exists. Every response says so
explicitly (the same posture as static/catalog/order-status.json).

No auth, deliberately: this container has no published host port and no
real-world side effects; its only callers are the internal agent (writes)
and the test suite / smoke test reading /deliveries to prove a routed
action genuinely arrived somewhere. A real channel would obviously
authenticate -- that's part of what makes these stubs, not products.
"""
from __future__ import annotations

import time

from fastapi import FastAPI
from pydantic import BaseModel, Field

DISCLAIMER = (
    "Illustrative stub -- no real ERP/Slack/email is connected "
    "(see ARCHITECTURE.md)."
)
_DELIVERIES_MAX = 500

app = FastAPI(title="agent-embassy-channel-stubs", docs_url=None, redoc_url=None, openapi_url=None)

_deliveries: list[dict] = []  # newest last; bounded


def _record(channel: str, reference: str, payload: dict) -> None:
    _deliveries.append({"at": time.time(), "channel": channel, "reference": reference, "payload": payload})
    if len(_deliveries) > _DELIVERIES_MAX:
        del _deliveries[: len(_deliveries) - _DELIVERIES_MAX]


class ErpOrder(BaseModel):
    action_id: str = Field(min_length=1, max_length=64)
    client_id: str = Field(min_length=1, max_length=200)
    item: str = Field(min_length=1, max_length=200)
    quantity: int = Field(gt=0, le=10_000)
    amount_cents: int = Field(gt=0, le=1_000_000)


class SlackMessage(BaseModel):
    action_id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=2000)


class Email(BaseModel):
    action_id: str = Field(min_length=1, max_length=64)
    to: str = Field(min_length=1, max_length=200)
    subject: str = Field(min_length=1, max_length=500)
    body: str = Field(min_length=1, max_length=5000)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/mock-erp/orders")
def mock_erp_order(order: ErpOrder):
    reference = f"ERP-{int(time.time())}-{order.action_id[-8:]}"
    _record("mock_erp", reference, order.model_dump())
    return {"reference": reference, "disclaimer": DISCLAIMER}


@app.post("/slack/webhook")
def slack_webhook(message: SlackMessage):
    reference = f"SLACK-{int(time.time())}-{message.action_id[-8:]}"
    _record("slack_stub", reference, message.model_dump())
    return {"reference": reference, "disclaimer": DISCLAIMER}


@app.post("/email/send")
def email_send(email: Email):
    reference = f"EMAIL-{int(time.time())}-{email.action_id[-8:]}"
    _record("email_stub", reference, email.model_dump())
    return {"reference": reference, "disclaimer": DISCLAIMER}


@app.get("/deliveries")
def deliveries():
    return {"disclaimer": DISCLAIMER, "entries": list(reversed(_deliveries))}
