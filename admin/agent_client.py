"""Read-only client for the internal agent's /internal/status endpoint.
Same shape as tier1_client.py/tier3_client.py: stdlib urllib only, a result
dataclass, never raises.

Authenticated with AGENT_STATUS_TOKEN -- a THIRD secret, deliberately not
ADMIN_INTERNAL_TOKEN: the agent must never hold a token verify accepts
(compromise of the component that ingests attacker-influenced text must
yield no authority over grants/approvals/audit), and the admin UI must be
structurally unable to invoke the agent's execution endpoint, which only
verify's AGENT_INTERNAL_TOKEN unlocks.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

AGENT_BASE_URL = os.environ.get("AGENT_BASE_URL", "http://agent:8010")
# Fail closed at import, same pattern as tier1_client's ADMIN_INTERNAL_TOKEN:
# a missing value would otherwise mean every status call 403s with no clue why.
AGENT_STATUS_TOKEN = os.environ.get("AGENT_STATUS_TOKEN", "")
if not AGENT_STATUS_TOKEN:
    raise RuntimeError("AGENT_STATUS_TOKEN must be set (see .env.example)")


@dataclass
class AgentStatusResult:
    ok: bool
    rules: dict | None = None
    llm: dict | None = None
    decisions: list[dict] | None = None
    error: str | None = None


def get_status() -> AgentStatusResult:
    try:
        req = urllib.request.Request(
            f"{AGENT_BASE_URL}/internal/status",
            headers={"X-Agent-Status-Token": AGENT_STATUS_TOKEN},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, body = exc.code, exc.read()
    except Exception:
        return AgentStatusResult(ok=False, error="could not reach the internal agent")

    if status != 200:
        return AgentStatusResult(ok=False, error=f"the internal agent returned HTTP {status}")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return AgentStatusResult(ok=False, error="the internal agent returned an unparseable status")
    return AgentStatusResult(
        ok=True,
        rules=parsed.get("rules"),
        llm=parsed.get("llm"),
        decisions=parsed.get("decisions", []),
    )
