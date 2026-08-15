"""Routing rules for the internal agent -- the human-edited, deterministic
first stage of every decision (LLM only where a rule explicitly says so).

rules.json shape:

    {
      "allowed_channels": ["mock_erp", "slack_stub", "email_stub"],
      "rules": [
        {"action_type": "order.place", "max_amount_cents": 20000, "channel": "mock_erp"},
        {"action_type": "order.place", "channel": "llm", "fallback_channel": "mock_erp"}
      ]
    }

First-match evaluation, top to bottom. A rule's "channel" is either a name
from allowed_channels or the literal "llm" (delegate this case to the LLM,
which may itself only pick from allowed_channels). No match at all returns
None, which the caller treats as FAILED -- there is deliberately no implicit
default channel; a deployment wanting a catch-all writes it as an explicit
last rule, so every possible path through routing is visible in this file.

An "llm" rule MAY carry "fallback_channel": the channel to use when this
deployment has NO LLM configured at all (AGENT_LLM_MODEL unset -- the
dev-stack default, so the whole stack runs with zero provider keys). This
exists because the invariant above was not actually being met: with a bare
{"channel": "llm"} catch-all and no model configured, the path every order
over the first rule's ceiling took was "fail", and that path appeared
nowhere in this file. Now it does.

It is deliberately NOT a fallback for a configured LLM that returns nothing
usable (unreachable, derailed by prompt injection, unparseable output, a
channel outside the allowlist). Those still FAIL, exactly as before -- the
plan-stage adversarial review's reasoning stands: a fallback reachable by
derailing the LLM would let an attacker choose the channel, which is far
easier than forcing a specific output. Whether a model is configured is a
boot-time deployment fact that no caller can influence, so this branch is
not attacker-reachable.

Validated at import: unknown channels or a malformed file fail the boot,
loudly, rather than failing per-action at runtime.
"""
from __future__ import annotations

import json
import os

RULES_PATH = os.environ.get("RULES_PATH", os.path.join(os.path.dirname(__file__), "rules.json"))

with open(RULES_PATH, encoding="utf-8") as f:
    _config = json.load(f)

_ALLOWED: list[str] = _config.get("allowed_channels", [])
_RULES: list[dict] = _config.get("rules", [])

if not _ALLOWED or not all(isinstance(c, str) and c for c in _ALLOWED):
    raise RuntimeError(f"{RULES_PATH}: allowed_channels must be a non-empty list of channel names")
for i, rule in enumerate(_RULES):
    if rule.get("channel") not in [*_ALLOWED, "llm"]:
        raise RuntimeError(
            f"{RULES_PATH}: rules[{i}].channel {rule.get('channel')!r} is not in allowed_channels or 'llm'"
        )
    if not isinstance(rule.get("action_type"), str):
        raise RuntimeError(f"{RULES_PATH}: rules[{i}].action_type must be a string")
    if "max_amount_cents" in rule and not isinstance(rule["max_amount_cents"], int):
        raise RuntimeError(f"{RULES_PATH}: rules[{i}].max_amount_cents must be an integer")
    if "fallback_channel" in rule:
        # Must be a real channel (never "llm" -- that would be circular) and
        # only meaningful on a rule that actually delegates to the LLM.
        if rule["fallback_channel"] not in _ALLOWED:
            raise RuntimeError(
                f"{RULES_PATH}: rules[{i}].fallback_channel {rule['fallback_channel']!r} is not in allowed_channels"
            )
        if rule.get("channel") != "llm":
            raise RuntimeError(
                f"{RULES_PATH}: rules[{i}].fallback_channel is only valid on a rule with channel 'llm'"
            )


def allowed_channels() -> list[str]:
    return list(_ALLOWED)


def _match(action_type: str, amount_cents: int) -> dict | None:
    """First matching rule, top to bottom, or None."""
    for rule in _RULES:
        if rule["action_type"] != action_type:
            continue
        if "max_amount_cents" in rule and amount_cents > rule["max_amount_cents"]:
            continue
        return rule
    return None


def evaluate(action_type: str, amount_cents: int) -> str | None:
    """First matching rule's channel, "llm", or None (no match -> fail)."""
    rule = _match(action_type, amount_cents)
    return None if rule is None else rule["channel"]


def fallback_channel(action_type: str, amount_cents: int) -> str | None:
    """The matching rule's fallback_channel, if it declared one.

    Consulted by the caller ONLY when the rule delegates to the LLM and this
    deployment has no LLM configured -- never as a rescue for a configured
    LLM that answered unusably (see module docstring)."""
    rule = _match(action_type, amount_cents)
    return None if rule is None else rule.get("fallback_channel")


def summary() -> dict:
    """For the admin status page -- the rules as loaded, verbatim (they are
    operator-authored config, not caller-influenced text)."""
    return {"path": RULES_PATH, "allowed_channels": list(_ALLOWED), "rules": list(_RULES)}
