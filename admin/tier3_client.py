"""Client for verify's Tier 3 endpoints (weekly-limit grants + audit trail).
Same shape as tier1_client.py: stdlib urllib only, a result dataclass per
operation, never raises.

Grants set through this module apply immediately in the running verify
process and are NOT persisted -- same "hot-reload, not persisted" tradeoff
as Tier 1's config (see templates/tier1_config.html), and for the same
reason: this is a feasibility demo against a mock connector, not a system
of record.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from tier1_client import ADMIN_INTERNAL_TOKEN, VERIFY_BASE_URL

_GRANTS_URL = f"{VERIFY_BASE_URL}/tier3/admin-grants"
_AUDIT_URL = f"{VERIFY_BASE_URL}/tier3/admin-audit"
_APPROVALS_URL = f"{VERIFY_BASE_URL}/tier3/admin-approvals"

# Approve/reject deliberately do NOT use this module's 5s convention:
# verify's approve endpoint synchronously performs the internal-agent
# handoff (up to 2 x 10s attempts, see verify/agent_handoff.py) before
# answering. A 5s client timeout here would report "could not reach verify"
# to the admin WHILE the action executes and the budget is consumed --
# then a natural retry-click would 404 confusingly (found at plan review).
_APPROVAL_TIMEOUT_SECONDS = 25


@dataclass
class GrantResult:
    ok: bool
    values: dict | None = None
    error: str | None = None


@dataclass
class AuditResult:
    ok: bool
    entries: list[dict] | None = None
    error: str | None = None


@dataclass
class ApprovalsResult:
    ok: bool
    entries: list[dict] | None = None
    error: str | None = None


@dataclass
class ApprovalActionResult:
    ok: bool
    outcome: dict | None = None
    error: str | None = None


def _tier3_request(method: str, url: str, body: dict | None = None, timeout: int = 5) -> tuple[int, bytes]:
    """Same contract as tier1_client._verify_request. Request(...)
    construction kept INSIDE the try block -- its constructor can itself
    raise ValueError for a malformed URL, the bug shape this repo has hit
    twice already (test_console.py, keycloak_client.py)."""
    try:
        headers = {
            "X-Admin-Token": ADMIN_INTERNAL_TOKEN,
            **({"Content-Type": "application/json"} if body is not None else {}),
        }
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, method=method, headers=headers, data=data)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return 0, b"could not reach verify"
    except Exception as exc:
        return 0, str(exc).encode()


def _grant_url(client_id: str) -> str:
    # Keycloak client IDs aren't constrained to this repo's own
    # _CLIENT_ID_RE for clients that already exist -- an unescaped "/" would
    # silently route to the wrong path segment.
    return f"{_GRANTS_URL}/{urllib.parse.quote(client_id, safe='')}"


def _parse_grant(status: int, body: bytes, verb: str) -> GrantResult:
    if status != 200:
        return GrantResult(ok=False, error=f"verify returned HTTP {status} {verb} the Tier 3 grant")
    try:
        values = json.loads(body)
    except json.JSONDecodeError:
        return GrantResult(ok=False, error="verify returned an unparseable Tier 3 grant")
    return GrantResult(ok=True, values=values)


def get_grant(client_id: str) -> GrantResult:
    status, body = _tier3_request("GET", _grant_url(client_id))
    return _parse_grant(status, body, "fetching")


def set_grant(client_id: str, weekly_limit_cents: int) -> GrantResult:
    status, body = _tier3_request("PUT", _grant_url(client_id), {"weekly_limit_cents": weekly_limit_cents})
    if status == 422:
        return GrantResult(ok=False, error="the weekly limit is out of the allowed range")
    return _parse_grant(status, body, "setting")


def revoke_grant(client_id: str) -> GrantResult:
    status, body = _tier3_request("DELETE", _grant_url(client_id))
    return _parse_grant(status, body, "revoking")


def list_audit() -> AuditResult:
    status, body = _tier3_request("GET", _AUDIT_URL)
    if status != 200:
        return AuditResult(ok=False, error=f"verify returned HTTP {status} fetching the Tier 3 audit log")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return AuditResult(ok=False, error="verify returned an unparseable Tier 3 audit log")
    return AuditResult(ok=True, entries=parsed.get("entries", []))


def list_pending() -> ApprovalsResult:
    status, body = _tier3_request("GET", _APPROVALS_URL)
    if status != 200:
        return ApprovalsResult(ok=False, error=f"verify returned HTTP {status} fetching pending approvals")
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        return ApprovalsResult(ok=False, error="verify returned an unparseable pending-approvals list")
    return ApprovalsResult(ok=True, entries=parsed.get("entries", []))


def _approval_action(action_id: str, verb: str) -> ApprovalActionResult:
    url = f"{_APPROVALS_URL}/{urllib.parse.quote(action_id, safe='')}/{verb}"
    status, body = _tier3_request("POST", url, timeout=_APPROVAL_TIMEOUT_SECONDS)
    if status == 404:
        return ApprovalActionResult(ok=False, error="that action is no longer pending (expired, or already decided)")
    if status == 409:
        return ApprovalActionResult(
            ok=False, error="this client's mandate was revoked while the action was pending -- not executed"
        )
    if status == 503:
        return ApprovalActionResult(
            ok=False,
            error=(
                "the internal agent is unavailable -- the action was NOT executed and the budget was "
                "not consumed. The request is resolved as failed (no longer pending); the partner can resubmit"
            ),
        )
    if status == 502:
        # Two distinct 502s from verify: agent answered "failed" (budget
        # released) or handoff timed out (budget consumed, execution
        # unknown). Surface verify's own detail string, which says which.
        try:
            detail = json.loads(body).get("detail", "")
        except json.JSONDecodeError:
            detail = ""
        return ApprovalActionResult(ok=False, error=detail or "the internal agent could not execute the action")
    if status != 200:
        return ApprovalActionResult(ok=False, error=f"verify returned HTTP {status} on {verb}")
    try:
        outcome = json.loads(body)
    except json.JSONDecodeError:
        return ApprovalActionResult(ok=False, error="verify returned an unparseable approval outcome")
    return ApprovalActionResult(ok=True, outcome=outcome)


def approve_action(action_id: str) -> ApprovalActionResult:
    return _approval_action(action_id, "approve")


def reject_action(action_id: str) -> ApprovalActionResult:
    return _approval_action(action_id, "reject")
