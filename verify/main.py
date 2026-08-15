"""Tier 1 identity verification: domain-challenge, no Keycloak.

Proves control of a domain at request time (comparable to single-vantage-
point HTTP-01 domain validation — see the Tier 1 plan for why this is an
explicitly weaker claim than a CA/Browser-Forum-grade DV certificate, which
since 2025 requires multi-perspective corroboration this single-server MVP
does not attempt). It does not prove legal company identity; that's left to
Tier 2's bilateral OAuth2+mTLS agreement.

Public endpoints:
- POST /tier1/challenge  — requester claims a domain, gets a token to publish
- POST /tier1/verify     — requester asks us to check; issues a session token
- GET  /tier1/check      — nginx `auth_request` target gating Tier 1 resources

Internal-only (no published host port, plus a shared-secret header — see
require_internal_admin): GET/PUT /tier1/admin-config, the admin UI's hook for
hot-reloading (not persisting) the TTLs/rate limits above.
"""
from __future__ import annotations

import os
import secrets
import threading
import time
from dataclasses import dataclass

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from agent_handoff import HandoffResult, execute_handoff
from introspection import introspect_access_token
from keycloak_auth import InvalidToken, validate_access_token
from security import InvalidDomain, fetch_challenge_file, validate_domain

# ADMIN_INTERNAL_TOKEN gates the /tier1/admin-config endpoints below (admin
# UI -> verify, over the internal Docker network only — see
# require_internal_admin). Fail closed at import, same reasoning as
# admin/keycloak_client.py's KEYCLOAK_ADMIN_USERNAME/PASSWORD check: a
# missing value would otherwise mean every admin-config call 403s with no
# clue why.
ADMIN_INTERNAL_TOKEN = os.environ.get("ADMIN_INTERNAL_TOKEN", "")
if not ADMIN_INTERNAL_TOKEN:
    raise RuntimeError("ADMIN_INTERNAL_TOKEN must be set (see .env.example)")


@dataclass
class Tier3Event:
    """One row of Tier 3's audit trail -- deliberately the single source of
    truth for both "what happened" (admin/tier3-audit) and "how much of the
    weekly budget is used" (Store.tier3_used_cents sums accepted events in
    the trailing window), instead of a separate usage ledger. Only accepted
    events count toward usage; rejected attempts (over limit, no grant,
    revoked/expired token, failed mTLS) are still recorded here -- Tier 3's
    spec row requires "immediate audit" of everything, not just successes."""

    at: float
    client_id: str
    item: str
    amount_cents: int
    outcome: str  # "accepted", "rejected", "queued", or "expired"
    reason: str
    order_number: str | None = None
    action_id: str | None = None


@dataclass
class Tier3PendingAction:
    """One out-of-mandate action awaiting explicit human approval (spec
    section 4's two-mode model). Lives only until approved, rejected, or
    TTL-expired -- in-memory like everything else in Store, and the admin
    UI states that restart-loss plainly."""

    action_id: str
    client_id: str
    item: str
    quantity: int
    amount_cents: int
    queued_at: float
    expires_at: float


@dataclass
class Tier3Resolution:
    """The pollable fate of one action_id, written for BOTH modes and every
    terminal state -- deliberately NOT derived from the audit trail, which is
    pruned by window/cap and so would make a valid action_id start 404ing
    (found at plan review). This map is the poll endpoint's single source of
    truth."""

    action_id: str
    client_id: str
    status: str  # queued | executed | failed | rejected | expired | execution_unknown
    detail: str
    created_at: float
    updated_at: float
    channel: str | None = None
    order_number: str | None = None


class Store:
    """In-memory state. Single-instance MVP scope: does not survive restarts
    and does not coordinate across multiple verify replicas. Acceptable at
    this project's current scale (see Tier 1 plan); revisit with a shared
    store (e.g. Redis) if the verify service is ever run with >1 replica.
    Tier 3's grants/audit trail share this same accepted tradeoff -- a
    restart clears both, same as Tier 1's config hot-reload.

    Also holds Tier 1's tuning config (TTLs, rate limits) as live-mutable
    attributes, seeded from env vars at startup. This makes the admin UI's
    /tier1/admin-config endpoint a small addition rather than new
    infrastructure: check_rate_limit already took its limits as call-time
    parameters, so only the two TTL methods needed to move from reading
    module constants to reading self.* here. A value changed via that
    endpoint is NOT persisted — it lives only in this process's memory, same
    as challenges/sessions, and reverts to the env var default on restart."""

    def __init__(self) -> None:
        self.challenges: dict[str, tuple[str, float]] = {}  # domain -> (token, expires_at)
        self.sessions: dict[str, tuple[str, float]] = {}  # session_token -> (domain, expires_at)
        self.rate_limit_hits: dict[str, list[float]] = {}  # client_ip -> [timestamps]
        self.challenge_ttl_seconds = int(os.environ.get("CHALLENGE_TTL_SECONDS", "300"))
        self.session_ttl_seconds = int(os.environ.get("SESSION_TTL_SECONDS", "3600"))
        self.challenge_rate_limit_max = int(os.environ.get("CHALLENGE_RATE_LIMIT_MAX", "10"))
        self.challenge_rate_limit_window = int(os.environ.get("CHALLENGE_RATE_LIMIT_WINDOW", "60"))
        # /tier1/verify triggers a real outbound SSRF-guarded fetch per call.
        # Without its own limit, one rate-limited challenge could be followed
        # by unlimited verify calls for its TTL, using this service as a
        # repeat proxy toward an external target. Separate bucket from the
        # challenge limit so the two endpoints don't share (and starve) one
        # budget.
        self.verify_rate_limit_max = int(os.environ.get("VERIFY_RATE_LIMIT_MAX", "10"))
        self.verify_rate_limit_window = int(os.environ.get("VERIFY_RATE_LIMIT_WINDOW", "60"))

        # Tier 3: client_id -> weekly limit in cents, set by admin via
        # /tier3/admin-grants. Absent/None means no Tier 3 access at all.
        self.tier3_grants: dict[str, int] = {}
        self.tier3_events: list[Tier3Event] = []
        self.tier3_window_seconds = int(os.environ.get("TIER3_WINDOW_SECONDS", "604800"))
        # Hard cap on stored events PER client_id (see record_tier3_event),
        # independent of the age-based prune. Documented tradeoff: if a
        # single client hits this cap, their own oldest events drop out of
        # both the audit view AND their own usage sum, understating their
        # usage rather than overstating it (fails open on their own limit,
        # not closed). This is NOT a volume this demo can't reach: at the
        # default TIER3_RATE_LIMIT_MAX=10 per TIER3_RATE_LIMIT_WINDOW=60s
        # (keyed on client_ip, see tier3_rate_limit_max below), one client
        # reaches 500 accepted events in under an hour of steady ordering --
        # a real, near-term exposure, not a theoretical one, and worth
        # revisiting (e.g. raising the default, or a warning in the admin
        # UI once a client's audit window is more than half-used) before a
        # real pilot generates that kind of steady order volume. Deliberately
        # per-client, not a single global cap: an earlier global-cap version let one client
        # with no grant at all evict a DIFFERENT client's real accepted
        # orders out of the buffer once the shared cap was hit, found live
        # during adversarial review -- see record_tier3_event's docstring.
        self.tier3_audit_max = int(os.environ.get("TIER3_AUDIT_MAX", "500"))
        # /tier3/orders calls out to Keycloak's real introspection endpoint
        # on every request -- a separate, dedicated bucket from Tier 1's
        # verify_rate_limit_max/window above, on purpose: reusing that pair
        # was tried first and confirmed live during adversarial review to be
        # a hidden coupling -- an admin raising Tier 1's "Verify rate limit"
        # on /tier1-config (with no reason to think it touches Tier 3 at
        # all) silently loosened /tier3/orders' protection against
        # hammering Keycloak too. Not exposed on the Tier 1 admin-config
        # endpoint or page for the same reason.
        self.tier3_rate_limit_max = int(os.environ.get("TIER3_RATE_LIMIT_MAX", "10"))
        self.tier3_rate_limit_window = int(os.environ.get("TIER3_RATE_LIMIT_WINDOW", "60"))

        # Serializes the budget check + reservation in /tier3/orders (and
        # approval). Before the internal-agent handoff existed, the
        # check-then-record window was a handful of statements; the handoff
        # widened it to a multi-second network call, so without this lock N
        # concurrent requests each sized at the full remaining budget would
        # ALL pass the check and ALL execute (the per-IP rate limit does not
        # bound this: budget is per client_id, and one credential can arrive
        # from many IPs). Found at plan-stage adversarial review, before any
        # code -- hence reserve-then-settle: reserve budget under this lock
        # BEFORE the handoff, settle (confirm/release) after.
        self.tier3_lock = threading.Lock()

        # Out-of-mandate actions awaiting human approval. TTL defaults to
        # the mandate window itself (not an independent constant) so an
        # admin changing TIER3_WINDOW_SECONDS can't silently decouple the
        # two. Per-client cap bounds the human-attention cost: the queue's
        # total size is at most cap x (number of grants), and grants are
        # exclusively human-created via the admin UI.
        self.tier3_pending: dict[str, Tier3PendingAction] = {}
        self.tier3_pending_ttl_seconds = (
            int(os.environ.get("TIER3_PENDING_TTL_SECONDS", "0")) or self.tier3_window_seconds
        )
        self.tier3_pending_max_per_client = int(os.environ.get("TIER3_PENDING_MAX_PER_CLIENT", "10"))

        # action_id -> pollable resolution, every state (see Tier3Resolution).
        # Same TTL-defaulting reasoning as the pending queue; per-client cap
        # mirrors tier3_audit_max's memory-bound posture.
        self.tier3_resolutions: dict[str, Tier3Resolution] = {}
        self.tier3_resolution_ttl_seconds = (
            int(os.environ.get("TIER3_RESOLUTION_TTL_SECONDS", "0")) or self.tier3_window_seconds
        )
        self.tier3_resolution_max_per_client = int(os.environ.get("TIER3_RESOLUTION_MAX_PER_CLIENT", "500"))

        # The poll endpoint gets its OWN bucket, never tier3_orders' -- a
        # caller polling a pending action every few seconds for days is the
        # DESIGNED behavior, and sharing the order bucket would let a client
        # 429 its own order placement by polling (or, with no limit at all,
        # make polling an unmetered amplifier at Keycloak's introspection
        # endpoint -- the same hidden-coupling bug class found twice before,
        # see tier3_rate_limit_max's comment above).
        self.tier3_poll_rate_limit_max = int(os.environ.get("TIER3_POLL_RATE_LIMIT_MAX", "60"))
        self.tier3_poll_rate_limit_window = int(os.environ.get("TIER3_POLL_RATE_LIMIT_WINDOW", "60"))

    def check_rate_limit(self, bucket: str, client_ip: str, max_requests: int, window_seconds: int) -> bool:
        now = time.time()
        key = f"{bucket}:{client_ip}"
        hits = [t for t in self.rate_limit_hits.get(key, []) if now - t < window_seconds]
        hits.append(now)
        self.rate_limit_hits[key] = hits
        return len(hits) <= max_requests

    def issue_challenge(self, domain: str) -> tuple[str, float]:
        token = secrets.token_urlsafe(32)
        expires_at = time.time() + self.challenge_ttl_seconds
        # Concurrent issuance for the same domain overwrites the pending
        # challenge (last write wins) — an accepted availability tradeoff,
        # not a security bypass: verify only ever succeeds against whichever
        # token is currently stored.
        self.challenges[domain] = (token, expires_at)
        return token, expires_at

    def get_pending_challenge(self, domain: str) -> str | None:
        entry = self.challenges.get(domain)
        if entry is None:
            return None
        token, expires_at = entry
        if time.time() > expires_at:
            del self.challenges[domain]
            return None
        return token

    def issue_session(self, domain: str) -> tuple[str, float]:
        session_token = secrets.token_urlsafe(32)
        expires_at = time.time() + self.session_ttl_seconds
        self.sessions[session_token] = (domain, expires_at)
        # The challenge is single-use: consume it so it can't be replayed
        # for a second session without a fresh challenge/publish cycle.
        self.challenges.pop(domain, None)
        return session_token, expires_at

    def check_session(self, session_token: str) -> str | None:
        entry = self.sessions.get(session_token)
        if entry is None:
            return None
        domain, expires_at = entry
        if time.time() > expires_at:
            del self.sessions[session_token]
            return None
        return domain

    def record_tier3_event(
        self,
        *,
        client_id: str,
        item: str,
        amount_cents: int,
        outcome: str,
        reason: str,
        order_number: str | None = None,
        action_id: str | None = None,
    ) -> None:
        now = time.time()
        self.tier3_events.append(
            Tier3Event(
                at=now,
                client_id=client_id,
                item=item,
                amount_cents=amount_cents,
                outcome=outcome,
                reason=reason,
                order_number=order_number,
                action_id=action_id,
            )
        )
        # Age-based prune first (keeps the list bounded under normal use
        # without ever discarding anything still inside the usage window),
        # then the hard cap as a backstop -- see tier3_audit_max's docstring.
        cutoff = now - self.tier3_window_seconds
        self.tier3_events = [e for e in self.tier3_events if e.at >= cutoff]

        # The hard cap is applied PER client_id, not as a single global
        # truncation of the whole list -- confirmed live during adversarial
        # review that a global cap is a real cross-tenant attack: a client
        # with NO Tier 3 grant at all (every rejected call still records an
        # event) could spam rejected requests until the global cap evicted a
        # COMPLETELY UNRELATED client's real accepted orders out of the
        # buffer -- erasing that victim's audit history and, since
        # tier3_used_cents only sums surviving events, silently refilling
        # their spending budget. Capping per client_id means an attacker can
        # only ever evict their own old entries, never another client's.
        # (A residual, accepted at demo scale: this doesn't bound memory
        # across an unbounded number of distinct client_ids -- but each one
        # requires a real Tier 2 Keycloak credential + valid mTLS cert to
        # reach this endpoint at all, a much higher bar than the bug above.)
        per_client_count: dict[str, int] = {}
        kept: list[Tier3Event] = []
        for event in reversed(self.tier3_events):
            per_client_count[event.client_id] = per_client_count.get(event.client_id, 0) + 1
            if per_client_count[event.client_id] <= self.tier3_audit_max:
                kept.append(event)
        kept.reverse()
        self.tier3_events = kept

    def tier3_used_cents(self, client_id: str) -> int:
        # Filters by the window independently of record_tier3_event's own
        # prune, which only runs on writes -- correctness lives here, the
        # prune above is purely a memory-bound, not the source of truth.
        cutoff = time.time() - self.tier3_window_seconds
        return sum(
            e.amount_cents
            for e in self.tier3_events
            if e.client_id == client_id and e.outcome == "accepted" and e.at >= cutoff
        )

    def settle_tier3_event(
        self,
        action_id: str,
        *,
        outcome: str,
        reason: str,
        order_number: str | None = None,
    ) -> None:
        """Reserve-then-settle's second half: mutate the reservation event
        recorded before the handoff. Settling to "rejected" releases the
        budget (tier3_used_cents only sums accepted events); leaving it
        "accepted" keeps it consumed. Searches newest-first -- action_ids
        are unique, so first match is the only match."""
        for event in reversed(self.tier3_events):
            if event.action_id == action_id:
                event.outcome = outcome
                event.reason = reason
                if order_number is not None:
                    event.order_number = order_number
                return

    def prune_tier3_pending(self) -> None:
        """Lazy TTL expiry for the approval queue, same pattern as
        challenges/sessions. Runs BEFORE the per-client cap check in the
        order handler (an expired entry must never block a new queue slot)
        and before every admin list/approve/reject. Each expiry is audited
        and resolved so the caller's poll sees "expired", not a 404."""
        now = time.time()
        for action_id in [a.action_id for a in self.tier3_pending.values() if now > a.expires_at]:
            action = self.tier3_pending.pop(action_id)
            self.record_tier3_event(
                client_id=action.client_id,
                item=action.item,
                amount_cents=action.amount_cents,
                outcome="expired",
                reason="pending approval expired before a human decided",
                action_id=action_id,
            )
            self.set_tier3_resolution(
                action_id,
                action.client_id,
                status="expired",
                detail="pending approval expired before a human decided",
            )

    def queue_tier3_action(self, action_id: str, client_id: str, item: str, quantity: int, amount_cents: int) -> Tier3PendingAction:
        now = time.time()
        action = Tier3PendingAction(
            action_id=action_id,
            client_id=client_id,
            item=item,
            quantity=quantity,
            amount_cents=amount_cents,
            queued_at=now,
            expires_at=now + self.tier3_pending_ttl_seconds,
        )
        self.tier3_pending[action_id] = action
        return action

    def set_tier3_resolution(
        self,
        action_id: str,
        client_id: str,
        *,
        status: str,
        detail: str,
        channel: str | None = None,
        order_number: str | None = None,
    ) -> None:
        now = time.time()
        existing = self.tier3_resolutions.get(action_id)
        if existing is not None:
            existing.status = status
            existing.detail = detail
            existing.updated_at = now
            if channel is not None:
                existing.channel = channel
            if order_number is not None:
                existing.order_number = order_number
            return
        self.tier3_resolutions[action_id] = Tier3Resolution(
            action_id=action_id,
            client_id=client_id,
            status=status,
            detail=detail,
            created_at=now,
            updated_at=now,
            channel=channel,
            order_number=order_number,
        )
        # TTL prune + per-client cap (oldest evicted first), same
        # memory-bound posture as record_tier3_event's audit cap.
        cutoff = now - self.tier3_resolution_ttl_seconds
        self.tier3_resolutions = {k: r for k, r in self.tier3_resolutions.items() if r.updated_at >= cutoff}
        per_client: dict[str, int] = {}
        kept: dict[str, Tier3Resolution] = {}
        for key in reversed(list(self.tier3_resolutions)):
            resolution = self.tier3_resolutions[key]
            per_client[resolution.client_id] = per_client.get(resolution.client_id, 0) + 1
            if per_client[resolution.client_id] <= self.tier3_resolution_max_per_client:
                kept[key] = resolution
        self.tier3_resolutions = dict(reversed(list(kept.items())))

    def get_tier3_resolution(self, action_id: str) -> Tier3Resolution | None:
        resolution = self.tier3_resolutions.get(action_id)
        if resolution is None:
            return None
        if time.time() - resolution.updated_at > self.tier3_resolution_ttl_seconds:
            del self.tier3_resolutions[action_id]
            return None
        return resolution


store = Store()
app = FastAPI(title="agent-embassy-verify")


@app.get("/health")
def health():
    return {"status": "ok"}


class ChallengeRequest(BaseModel):
    domain: str


class VerifyRequest(BaseModel):
    domain: str


def require_internal_admin(x_admin_token: str | None = Header(default=None)) -> None:
    """Gates /tier1/admin-config. verify has no published host port (see
    docker-compose.yml), so this is only ever reachable from other
    containers on the internal Docker network — but unlike /tier2/check,
    that alone isn't the whole trust model here: this endpoint mutates
    rate limits/TTLs for every Tier 1 caller, a more consequential surface
    than a per-client check, so it also requires a shared secret only
    `admin` holds. secrets.compare_digest avoids a timing side-channel on
    the comparison."""
    if not x_admin_token or not secrets.compare_digest(x_admin_token, ADMIN_INTERNAL_TOKEN):
        raise HTTPException(status_code=403, detail="forbidden")


class Tier1ConfigUpdate(BaseModel):
    # Bounds exist so a typo can't zero out or effectively disable a
    # protection (e.g. a TTL of 0 or a rate limit window of 0) — not because
    # any particular bound is itself load-bearing.
    challenge_ttl_seconds: int = Field(gt=0, le=86400)
    session_ttl_seconds: int = Field(gt=0, le=86400)
    challenge_rate_limit_max: int = Field(gt=0, le=10000)
    challenge_rate_limit_window: int = Field(gt=0, le=3600)
    verify_rate_limit_max: int = Field(gt=0, le=10000)
    verify_rate_limit_window: int = Field(gt=0, le=3600)


def _client_ip(request: Request) -> str:
    """The two public Tier 1 endpoints below are reachable ONLY through
    nginx's reverse proxy (verify has no published host port -- see
    docker-compose.yml) or another container on the same docker network, so
    trusting an X-Forwarded-For nginx itself sets is the same trust model
    already accepted for /tier2/check's X-SSL-Client-Verify header. Without
    this, request.client.host is always nginx's own container IP for every
    external caller -- confirmed live during adversarial review -- which
    collapses the per-client rate limit into one shared bucket for every
    caller (trivial single-attacker DoS of the shared budget). nginx sets
    this header to $remote_addr (not $proxy_add_x_forwarded_for), so it
    always reflects nginx's own view of the direct TCP peer, not something
    a client can override by sending its own X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.strip()
    return request.client.host if request.client else "unknown"


@app.post("/tier1/challenge")
def create_challenge(body: ChallengeRequest, request: Request):
    client_ip = _client_ip(request)
    if not store.check_rate_limit(
        "challenge", client_ip, store.challenge_rate_limit_max, store.challenge_rate_limit_window
    ):
        raise HTTPException(status_code=429, detail="too many challenge requests, slow down")

    try:
        domain = validate_domain(body.domain)
    except InvalidDomain as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    token, expires_at = store.issue_challenge(domain)
    return {
        "domain": domain,
        "token": token,
        "well_known_path": "/.well-known/agent-embassy-challenge.txt",
        "expires_in": store.challenge_ttl_seconds,
        "expires_at": expires_at,
    }


@app.post("/tier1/verify")
def verify_challenge(body: VerifyRequest, request: Request):
    client_ip = _client_ip(request)
    if not store.check_rate_limit("verify", client_ip, store.verify_rate_limit_max, store.verify_rate_limit_window):
        raise HTTPException(status_code=429, detail="too many verify requests, slow down")

    try:
        domain = validate_domain(body.domain)
    except InvalidDomain as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    expected_token = store.get_pending_challenge(domain)
    if expected_token is None:
        raise HTTPException(status_code=404, detail="no pending challenge for this domain, or it expired")

    try:
        status, response_body = fetch_challenge_file(domain)
    except Exception:
        # Never leak *why* the fetch failed (DNS error, TLS error, refused
        # SSRF target, timeout, ...) — all collapse to the same generic
        # failure from the caller's point of view.
        raise HTTPException(status_code=502, detail="could not verify domain control")

    if status != 200 or response_body.decode("utf-8", errors="replace").strip() != expected_token:
        raise HTTPException(status_code=403, detail="domain control could not be confirmed")

    session_token, expires_at = store.issue_session(domain)
    return {
        "session_token": session_token,
        "domain": domain,
        "expires_in": store.session_ttl_seconds,
        "expires_at": expires_at,
    }


@app.get("/tier1/check")
def check_session(authorization: str | None = Header(default=None)):
    """Target for nginx's `auth_request` directive. Returns 200 with the
    verified domain in a response header on success, 401 otherwise — nginx
    treats any non-2xx as denied and never serves the protected resource."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer session token")

    session_token = authorization.removeprefix("Bearer ").strip()
    domain = store.check_session(session_token)
    if domain is None:
        raise HTTPException(status_code=401, detail="invalid or expired session token")

    return Response(status_code=200, headers={"X-Verified-Domain": domain})


@app.get("/tier2/check")
def check_tier2(
    authorization: str | None = Header(default=None),
    x_ssl_client_verify: str | None = Header(default=None),
):
    """Target for nginx's `auth_request` on the Tier 2 (mTLS) listener.
    Two independent proofs are required ("OAuth2 + mTLS" — see
    ARCHITECTURE.md): (1) nginx terminated the TLS handshake and validated the client
    certificate against the configured CA — nginx sets this header itself
    from its own $ssl_client_verify computation, unreachable/unforgeable by
    a client that isn't already talking to nginx over the mTLS listener; and
    (2) a valid, unexpired Keycloak-issued access token for this service."""
    if x_ssl_client_verify != "SUCCESS":
        raise HTTPException(status_code=401, detail="client certificate not verified")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer access token")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = validate_access_token(token)
    except InvalidToken:
        raise HTTPException(status_code=401, detail="invalid or expired access token")

    return Response(status_code=200, headers={"X-Verified-Client": claims.get("azp", claims.get("sub", ""))})


def _tier1_config_dict() -> dict[str, int]:
    return {
        "challenge_ttl_seconds": store.challenge_ttl_seconds,
        "session_ttl_seconds": store.session_ttl_seconds,
        "challenge_rate_limit_max": store.challenge_rate_limit_max,
        "challenge_rate_limit_window": store.challenge_rate_limit_window,
        "verify_rate_limit_max": store.verify_rate_limit_max,
        "verify_rate_limit_window": store.verify_rate_limit_window,
    }


@app.get("/tier1/admin-config")
def get_tier1_admin_config(_: None = Depends(require_internal_admin)):
    return _tier1_config_dict()


@app.put("/tier1/admin-config")
def update_tier1_admin_config(body: Tier1ConfigUpdate, _: None = Depends(require_internal_admin)):
    # Applies immediately (this process's in-memory Store, hot-reload) and is
    # NOT persisted anywhere — a restart reverts to the env var defaults.
    # The admin UI surfaces that limitation directly rather than hiding it.
    store.challenge_ttl_seconds = body.challenge_ttl_seconds
    store.session_ttl_seconds = body.session_ttl_seconds
    store.challenge_rate_limit_max = body.challenge_rate_limit_max
    store.challenge_rate_limit_window = body.challenge_rate_limit_window
    store.verify_rate_limit_max = body.verify_rate_limit_max
    store.verify_rate_limit_window = body.verify_rate_limit_window
    return _tier1_config_dict()


class Tier3GrantUpdate(BaseModel):
    # Same "a typo can't disable a protection" reasoning as
    # Tier1ConfigUpdate's bounds -- the upper bound is arbitrary but exists
    # so a stray extra digit can't hand out a runaway budget by accident.
    weekly_limit_cents: int = Field(gt=0, le=100_000_00)


class Tier3OrderRequest(BaseModel):
    item: str = Field(min_length=1, max_length=200)
    quantity: int = Field(gt=0, le=10_000)
    amount_cents: int = Field(gt=0, le=1_000_000)


def _tier3_grant_dict(client_id: str) -> dict:
    limit = store.tier3_grants.get(client_id)
    used = store.tier3_used_cents(client_id)
    return {
        "client_id": client_id,
        "weekly_limit_cents": limit,
        "used_cents": used,
        "remaining_cents": (limit - used) if limit is not None else None,
        "window_seconds": store.tier3_window_seconds,
    }


@app.get("/tier3/admin-grants/{client_id}")
def get_tier3_grant(client_id: str, _: None = Depends(require_internal_admin)):
    return _tier3_grant_dict(client_id)


@app.put("/tier3/admin-grants/{client_id}")
def put_tier3_grant(client_id: str, body: Tier3GrantUpdate, _: None = Depends(require_internal_admin)):
    # This IS the "explicit human approval" step Tier 3 requires -- a
    # human, via the admin UI, deciding a specific partner may
    # place orders up to a specific weekly amount. Same in-memory/
    # not-persisted tradeoff as everything else in Store.
    store.tier3_grants[client_id] = body.weekly_limit_cents
    return _tier3_grant_dict(client_id)


@app.delete("/tier3/admin-grants/{client_id}")
def delete_tier3_grant(client_id: str, _: None = Depends(require_internal_admin)):
    # Revoking a mandate revokes its pending exceptions too: an entry in the
    # approval queue is an over-mandate request whose only claim to exist is
    # the (now deleted) human-authorized relationship -- leaving it approvable
    # after revocation would execute an action for a client an admin just cut
    # off (found at plan-stage adversarial review). Each purge is audited and
    # resolved so the caller's poll sees "rejected", not a 404.
    with store.tier3_lock:
        store.tier3_grants.pop(client_id, None)
        store.prune_tier3_pending()
        for action_id in [a.action_id for a in store.tier3_pending.values() if a.client_id == client_id]:
            action = store.tier3_pending.pop(action_id)
            store.record_tier3_event(
                client_id=client_id,
                item=action.item,
                amount_cents=action.amount_cents,
                outcome="rejected",
                reason="mandate revoked -- pending approval cancelled",
                action_id=action_id,
            )
            store.set_tier3_resolution(
                action_id,
                client_id,
                status="rejected",
                detail="mandate revoked -- pending approval cancelled",
            )
    return _tier3_grant_dict(client_id)


@app.get("/tier3/admin-audit")
def get_tier3_audit(_: None = Depends(require_internal_admin)):
    return {
        "entries": [
            {
                "at": e.at,
                "client_id": e.client_id,
                "item": e.item,
                "amount_cents": e.amount_cents,
                "outcome": e.outcome,
                "reason": e.reason,
                "order_number": e.order_number,
                "action_id": e.action_id,
            }
            for e in reversed(store.tier3_events)
        ]
    }


@app.post("/tier3/orders", status_code=201)
def create_tier3_order(
    body: Tier3OrderRequest,
    request: Request,
    authorization: str | None = Header(default=None),
    x_ssl_client_verify: str | None = Header(default=None),
):
    """Tier 3's mock transactional endpoint -- a fictional, illustrative
    order-placement resource (same "no real PMS/ERP connector exists"
    posture already documented on static/catalog/order-status.json),
    reachable only through nginx's mTLS :443 listener (see
    nginx/default.conf) -- never exposed on the plain :80 listener.

    Order of checks, and why each comes where it does: rate-limit first,
    because introspect_access_token() below is a real outbound call to
    Keycloak on every request -- without a limit here this endpoint would be
    an unmetered amplifier pointed at Keycloak's introspection endpoint, the
    same class of bug the last adversarial review found in Tier 1's rate
    limiter. mTLS next (cheap, no network call). Introspection third -- this
    is the whole reason Tier 3 exists instead of just reusing /tier2/check:
    it asks Keycloak's live state, so a disabled/revoked client is rejected
    immediately instead of staying valid until the token's own exp claim
    (Tier 2's accepted tradeoff, see keycloak_auth.py). Every branch past
    the mTLS check records a Tier 3 audit event, including every rejection
    reason -- "immediate audit" in the spec means the denials too, not just
    the successful orders.
    """
    client_ip = _client_ip(request)
    if not store.check_rate_limit(
        "tier3_orders", client_ip, store.tier3_rate_limit_max, store.tier3_rate_limit_window
    ):
        raise HTTPException(status_code=429, detail="too many Tier 3 order requests, slow down")

    if x_ssl_client_verify != "SUCCESS":
        store.record_tier3_event(
            client_id="unknown",
            item=body.item,
            amount_cents=body.amount_cents,
            outcome="rejected",
            reason="client certificate not verified",
        )
        raise HTTPException(status_code=401, detail="client certificate not verified")

    if not authorization or not authorization.startswith("Bearer "):
        store.record_tier3_event(
            client_id="unknown",
            item=body.item,
            amount_cents=body.amount_cents,
            outcome="rejected",
            reason="missing bearer access token",
        )
        raise HTTPException(status_code=401, detail="missing bearer access token")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = introspect_access_token(token)
    except InvalidToken:
        # The revocation path: a disabled/deleted client, or a naturally
        # expired token, fails here. client_id is genuinely unknown at this
        # point -- introspection never got far enough to say whose token it
        # was -- so this is recorded under "unknown" rather than guessed.
        store.record_tier3_event(
            client_id="unknown",
            item=body.item,
            amount_cents=body.amount_cents,
            outcome="rejected",
            reason="token rejected by introspection (revoked, disabled, or expired)",
        )
        raise HTTPException(status_code=401, detail="invalid, expired, or revoked access token")

    client_id = claims.get("client_id") or claims.get("azp") or "unknown"

    limit = store.tier3_grants.get(client_id)
    if limit is None:
        store.record_tier3_event(
            client_id=client_id,
            item=body.item,
            amount_cents=body.amount_cents,
            outcome="rejected",
            reason="no Tier 3 grant for this client",
        )
        raise HTTPException(status_code=403, detail="no Tier 3 grant for this client")

    action_id = f"act-{int(time.time())}-{secrets.token_hex(4)}"

    # Reserve-then-settle under the lock: the budget check and the
    # reservation (an "accepted" audit event, which tier3_used_cents counts
    # immediately) are atomic, so concurrent requests see each other's
    # reservations and cannot jointly exceed the mandate. The handoff itself
    # runs OUTSIDE the lock -- it's a multi-second network call and holding
    # the lock across it would serialize every Tier 3 request behind the
    # slowest handoff.
    queue_full_remaining: int | None = None
    with store.tier3_lock:
        used = store.tier3_used_cents(client_id)
        within_mandate = used + body.amount_cents <= limit
        if within_mandate:
            store.record_tier3_event(
                client_id=client_id,
                item=body.item,
                amount_cents=body.amount_cents,
                outcome="accepted",
                reason="within mandate -- handoff in progress",
                action_id=action_id,
            )
        else:
            remaining = max(limit - used, 0)
            # MODE 2: over-mandate is queued for explicit human approval,
            # not rejected -- see ARCHITECTURE.md's two-mode model. Expired entries are pruned
            # BEFORE the cap check so they can never block a live slot.
            store.prune_tier3_pending()
            pending_count = sum(1 for a in store.tier3_pending.values() if a.client_id == client_id)
            if pending_count >= store.tier3_pending_max_per_client:
                queue_full_remaining = remaining
            else:
                store.queue_tier3_action(action_id, client_id, body.item, body.quantity, body.amount_cents)
                store.record_tier3_event(
                    client_id=client_id,
                    item=body.item,
                    amount_cents=body.amount_cents,
                    outcome="queued",
                    reason=f"exceeds mandate remaining ({remaining} of {limit} cents) -- awaiting human approval",
                    action_id=action_id,
                )
                store.set_tier3_resolution(
                    action_id,
                    client_id,
                    status="queued",
                    detail="awaiting human approval",
                )

    if queue_full_remaining is not None:
        # Distinct, auditable reason: this is the admin's signal that a
        # partner is flooding the approval queue (and the grant itself is
        # the revocable lever that bounds it).
        store.record_tier3_event(
            client_id=client_id,
            item=body.item,
            amount_cents=body.amount_cents,
            outcome="rejected",
            reason="pending-approval queue full for this client",
            action_id=action_id,
        )
        raise HTTPException(
            status_code=403,
            detail="too many actions already awaiting approval for this client",
        )

    if not within_mandate:
        return JSONResponse(
            status_code=202,
            content={
                "action_id": action_id,
                "status": "pending_approval",
                "status_path": f"/tier3/orders/{action_id}",
                "expires_at": store.tier3_pending[action_id].expires_at,
                "description": (
                    "This order exceeds the mandate's remaining budget, so it is queued for "
                    "explicit human approval and has NOT been executed. Poll the status path "
                    "for the outcome. Illustrative demo -- see ARCHITECTURE.md."
                ),
            },
        )

    # MODE 1: within mandate -- execute via the internal agent.
    envelope = _handoff_envelope(
        action_id, client_id, body, mode="within_mandate", limit=limit, used=used
    )
    result = execute_handoff(envelope)
    return _settle_handoff(
        action_id, client_id, body, result, limit=limit, used=used, approved_by_human=False
    )


def _handoff_envelope(
    action_id: str,
    client_id: str,
    body: Tier3OrderRequest,
    *,
    mode: str,
    limit: int,
    used: int,
    approved_by: str | None = None,
) -> dict:
    return {
        "action_id": action_id,
        "action_type": "order.place",
        "client_id": client_id,
        "requested_at": time.time(),
        "payload": {"item": body.item, "quantity": body.quantity, "amount_cents": body.amount_cents},
        "mandate": {
            "mode": mode,
            "weekly_limit_cents": limit,
            "used_cents": used,
            "remaining_cents": max(limit - used, 0),
            "window_seconds": store.tier3_window_seconds,
            "approved_by": approved_by,
        },
    }


def _settle_handoff(
    action_id: str,
    client_id: str,
    body: Tier3OrderRequest,
    result: HandoffResult,
    *,
    limit: int,
    used: int,
    approved_by_human: bool,
):
    """Reserve-then-settle's settlement, shared by the order handler and the
    approval endpoint. The budget reservation already exists; this either
    confirms it (executed / execution-unknown) or releases it (failed /
    agent down). Response bodies are constructed here from verify's OWN
    strings plus the agent's validated channel/reference -- never free text
    from the agent (and, transitively, never LLM output)."""
    prefix = "approved by human (out of mandate), " if approved_by_human else "within mandate, "

    if result.kind == "ok" and result.status == "executed":
        store.settle_tier3_event(
            action_id,
            outcome="accepted",
            reason=f"{prefix}executed via {result.channel} (decided by {result.decided_by})",
            order_number=result.reference,
        )
        store.set_tier3_resolution(
            action_id,
            client_id,
            status="executed",
            detail=f"executed via {result.channel}",
            channel=result.channel,
            order_number=result.reference,
        )
        return {
            "@context": "https://schema.org",
            "@type": "Order",
            "orderNumber": result.reference,
            "orderStatus": "https://schema.org/OrderProcessing",
            "orderedItem": {"@type": "Product", "name": body.item, "orderQuantity": body.quantity},
            "totalPaymentDue": {
                "@type": "PriceSpecification",
                "price": body.amount_cents / 100,
                "priceCurrency": "EUR",
            },
            "action_id": action_id,
            "channel": result.channel,
            "status_path": f"/tier3/orders/{action_id}",
            "remaining_cents": limit - used - body.amount_cents,
            "description": (
                "Executed by the privileged internal agent against an illustrative stub "
                "channel -- no real ERP/Slack/email is connected (see ARCHITECTURE.md)."
            ),
        }

    if result.kind == "ok":  # status == "failed": agent answered, did not execute
        store.settle_tier3_event(
            action_id,
            outcome="rejected",
            reason=f"{prefix}internal agent could not execute (no routing rule or channel failure) -- budget released",
        )
        store.set_tier3_resolution(
            action_id, client_id, status="failed", detail="the internal agent could not execute this action"
        )
        raise HTTPException(
            status_code=502,
            detail="the internal agent could not execute this action; the mandate budget was not consumed",
        )

    if result.kind == "down":
        store.settle_tier3_event(
            action_id,
            outcome="rejected",
            reason=f"{prefix}internal agent unavailable -- failed closed, budget released",
        )
        store.set_tier3_resolution(
            action_id, client_id, status="failed", detail="the internal agent was unavailable; not executed"
        )
        raise HTTPException(
            status_code=503,
            detail="the internal agent is unavailable; the action was not executed and the mandate budget was not consumed",
        )

    # kind == "unknown": timeout (after one idempotent retry) or a 200 with
    # an unparseable body. The action MAY have executed, so the reservation
    # STANDS -- failing closed on spending. The decision log on the agent's
    # status page is queryable by action_id for reconciliation.
    store.settle_tier3_event(
        action_id,
        outcome="accepted",
        reason=f"{prefix}handoff did not complete -- budget consumed, execution unknown (reconcile via the internal agent's decision log)",
    )
    store.set_tier3_resolution(
        action_id,
        client_id,
        status="execution_unknown",
        detail="the handoff did not complete; the action may have executed",
    )
    raise HTTPException(
        status_code=502,
        detail=(
            "the handoff to the internal agent did not complete: the action MAY have executed. "
            f"Do not resubmit -- the mandate budget has been consumed pending reconciliation; "
            f"poll /tier3/orders/{action_id}"
        ),
    )


@app.get("/tier3/orders/{action_id}")
def get_tier3_order_status(
    action_id: str,
    request: Request,
    authorization: str | None = Header(default=None),
    x_ssl_client_verify: str | None = Header(default=None),
):
    """Pollable resolution for one action_id -- the 202 response's
    status_path, and the reconciliation path after an execution-unknown 502.

    Own rate-limit bucket (polling for days is the DESIGNED behavior; see
    Store.tier3_poll_rate_limit_max). Full Tier 3 auth chain EXCEPT the
    grant check -- a client whose mandate was revoked must still be able to
    learn the fate of its already-queued actions. Records NO audit events on
    any path: a per-call audit write would let a client evict its own
    accepted events at poll speed and refill its budget via the documented
    per-client-cap residual (see tier3_audit_max)."""
    client_ip = _client_ip(request)
    if not store.check_rate_limit(
        "tier3_poll", client_ip, store.tier3_poll_rate_limit_max, store.tier3_poll_rate_limit_window
    ):
        raise HTTPException(status_code=429, detail="too many status requests, slow down")

    if x_ssl_client_verify != "SUCCESS":
        raise HTTPException(status_code=401, detail="client certificate not verified")

    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer access token")

    token = authorization.removeprefix("Bearer ").strip()
    try:
        claims = introspect_access_token(token)
    except InvalidToken:
        raise HTTPException(status_code=401, detail="invalid, expired, or revoked access token")

    client_id = claims.get("client_id") or claims.get("azp") or "unknown"

    # Expire any overdue pending entries first, so a queued action past its
    # TTL polls as "expired" rather than stale-"queued".
    with store.tier3_lock:
        store.prune_tier3_pending()

    resolution = store.get_tier3_resolution(action_id)
    if resolution is None or resolution.client_id != client_id:
        # Same 404 for "never existed", "expired out of the map", and
        # "belongs to a different client" -- no cross-client probing signal.
        raise HTTPException(status_code=404, detail="unknown action id")

    return {
        "action_id": resolution.action_id,
        "status": resolution.status,
        "detail": resolution.detail,
        "channel": resolution.channel,
        "order_number": resolution.order_number,
        "created_at": resolution.created_at,
        "updated_at": resolution.updated_at,
    }


@app.get("/tier3/admin-approvals")
def list_tier3_approvals(_: None = Depends(require_internal_admin)):
    """The approval queue, for the admin UI. Each entry carries the client's
    CURRENT grant state (the grant may have changed since queueing) so the
    approving human sees what they're deciding against, not a snapshot."""
    with store.tier3_lock:
        store.prune_tier3_pending()
        entries = sorted(store.tier3_pending.values(), key=lambda a: a.queued_at)
        return {
            "entries": [
                {
                    "action_id": a.action_id,
                    "client_id": a.client_id,
                    "item": a.item,
                    "quantity": a.quantity,
                    "amount_cents": a.amount_cents,
                    "queued_at": a.queued_at,
                    "expires_at": a.expires_at,
                    "grant": _tier3_grant_dict(a.client_id),
                }
                for a in entries
            ]
        }


@app.post("/tier3/admin-approvals/{action_id}/approve")
def approve_tier3_action(action_id: str, _: None = Depends(require_internal_admin)):
    """Executes a queued out-of-mandate action after explicit human approval.

    Re-checks the grant still exists at approval time (it may have been
    revoked while the action sat in the queue -- approving then would execute
    an action for a client an admin already cut off; 409, entry consumed).
    Deliberately does NOT re-check remaining budget: the action is
    over-mandate by definition, and the human approval IS the authorization
    for this specific spend -- it counts against the mandate afterward, so
    the window's later in-mandate actions see the reduced remainder.

    Double-approve is structurally impossible: the pop below consumes the
    entry, so a second approve (another admin, a double click) gets 404 and
    the budget is only ever reserved once."""
    with store.tier3_lock:
        store.prune_tier3_pending()
        action = store.tier3_pending.pop(action_id, None)
        if action is None:
            raise HTTPException(status_code=404, detail="unknown, expired, or already resolved action")
        limit = store.tier3_grants.get(action.client_id)
        if limit is None:
            store.record_tier3_event(
                client_id=action.client_id,
                item=action.item,
                amount_cents=action.amount_cents,
                outcome="rejected",
                reason="approval refused: mandate revoked while pending",
                action_id=action_id,
            )
            store.set_tier3_resolution(
                action_id,
                action.client_id,
                status="rejected",
                detail="mandate revoked while pending approval",
            )
            raise HTTPException(status_code=409, detail="this client's mandate was revoked while the action was pending")
        used = store.tier3_used_cents(action.client_id)
        store.record_tier3_event(
            client_id=action.client_id,
            item=action.item,
            amount_cents=action.amount_cents,
            outcome="accepted",
            reason="approved by human -- handoff in progress",
            action_id=action_id,
        )

    body = Tier3OrderRequest(item=action.item, quantity=action.quantity, amount_cents=action.amount_cents)
    envelope = _handoff_envelope(
        action_id, action.client_id, body, mode="approved_by_human", limit=limit, used=used, approved_by="admin"
    )
    result = execute_handoff(envelope)
    return _settle_handoff(
        action_id, action.client_id, body, result, limit=limit, used=used, approved_by_human=True
    )


@app.post("/tier3/admin-approvals/{action_id}/reject")
def reject_tier3_action(action_id: str, _: None = Depends(require_internal_admin)):
    with store.tier3_lock:
        store.prune_tier3_pending()
        action = store.tier3_pending.pop(action_id, None)
        if action is None:
            raise HTTPException(status_code=404, detail="unknown, expired, or already resolved action")
        store.record_tier3_event(
            client_id=action.client_id,
            item=action.item,
            amount_cents=action.amount_cents,
            outcome="rejected",
            reason="rejected by human",
            action_id=action_id,
        )
        store.set_tier3_resolution(
            action_id,
            action.client_id,
            status="rejected",
            detail="rejected by human",
        )
    return {"action_id": action_id, "status": "rejected"}
