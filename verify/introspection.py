"""Tier 3 bearer-token validation against Keycloak's real-time introspection
endpoint (RFC 7662) -- deliberately NOT the local-JWKS approach keycloak_auth
validate_access_token() uses for Tier 2.

keycloak_auth.py's docstring already concedes "Immediate revocation before
token expiry is out of scope" for Tier 2 -- local signature validation has no
way to see that an admin disabled a client or revoked a session in the
meantime; the token stays valid until its own exp claim. Tier 3's spec row
explicitly requires "immediate ... revocation", so it pays one extra network
round-trip to Keycloak per request in exchange for that: introspection asks
Keycloak's live state directly, and a disabled client fails introspection
immediately (verified against Keycloak's own source at the pinned image tag,
26.7.1: ClientModel.isEnabled() is checked in verifyClient() before any
session/audience logic runs).

The introspecting client here is named "agent-embassy-tier2" on purpose, not
arbitrarily: Keycloak's introspection endpoint requires the AUTHENTICATED
(introspecting) client's own clientId to appear in the token's `aud` claim
(a plain string-containment check, confirmed in
AccessTokenIntrospectionProvider.verifyAudience()). Every partner token
already carries aud: "agent-embassy-tier2" via keycloak/realm-export.json's
existing tier2-audience protocol mapper (also auto-attached by
admin/keycloak_client.py's create_client() for every future partner client).
Naming the client to match means introspection works with zero new protocol
mappers -- adding one instead was considered and rejected, since a mapper
that only new clients get would reintroduce the exact "client missing a
required mapper fails Tier 2/3 auth silently" footgun keycloak_client.py's
audience-mapper auto-attachment already exists to prevent. The deprecated
Keycloak bypass flag (allow-token-introspection-without-audience-check) was
also considered and rejected -- it's slated for removal upstream.
"""
from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.parse
import urllib.request

from keycloak_auth import InvalidToken

KEYCLOAK_INTROSPECTION_URL = os.environ.get(
    "KEYCLOAK_INTROSPECTION_URL",
    "http://keycloak:8080/realms/agent-embassy/protocol/openid-connect/token/introspect",
)
TIER3_INTROSPECTION_CLIENT_ID = os.environ.get("TIER3_INTROSPECTION_CLIENT_ID", "agent-embassy-tier2")
TIER3_INTROSPECTION_SECRET = os.environ.get("TIER3_INTROSPECTION_SECRET", "")

if not TIER3_INTROSPECTION_SECRET:
    raise RuntimeError("TIER3_INTROSPECTION_SECRET must be set (see .env.example)")

_basic_auth = base64.b64encode(f"{TIER3_INTROSPECTION_CLIENT_ID}:{TIER3_INTROSPECTION_SECRET}".encode()).decode()


def _post_introspect(token: str) -> tuple[int, bytes]:
    """The single mockable network boundary -- mirrors keycloak_auth's
    _get_jwks_client and admin/tier1_client.py's _verify_request. Request(...)
    construction is kept INSIDE the try block: its constructor can itself
    raise ValueError for a malformed URL, the same bug shape this repo has
    hit twice already (admin/test_console.py, admin/keycloak_client.py)."""
    try:
        data = urllib.parse.urlencode({"token": token}).encode()
        req = urllib.request.Request(
            KEYCLOAK_INTROSPECTION_URL,
            method="POST",
            data=data,
            headers={
                "Authorization": f"Basic {_basic_auth}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return 0, b"could not reach keycloak"
    except Exception as exc:
        return 0, str(exc).encode()


def introspect_access_token(token: str) -> dict:
    """Returns the introspection response's claims on success (at minimum
    `active: True` plus whatever Keycloak includes, e.g. client_id/azp/exp).
    Raises InvalidToken otherwise -- unreachable Keycloak, a non-200
    response, an unparseable body, or active is not True all collapse to the
    same exception, mirroring Tier 1/2's generic-failure posture. The caller
    never learns the secret or Keycloak's raw response on failure."""
    status, body = _post_introspect(token)
    if status != 200:
        raise InvalidToken(f"introspection endpoint returned HTTP {status}")
    try:
        data = json.loads(body)
    except json.JSONDecodeError as exc:
        raise InvalidToken("introspection endpoint returned an unparseable body") from exc
    if data.get("active") is not True:
        raise InvalidToken("token is not active (expired, revoked, or disabled)")
    return data
