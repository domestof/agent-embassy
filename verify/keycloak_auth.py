"""Tier 2 bearer-token validation against Keycloak.

Validates the JWT's signature against Keycloak's own published JWKS (fetched
once, cached) rather than calling Keycloak's introspection endpoint per
request — the standard resource-server pattern for JWT access tokens, and
one fewer network round-trip per request than introspection would cost.
Immediate revocation before token expiry is out of scope, same tradeoff
already accepted for Tier 1 session tokens.
"""
from __future__ import annotations

import os

import jwt
from jwt import PyJWKClient

# Defaults match docker-compose.yml's `keycloak`/`verify` service wiring;
# overridable like Tier 1's other *_SECONDS/*_MAX env vars in main.py.
KEYCLOAK_JWKS_URL = os.environ.get(
    "KEYCLOAK_JWKS_URL", "http://keycloak:8080/realms/agent-embassy/protocol/openid-connect/certs"
)
KEYCLOAK_ISSUER = os.environ.get("KEYCLOAK_ISSUER", "http://keycloak:8080/realms/agent-embassy")
KEYCLOAK_AUDIENCE = os.environ.get("TIER2_AUDIENCE", "agent-embassy-tier2")

_jwks_client: PyJWKClient | None = None


def _get_jwks_client() -> PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        # lifespan: seconds a fetched key is trusted before Keycloak's JWKS
        # is re-fetched — bounds how quickly a rotated signing key is honored.
        _jwks_client = PyJWKClient(KEYCLOAK_JWKS_URL, cache_keys=True, lifespan=300)
    return _jwks_client


class InvalidToken(Exception):
    pass


def validate_access_token(token: str) -> dict:
    """Returns the token's claims on success. Raises InvalidToken otherwise
    — signature, issuer, audience, and expiry are all checked; the caller
    never learns which check failed (mirrors Tier 1's generic-failure
    posture in security.py)."""
    try:
        signing_key = _get_jwks_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=KEYCLOAK_ISSUER,
            audience=KEYCLOAK_AUDIENCE,
        )
    except Exception as exc:
        raise InvalidToken(str(exc)) from exc
    return claims
