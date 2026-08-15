"""Client for verify's /tier1/admin-config endpoint (Tier 1 TTL/rate-limit
hot-reload). Much smaller than keycloak_client.py's problem (one internal
service, two operations) but the same shape: stdlib urllib only, a result
dataclass, never raises.

Changes made through this module apply immediately in the running verify
process and are NOT persisted -- they revert to the env var defaults in
docker-compose.yml/.env on a verify restart. The admin UI surfaces that
directly rather than hiding it (see templates/tier1_config.html).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

VERIFY_BASE_URL = os.environ.get("VERIFY_BASE_URL", "http://verify:8001")
ADMIN_INTERNAL_TOKEN = os.environ.get("ADMIN_INTERNAL_TOKEN", "")

# Fail closed at import, same reasoning as keycloak_client.py's
# KEYCLOAK_ADMIN_USERNAME/PASSWORD check: an unset token would just mean
# every call to verify 403s with no clue why.
if not ADMIN_INTERNAL_TOKEN:
    raise RuntimeError("ADMIN_INTERNAL_TOKEN must be set (see .env.example)")

_CONFIG_URL = f"{VERIFY_BASE_URL}/tier1/admin-config"

CONFIG_FIELDS = (
    "challenge_ttl_seconds",
    "session_ttl_seconds",
    "challenge_rate_limit_max",
    "challenge_rate_limit_window",
    "verify_rate_limit_max",
    "verify_rate_limit_window",
)


@dataclass
class ConfigResult:
    ok: bool
    values: dict[str, int] | None = None
    error: str | None = None


def _verify_request(method: str, body: dict | None = None) -> tuple[int, bytes]:
    """Same status/body contract as keycloak_client._admin_request, minus
    the response headers this caller never needs. Request(...) construction
    is kept INSIDE the try block -- its constructor can itself raise
    ValueError for a malformed URL (confirmed live in keycloak_client.py,
    the same bug shape test_console.py's _get() hit first)."""
    try:
        headers = {
            "X-Admin-Token": ADMIN_INTERNAL_TOKEN,
            **({"Content-Type": "application/json"} if body is not None else {}),
        }
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(_CONFIG_URL, method=method, headers=headers, data=data)
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError:
        return 0, b"could not reach verify"
    except Exception as exc:
        return 0, str(exc).encode()


def get_config() -> ConfigResult:
    status, body = _verify_request("GET")
    if status != 200:
        return ConfigResult(ok=False, error=f"verify returned HTTP {status} fetching Tier 1 config")
    try:
        values = json.loads(body)
    except json.JSONDecodeError:
        return ConfigResult(ok=False, error="verify returned an unparseable Tier 1 config")
    return ConfigResult(ok=True, values=values)


def update_config(**fields: int) -> ConfigResult:
    missing = [f for f in CONFIG_FIELDS if f not in fields]
    if missing:
        return ConfigResult(ok=False, error=f"missing config field(s): {', '.join(missing)}")

    status, body = _verify_request("PUT", {f: fields[f] for f in CONFIG_FIELDS})
    if status == 422:
        return ConfigResult(ok=False, error="one or more values are out of the allowed range")
    if status != 200:
        return ConfigResult(ok=False, error=f"verify returned HTTP {status} updating Tier 1 config")
    try:
        values = json.loads(body)
    except json.JSONDecodeError:
        return ConfigResult(ok=False, error="verify returned an unparseable Tier 1 config")
    return ConfigResult(ok=True, values=values)
