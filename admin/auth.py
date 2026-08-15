"""Gates every admin route with a single shared credential (`.env`), the same
"one shared secret" precedent already used for LiteLLM's master key. Chosen
over a Keycloak browser login for this v1: the deployed realm
(keycloak/realm-export.json) has zero human users and its one client is
client-credentials only (`standardFlowEnabled: false`) — a real login flow
would be new infrastructure, not reuse. Revisit once more than one human
admin needs a distinct account, or one deployment needs to serve more than
one pilot client — see the admin-UI plan for the full reasoning.
"""
from __future__ import annotations

import os
import secrets

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

ADMIN_UI_USERNAME = os.environ.get("ADMIN_UI_USERNAME", "")
ADMIN_UI_PASSWORD = os.environ.get("ADMIN_UI_PASSWORD", "")

# Fail closed at startup rather than silently accepting empty credentials:
# without this, an unset username/password would both default to "", and a
# request presenting an empty Basic Auth username/password would then
# authenticate successfully (compare_digest("", "") is True).
if not ADMIN_UI_USERNAME or not ADMIN_UI_PASSWORD:
    raise RuntimeError("ADMIN_UI_USERNAME and ADMIN_UI_PASSWORD must both be set (see .env.example)")

_security = HTTPBasic()


def verify_admin(credentials: HTTPBasicCredentials = Depends(_security)) -> str:
    # secrets.compare_digest on both fields — constant-time, and evaluated
    # unconditionally (not short-circuited) so a wrong username alone can't
    # be timed separately from a wrong password.
    username_ok = secrets.compare_digest(credentials.username, ADMIN_UI_USERNAME)
    password_ok = secrets.compare_digest(credentials.password, ADMIN_UI_PASSWORD)
    if not (username_ok and password_ok):
        raise HTTPException(
            status_code=401,
            detail="invalid admin credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username
