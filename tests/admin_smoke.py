#!/usr/bin/env python3
"""Real end-to-end smoke test for the Tier 0 admin UI.

Adds a marker product via the admin API against a running docker-compose
stack, then independently re-fetches it via the PUBLIC `static` endpoint
(never the admin API, never the filesystem) — proving the write actually
reached the exact file nginx serves, with no restart in between. Mirrors
tests/tier0_two_party.py's two-independent-parties-over-real-HTTP style.

Run against a live stack:
    docker compose up -d
    ADMIN_UI_PASSWORD=<value from your .env> python3 tests/admin_smoke.py
    docker compose down
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ADMIN_BASE_URL = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("ADMIN_BASE_URL", "http://localhost:8090")
STATIC_BASE_URL = os.environ.get("STATIC_BASE_URL", "http://localhost:8080")
USERNAME = os.environ.get("ADMIN_UI_USERNAME", "admin")
PASSWORD = os.environ.get("ADMIN_UI_PASSWORD", "")

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)


def _auth_header() -> str:
    token = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
    return f"Basic {token}"


def admin_post(path: str, data: dict) -> tuple[int, str]:
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        ADMIN_BASE_URL + path,
        data=body,
        method="POST",
        headers={"Authorization": _auth_header(), "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def public_get(path: str) -> tuple[int, bytes]:
    req = urllib.request.Request(STATIC_BASE_URL + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def main() -> int:
    if not PASSWORD:
        print("Set ADMIN_UI_PASSWORD (matching the running stack's .env) before running this.")
        return 1

    marker = f"admin-smoke-{int(time.time())}"
    print(f"Adding a marker product ({marker!r}) via the admin API at {ADMIN_BASE_URL}\n")

    status, _body = admin_post("/catalog/products/new", {"field__name": marker, "field__description": "smoke test"})
    check("admin add-item POST is accepted (redirect)", status in (200, 303), f"got {status}")

    # Independently re-fetch via the PUBLIC endpoint only — proving the
    # write reached the exact file nginx serves, with no restart involved.
    status, body = public_get("/catalog/products.json")
    check("public products.json is reachable", status == 200, f"got {status}")
    if status != 200:
        print("\nCannot continue without the public catalog.")
        return 1

    try:
        doc = json.loads(body)
    except json.JSONDecodeError as exc:
        check("public products.json is valid JSON", False, str(exc))
        return 1
    check("public products.json is valid JSON", True)

    names = [item.get("name") for item in doc.get("itemListElement", [])]
    check(f"marker product {marker!r} appears in the PUBLIC catalog", marker in names, f"got names={names}")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All checks passed — a write via the admin API reached the exact file nginx serves, live.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
