#!/usr/bin/env python3
"""Real end-to-end smoke test for Tier 1 config hot-reloading in the admin
UI.

Changes verify's challenge rate limit through the admin UI's real HTTP
surface, then hits the REAL public /tier1/challenge endpoint through nginx
(the same path an external agent would use) repeatedly and confirms the new,
lower limit is enforced immediately -- the actual proof this feature exists
for (hot-reload, no restart), not just that a form submission returns 200.
Restores the original values afterward so it doesn't leave a reduced rate
limit behind for whatever runs against the same stack next.

Run against a live stack:
    docker compose up -d
    ADMIN_UI_PASSWORD=<value from your .env> python3 tests/tier1_config_smoke.py
    docker compose down
"""
from __future__ import annotations

import base64
import os
import re
import urllib.error
import urllib.parse
import urllib.request

ADMIN_BASE_URL = os.environ.get("ADMIN_BASE_URL", "http://localhost:8090")
STATIC_BASE_URL = os.environ.get("STATIC_BASE_URL", "http://localhost:8080")
ADMIN_UI_USERNAME = os.environ.get("ADMIN_UI_USERNAME", "admin")
ADMIN_UI_PASSWORD = os.environ.get("ADMIN_UI_PASSWORD", "")

FIELDS = (
    "challenge_ttl_seconds",
    "session_ttl_seconds",
    "challenge_rate_limit_max",
    "challenge_rate_limit_window",
    "verify_rate_limit_max",
    "verify_rate_limit_window",
)

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> bool:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)
    return condition


def _auth_header() -> str:
    token = base64.b64encode(f"{ADMIN_UI_USERNAME}:{ADMIN_UI_PASSWORD}".encode()).decode()
    return f"Basic {token}"


def admin_request(method: str, path: str, data: dict | None = None) -> tuple[int, str]:
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(
        ADMIN_BASE_URL + path,
        data=body,
        method=method,
        headers={"Authorization": _auth_header(), "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def read_current_values(form_html: str) -> dict[str, str]:
    values = {}
    for field in FIELDS:
        match = re.search(rf'name="{field}"[^>]*value="(\d*)"', form_html)
        if match:
            values[field] = match.group(1)
    return values


def public_challenge_status(domain: str) -> int:
    req = urllib.request.Request(
        f"{STATIC_BASE_URL}/tier1/challenge",
        data=b'{"domain": "%s"}' % domain.encode(),
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def main() -> int:
    if not ADMIN_UI_PASSWORD:
        print("Set ADMIN_UI_PASSWORD (matching the running stack's .env) before running this.")
        return 1

    print(f"Fetching current Tier 1 config from the admin UI at {ADMIN_BASE_URL}\n")
    status, body = admin_request("GET", "/tier1-config")
    if not check("admin GET /tier1-config succeeds", status == 200, f"got {status}"):
        return 1
    original = read_current_values(body)
    if not check("all six fields recovered from the rendered form", len(original) == len(FIELDS), f"got {original}"):
        return 1

    try:
        lowered = dict(original)
        lowered["challenge_rate_limit_max"] = "2"
        status, _body = admin_request("POST", "/tier1-config", lowered)
        check("admin POST /tier1-config (lowered limit) succeeds", status == 200, f"got {status}")

        status, body = admin_request("GET", "/tier1-config")
        check(
            "admin UI now shows the lowered limit",
            re.search(r'name="challenge_rate_limit_max"[^>]*value="2"', body) is not None,
        )

        print("\nHitting the REAL public /tier1/challenge endpoint through nginx...")
        codes = [public_challenge_status("tier1-config-smoke.example.com") for _ in range(3)]
        print(f"    statuses: {codes}")
        check("first 2 challenge requests succeed (200)", codes[:2] == [200, 200], f"got {codes}")
        check(
            "3rd challenge request is rate-limited (429) — proves hot-reload, no restart needed",
            codes[2] == 429,
            f"got {codes}",
        )

    finally:
        status, _body = admin_request("POST", "/tier1-config", original)
        check("cleanup: original Tier 1 config restored", status == 200, f"got {status}")
        status, body = admin_request("GET", "/tier1-config")
        restored = read_current_values(body)
        check("cleanup verified: admin UI reflects the restored values", restored == original, f"got {restored}")

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All checks passed — a Tier 1 config change made through the admin UI applies live, immediately, with no restart.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
