#!/usr/bin/env python3
"""Two-party smoke test for the Tier 0 public catalog.

Simulates two genuinely independent roles talking over real HTTP (not an
in-process test client, not mocks):

  Party A ("provider") — the running docker-compose stack (`static` + its
  nginx config), reachable at BASE_URL. This script never touches its
  internals; it only speaks HTTP to it, the same way a real external agent
  would.

  Party B ("consumer") — this script. It starts knowing only BASE_URL, the
  documented entry point (https://<domain>/.well-known/agent-embassy.json —
  see ARCHITECTURE.md), and follows the manifest to discover the *public*
  catalog paths rather than hardcoding them. The one exception is the Tier 1
  boundary check at the end, which deliberately hits the well-known
  `/catalog/contact.json` path directly (not read from the manifest) — the
  point there is to confirm the real gated resource is actually gated, not
  just that the manifest claims it is.

Run against a live stack (the `verify` service has a Docker healthcheck, so
`up -d` only returns once it's actually ready to answer — see
docker-compose.yml):
    docker compose up -d
    python3 tests/tier0_two_party.py
    docker compose down

Caveat: `docker compose restart` does not wait for healthchecks the way
`up -d` does, so running this script immediately after a `restart` can
transiently see a 500 (verify not yet accepting connections) instead of the
expected 401 on the last check. This is a real startup race, not a bug in
what's being asserted; it resolves within a couple of seconds.

Exit code 0 if every check passes, 1 otherwise. Each check prints its own
PASS/FAIL line so a failure is diagnosable without re-running under a
debugger.
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
MANIFEST_PATH = "/.well-known/agent-embassy.json"

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {label}" + (f" — {detail}" if detail and not condition else ""))
    if not condition:
        failures.append(label)


def http_get(path: str) -> tuple[int, bytes]:
    req = urllib.request.Request(BASE_URL + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        return 0, str(exc.reason).encode()


def main() -> int:
    print(f"Party B (consumer) starting cold against Party A (provider) at {BASE_URL}\n")

    # Step 1 — discover the manifest. This is the only URL Party B is
    # assumed to know in advance.
    status, body = http_get(MANIFEST_PATH)
    check("manifest is reachable and returns 200", status == 200, f"got {status}")
    if status != 200:
        print("\nCannot continue without a manifest.")
        return 1

    try:
        manifest = json.loads(body)
    except json.JSONDecodeError as exc:
        check("manifest body is valid JSON", False, str(exc))
        return 1
    check("manifest body is valid JSON", True)

    check(
        "manifest declares Tier 0 as auth: none",
        any(t.get("tier") == 0 and t.get("auth") == "none" for t in manifest.get("access_tiers", [])),
    )

    public_catalog = manifest.get("public_catalog", {})
    check("manifest advertises a non-empty public_catalog", bool(public_catalog))

    # Step 2 — follow the manifest's own links, not hardcoded paths. A real
    # external agent has no other way to know these URLs exist.
    for resource_name, path in public_catalog.items():
        status, body = http_get(path)
        check(f"catalog '{resource_name}' ({path}) returns 200", status == 200, f"got {status}")
        if status != 200:
            continue
        try:
            doc = json.loads(body)
        except json.JSONDecodeError as exc:
            check(f"catalog '{resource_name}' body is valid JSON", False, str(exc))
            continue
        check(f"catalog '{resource_name}' body is valid JSON", True)
        check(
            # Structural check only: a real @context/@type pair is present,
            # not that @type names an actual schema.org type.
            f"catalog '{resource_name}' declares a schema.org @context and @type",
            doc.get("@context") == "https://schema.org" and bool(doc.get("@type")),
            f"@context={doc.get('@context')!r} @type={doc.get('@type')!r}",
        )
        check(
            f"catalog '{resource_name}' has at least one list item",
            bool(doc.get("itemListElement")),
        )

    # Step 3 — confirm the Tier 0 boundary from the outside: a party with no
    # Tier 1 session must NOT be able to reach contact.json just because it
    # sits next to the public catalog files.
    status, _ = http_get("/catalog/contact.json")
    check(
        "contact.json (Tier 1 resource) is refused without a session token",
        status in (401, 403),
        f"got {status} — Tier 0 party could read a gated resource",
    )

    # Step 4 — same boundary, for order-status.json (a Tier 2 resource).
    # Found live during adversarial review of the LiteLLM MCP gateway work:
    # both nginx server blocks share one document root, and the plain :80
    # block had no location for this path at all, so it silently fell
    # through to the public catch-all and was served with ZERO auth —
    # completely defeating Tier 2's mTLS + token gate, which only applied on
    # :443. Fixed with an explicit deny in nginx/default.conf; this check
    # guards against it regressing.
    status, _ = http_get("/catalog/order-status.json")
    check(
        "order-status.json (Tier 2 resource) is not exposed on the plain :80 listener at all",
        status == 404,
        f"got {status} — Tier 0/1 party on :8080 could read a Tier 2 resource",
    )

    print()
    if failures:
        print(f"{len(failures)} check(s) failed:")
        for f in failures:
            print(f"  - {f}")
        return 1

    print("All checks passed — Party B independently discovered and consumed Party A's Tier 0 catalog.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
