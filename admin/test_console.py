""""Preview as an agent" console: makes a real HTTP GET against the public
`static` nginx service (its docker-internal address, no port publishing
needed) and shows exactly what came back. Never reads catalog_store or the
filesystem directly — that would only prove the admin service thinks the
data is right, not that nginx is actually serving it correctly (wrong
alias/root, stale bind-mount, wrong Content-Type, ...). Mirrors
tests/tier0_two_party.py's "independent party over real HTTP" role.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

STATIC_BASE_URL = os.environ.get("STATIC_BASE_URL", "http://static:80")
MANIFEST_PATH = "/.well-known/agent-embassy.json"


@dataclass
class ConsoleResult:
    path: str
    status: int
    headers: dict
    raw_body: str
    pretty_body: str | None
    error: str | None = None


def _get(path: str) -> tuple[int, dict, bytes]:
    req = urllib.request.Request(STATIC_BASE_URL + path, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()
    except urllib.error.URLError as exc:
        return 0, {}, str(exc.reason).encode()
    except Exception as exc:
        # `path` is free-text admin input (the console lets you type any
        # path, not just pick from the discovered-resources dropdown — see
        # main.py's console_run) and gets concatenated straight onto
        # STATIC_BASE_URL. Some malformed values (e.g. a stray "@" or ":")
        # never make it far enough to raise a urllib.error.URLError —
        # http.client's own host:port parsing raises http.client.InvalidURL
        # first, which is not a URLError subclass. Confirmed live: POSTing
        # path="@openbao" 500'd the whole admin request instead of showing
        # a failed preview. Catch-all so any such input degrades to a
        # visible failed check, matching this function's contract, not an
        # unhandled 500.
        return 0, {}, str(exc).encode()


def discover_resources() -> dict[str, str]:
    """{resource_name: path}, discovered by fetching the live manifest —
    exactly how an external agent would find them, not hardcoded here."""
    status, _headers, body = _get(MANIFEST_PATH)
    resources = {"manifest": MANIFEST_PATH}
    if status != 200:
        return resources
    try:
        manifest = json.loads(body)
    except json.JSONDecodeError:
        return resources
    resources.update(manifest.get("public_catalog", {}))
    return resources


def run_check(path: str) -> ConsoleResult:
    status, headers, body = _get(path)
    raw = body.decode("utf-8", errors="replace")
    pretty = None
    error = None
    if status == 200:
        try:
            pretty = json.dumps(json.loads(raw), indent=2)
        except json.JSONDecodeError as exc:
            error = f"200 OK but body is not valid JSON: {exc}"
    return ConsoleResult(path=path, status=status, headers=headers, raw_body=raw, pretty_body=pretty, error=error)
