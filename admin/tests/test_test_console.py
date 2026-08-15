"""Regression coverage for test_console.py's `_get`/`run_check`, which build
a URL by concatenating STATIC_BASE_URL with admin-supplied free-text `path`
(the console lets you type any path, not just pick from the dropdown — see
main.py's console_run). Confirmed live during adversarial review: POSTing
path="@openbao" (or any value that confuses http.client's host:port
splitting) raised http.client.InvalidURL, which is NOT a
urllib.error.URLError subclass, so it fell through the existing except
clauses and 500'd the whole /console/run request instead of showing a failed
preview.

(This test file is named test_test_console.py, not test_console.py, because
the module under test is itself named test_console.py at the admin/ top
level — reusing that name here would collide on import with pytest's
rootdir-relative module naming.)
"""
from __future__ import annotations

import test_console


def test_run_check_survives_malformed_path_with_bad_hostport():
    # "static:80@openbao" (STATIC_BASE_URL's host:port + this path) makes
    # http.client._get_hostport rsplit on the last ':' into
    # host="static:80@openbao", port="80@openbao" -- a non-numeric port,
    # raising http.client.InvalidURL before any socket is even opened. This
    # must degrade to a failed ConsoleResult, not raise.
    result = test_console.run_check("@openbao")
    assert result.status == 0
    assert "InvalidURL" in result.raw_body or "nonnumeric port" in result.raw_body


def test_run_check_survives_other_malformed_paths():
    for path in ["@evil.com", "@127.0.0.1:9999/", "::not-a-url::"]:
        result = test_console.run_check(path)
        # Whatever happens, it must come back as a ConsoleResult with a
        # non-200 status, never raise (and never crash the caller into a
        # bare 500 — see main.py's console_run, which has no try/except of
        # its own and relies on this function not raising).
        assert result.status != 200
