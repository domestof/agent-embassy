import log_tail

SAMPLE_LINES = [
    '172.19.0.1 - - [09/Aug/2026:20:15:03 +0000] "GET /catalog/products.json HTTP/1.1" 200 123 "-" "curl/8.5.0" "-"\n',
    '172.19.0.2 - - [09/Aug/2026:20:15:04 +0000] "GET /favicon.ico HTTP/1.1" 404 0 "-" "Mozilla/5.0" "-"\n',
    '172.19.0.3 - - [09/Aug/2026:20:15:05 +0000] "GET /.well-known/agent-embassy.json HTTP/1.1" 200 456 "-" "some-agent/1.0" "-"\n',
    "not a valid log line at all\n",
]


def test_parse_line_extracts_fields():
    entry = log_tail.parse_line(SAMPLE_LINES[0])
    assert entry.ip == "172.19.0.1"
    assert entry.method == "GET"
    assert entry.path == "/catalog/products.json"
    assert entry.status == 200


def test_parse_line_returns_none_for_malformed():
    assert log_tail.parse_line(SAMPLE_LINES[-1]) is None


def test_parse_line_old_format_has_no_verified_domain():
    """SAMPLE_LINES predates the catalog_activity log format (no trailing
    verified_domain field) -- e.g. what the mTLS :443 listener still writes,
    since it never touches Tier 1. Must parse cleanly with the field absent,
    not just not-crash."""
    entry = log_tail.parse_line(SAMPLE_LINES[0])
    assert entry.verified_domain is None


def test_parse_line_extracts_verified_domain():
    """The exact shape nginx's catalog_activity log_format produces (see
    nginx/default.conf) for a /catalog/contact.json hit that carried a valid
    Tier 1 session -- confirmed against a real captured log line, not just
    a hand-written guess at the format."""
    line = (
        '10.32.23.1 - - [14/Aug/2026:10:39:40 +0000] "GET /catalog/contact.json HTTP/1.1" '
        '200 299 "-" "Python-urllib/3.10" "-" verified_domain="acme-example.example.com"\n'
    )
    entry = log_tail.parse_line(line)
    assert entry is not None
    assert entry.path == "/catalog/contact.json"
    assert entry.verified_domain == "acme-example.example.com"


def test_parse_line_new_format_empty_verified_domain_is_none():
    """catalog_activity's verified_domain field is present but empty for
    every request that never went through contact.json's auth_request_set
    (nginx variables introduced this way are "" when unset for a given
    request, not omitted) -- must normalize to None, not the empty string,
    so the template's {% if %} check works."""
    line = (
        '10.32.23.1 - - [14/Aug/2026:10:40:00 +0000] "GET /catalog/products.json HTTP/1.1" '
        '200 123 "-" "curl/8.5.0" "-" verified_domain=""\n'
    )
    entry = log_tail.parse_line(line)
    assert entry is not None
    assert entry.verified_domain is None


def test_recent_catalog_requests_filters_and_orders_newest_first(tmp_path, monkeypatch):
    log_path = tmp_path / "access.log"
    log_path.write_text("".join(SAMPLE_LINES))
    monkeypatch.setattr(log_tail, "ACCESS_LOG_PATH", str(log_path))

    entries = log_tail.recent_catalog_requests()
    paths = [e.path for e in entries]
    # Newest first; the favicon line (neither /catalog/ nor /.well-known/)
    # is excluded, and the malformed line is skipped rather than raising.
    assert paths == ["/.well-known/agent-embassy.json", "/catalog/products.json"]


def test_recent_catalog_requests_returns_empty_when_no_log_file(tmp_path, monkeypatch):
    monkeypatch.setattr(log_tail, "ACCESS_LOG_PATH", str(tmp_path / "missing.log"))
    assert log_tail.recent_catalog_requests() == []
