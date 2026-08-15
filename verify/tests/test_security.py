import socket

import pytest

import security


def test_validate_domain_accepts_normal_domain():
    assert security.validate_domain("Example.com") == "example.com"
    assert security.validate_domain("sub.example.com") == "sub.example.com"


def test_validate_domain_rejects_ip_literal():
    with pytest.raises(security.InvalidDomain):
        security.validate_domain("1.2.3.4")


def test_validate_domain_rejects_malformed():
    with pytest.raises(security.InvalidDomain):
        security.validate_domain("not a domain")
    with pytest.raises(security.InvalidDomain):
        security.validate_domain("-bad.com")
    with pytest.raises(security.InvalidDomain):
        security.validate_domain("nodots")


def test_validate_domain_rejects_reserved_special_use_domains():
    for d in ["localhost", "foo.local", "bar.test", "baz.invalid", "qux.example"]:
        with pytest.raises(security.InvalidDomain):
            security.validate_domain(d)


def test_validate_domain_rejects_dot_internal():
    # RFC 9476 (2024) special-use domain — hostname-level rejection here is
    # defense-in-depth; resolve_public_ip's IP-level filtering is what
    # actually stops e.g. metadata.google.internal regardless of this check.
    with pytest.raises(security.InvalidDomain):
        security.validate_domain("metadata.google.internal")


def test_validate_domain_rejects_shared_hosting_subdomains():
    for d in ["someuser.github.io", "myapp.vercel.app", "bucket.s3.amazonaws.com", "github.io"]:
        with pytest.raises(security.InvalidDomain):
            security.validate_domain(d)


def test_resolve_public_ip_skips_private_and_returns_public(monkeypatch):
    def fake_getaddrinfo(host, port, proto=None):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
        ]

    monkeypatch.setattr(security.socket, "getaddrinfo", fake_getaddrinfo)
    assert security.resolve_public_ip("example.com") == "93.184.216.34"


def test_resolve_public_ip_rejects_private_loopback_and_link_local(monkeypatch):
    def fake_getaddrinfo(host, port, proto=None):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
            # 169.254.169.254 is the cloud metadata endpoint (AWS/GCP/Azure) —
            # the exact SSRF target this guard exists to block.
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port)),
        ]

    monkeypatch.setattr(security.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError):
        security.resolve_public_ip("attacker-controlled.example")


def test_resolve_public_ip_rejects_cgnat_shared_address_space(monkeypatch):
    # 100.64.0.0/10 (RFC 6598) is not private/reserved/link-local per
    # ipaddress's own classification, but is used as real internal address
    # space by Tailscale, some Kubernetes CNIs, and carrier-grade NAT — an
    # SSRF gap found by adversarial review, fixed by an explicit blocklist.
    def fake_getaddrinfo(host, port, proto=None):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("100.64.0.5", port)),
        ]

    monkeypatch.setattr(security.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(ValueError):
        security.resolve_public_ip("cgnat-attacker.example")


def test_parse_http_response_200():
    raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nabc123"
    status, body = security.parse_http_response(raw)
    assert status == 200
    assert body == b"abc123"


def test_parse_http_response_redirect_is_not_followed():
    # parse_http_response never chases Location — a 3xx comes back like any
    # other non-200 status for the caller to reject.
    raw = b"HTTP/1.1 302 Found\r\nLocation: https://attacker.example/\r\n\r\n"
    status, body = security.parse_http_response(raw)
    assert status == 302
    assert body == b""


def test_parse_http_response_malformed_raises():
    with pytest.raises(ValueError):
        security.parse_http_response(b"not an http response")


def test_fetch_challenge_file_connects_to_the_resolved_ip_not_a_reresolution(monkeypatch):
    calls = {}

    def fake_resolve(hostname, port=443):
        return "93.184.216.34"

    def fake_fetch_raw(ip, hostname, path, timeout, max_bytes):
        calls["ip"] = ip
        calls["hostname"] = hostname
        calls["path"] = path
        return b"HTTP/1.1 200 OK\r\n\r\ntoken-value"

    monkeypatch.setattr(security, "resolve_public_ip", fake_resolve)
    monkeypatch.setattr(security, "fetch_raw", fake_fetch_raw)

    status, body = security.fetch_challenge_file("example.com")
    assert status == 200
    assert body == b"token-value"
    assert calls["ip"] == "93.184.216.34"
    assert calls["hostname"] == "example.com"
    assert calls["path"] == security.CHALLENGE_PATH
