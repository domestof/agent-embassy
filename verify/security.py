"""Domain validation and SSRF-safe fetching for the Tier 1 domain-challenge.

Kept deliberately low-level (stdlib socket/ssl instead of an HTTP client
library) so the IP that gets validated is the exact IP that gets connected
to — no second DNS resolution happens between the check and the connection,
which is what closes the DNS-rebinding TOCTOU gap a naive "resolve, check,
then let an HTTP client re-resolve and connect" approach would leave open.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl

CHALLENGE_PATH = "/.well-known/agent-embassy-challenge.txt"

# RFC 1035-ish hostname: dot-separated labels, alnum + hyphen, label doesn't
# start/end with a hyphen, TLD is alphabetic and at least 2 chars.
_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_HOSTNAME_RE = re.compile(rf"^({_LABEL}\.)+[A-Za-z]{{2,63}}$")

# RFC 6761 special-use domains, plus .internal (RFC 9476, added 2024) — never
# legitimate targets for this challenge. Hostname-level rejection is
# defense-in-depth on top of resolve_public_ip's IP-level filtering, which is
# what actually stops e.g. metadata.google.internal today regardless of this
# list.
_RESERVED_SUFFIXES = ("localhost", ".local", ".test", ".example", ".invalid", ".internal")

# Ranges that Python's ipaddress module does NOT classify as private/
# reserved/link-local but that are routed as internal address space by real
# infrastructure (e.g. Tailscale's mesh network, some Kubernetes CNIs, and
# carrier-grade NAT deployments all use 100.64.0.0/10). ipaddress's built-in
# classification is not a complete "is this publicly routable" check, so
# these are blocked explicitly on top of it.
_EXTRA_BLOCKED_NETWORKS = (
    ipaddress.ip_network("100.64.0.0/10"),  # RFC 6598 CGNAT / shared address space
)

# Common shared-hosting platforms where a bare subdomain can be claimed by
# anyone (dangling-CNAME subdomain takeover). This is a denylist, not a full
# public-suffix-list apex check — it blocks the well-documented common cases,
# not every possible shared-hosting provider. Documented as a partial
# mitigation, not a complete defense against subdomain takeover.
_SHARED_HOSTING_SUFFIXES = (
    "github.io",
    "gitlab.io",
    "netlify.app",
    "vercel.app",
    "pages.dev",
    "herokuapp.com",
    "s3.amazonaws.com",
    "web.app",
    "firebaseapp.com",
    "azurewebsites.net",
    "azureedge.net",
    "cloudfront.net",
    "blogspot.com",
    "wordpress.com",
)


class InvalidDomain(ValueError):
    pass


def validate_domain(domain: str) -> str:
    """Validate and normalize a claimed domain. Raises InvalidDomain if unfit
    to be challenged. Does not perform any network I/O."""
    domain = domain.strip().lower().rstrip(".")
    if len(domain) > 253 or not domain:
        raise InvalidDomain("domain too long or empty")

    # Reject IP literals outright — the challenge is for domain identity,
    # not raw addresses.
    try:
        ipaddress.ip_address(domain)
        raise InvalidDomain("IP literals are not accepted as a domain")
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(domain):
        raise InvalidDomain("not a well-formed hostname")

    if domain == "localhost" or any(
        domain == s.lstrip(".") or domain.endswith(s) for s in _RESERVED_SUFFIXES
    ):
        raise InvalidDomain("reserved/special-use domain")

    if any(domain == s or domain.endswith("." + s) for s in _SHARED_HOSTING_SUFFIXES):
        raise InvalidDomain(
            "bare subdomains of shared-hosting platforms are not accepted "
            "(subdomain-takeover risk)"
        )

    return domain


def resolve_public_ip(hostname: str, port: int = 443) -> str:
    """Resolve hostname and return the first IP that is not private/loopback/
    link-local/multicast/reserved/unspecified. Raises ValueError if none of
    the resolved addresses are publicly routable — this is the core SSRF
    guard: it stops the verifier from ever connecting to an attacker-chosen
    internal address (e.g. a cloud metadata endpoint) via a domain that
    resolves there."""
    infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip = sockaddr[0]
        addr = ipaddress.ip_address(ip)
        if (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
            or addr.is_unspecified
            or any(addr in net for net in _EXTRA_BLOCKED_NETWORKS)
        ):
            continue
        return ip
    raise ValueError(f"{hostname} did not resolve to any publicly routable address")


def parse_http_response(raw: bytes) -> tuple[int, bytes]:
    """Parse an HTTP/1.1 response into (status_code, body). Deliberately
    does not follow redirects — a 3xx status is returned to the caller like
    any other non-200, and is never chased automatically. This is a stricter
    posture than real ACME HTTP-01 (which does follow cross-domain
    redirects); the tradeoff is documented in the Tier 1 plan."""
    header_end = raw.find(b"\r\n\r\n")
    if header_end == -1:
        raise ValueError("incomplete HTTP response (no header terminator)")
    header_bytes = raw[:header_end]
    body = raw[header_end + 4 :]
    status_line = header_bytes.split(b"\r\n", 1)[0]
    parts = status_line.split(b" ", 2)
    if len(parts) < 2:
        raise ValueError("malformed status line")
    status = int(parts[1])
    return status, body


def fetch_raw(ip: str, hostname: str, path: str, timeout: float, max_bytes: int) -> bytes:
    """Perform a plain HTTP/1.1 GET over TLS, connecting directly to `ip`
    (already validated by resolve_public_ip) with `hostname` as the TLS SNI
    / Host header. No redirects are followed since this never re-parses
    Location headers or reconnects — the raw response bytes are simply
    returned for parse_http_response to interpret."""
    ctx = ssl.create_default_context()
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        f"User-Agent: agent-embassy-tier1-verify/1.0\r\n"
        f"Accept: text/plain\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")

    with socket.create_connection((ip, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as tls_sock:
            tls_sock.sendall(request)
            data = b""
            tls_sock.settimeout(timeout)
            while len(data) < max_bytes:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                data += chunk
    return data[:max_bytes]


def fetch_challenge_file(
    domain: str, timeout: float = 5.0, max_bytes: int = 4096
) -> tuple[int, bytes]:
    """End-to-end SSRF-guarded fetch of the challenge file: resolve to a
    public IP, connect to that exact IP, GET the well-known path. Returns
    (status_code, body)."""
    ip = resolve_public_ip(domain)
    raw = fetch_raw(ip, domain, CHALLENGE_PATH, timeout, max_bytes)
    return parse_http_response(raw)
