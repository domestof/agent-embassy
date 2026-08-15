"""Reads nginx's access log for /catalog/* and /.well-known/* activity —
labeled "catalog request activity" in the UI, not "monitoring/security":
Tier 0 has no auth and nothing enforces its advertised rate_limit, so
there's nothing security-relevant to show yet. No aggregation, no charts, no
persistence beyond the log file nginx already owns.

Requires the `static` service's log directory to be bind-mounted to a real
host directory (docker-compose.yml: ./static-logs:/var/log/nginx) — the
nginx:alpine image's default access.log is a symlink to /dev/stdout, which
this container can't read from a second, separate container.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

ACCESS_LOG_PATH = os.environ.get("NGINX_ACCESS_LOG", "/var/log/nginx/access.log")
_TRACKED_PREFIXES = ("/catalog/", "/.well-known/")
_MAX_LINES_READ = 2000

# nginx's "catalog_activity" format (nginx/default.conf) -- the stock
# "main" format (nginx/nginx.conf, the base image's own) with one field
# appended: the domain Tier 1's own auth_request already proved for a
# /catalog/contact.json hit, captured via auth_request_set in
# nginx/tier0-tier1-locations.conf (empty for every other request -- Tier 1
# proves a domain, and until this field existed that proof was computed and
# then simply discarded, never reaching this admin view or anywhere else).
# The trailing group is optional and unanchored so lines still written in
# the plain "main" format (the mTLS :443 listener, which never touches
# Tier 1, keeps that format -- see tls-listeners.conf) still parse.
_LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d+) (?P<bytes>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
    r'(?: "(?:[^"]*)" verified_domain="(?P<verified_domain>[^"]*)")?'
)


@dataclass
class LogEntry:
    ip: str
    time: str
    method: str
    path: str
    status: int
    user_agent: str
    verified_domain: str | None = None


def parse_line(line: str) -> LogEntry | None:
    match = _LOG_RE.match(line)
    if not match:
        return None
    return LogEntry(
        ip=match.group("ip"),
        time=match.group("time"),
        method=match.group("method"),
        path=match.group("path"),
        status=int(match.group("status")),
        user_agent=match.group("user_agent"),
        verified_domain=match.group("verified_domain") or None,
    )


def recent_catalog_requests(limit: int = 100) -> list[LogEntry]:
    """Newest-first. Malformed lines are skipped, not fatal — an admin tool
    showing partial activity beats crashing on one bad line."""
    if not os.path.exists(ACCESS_LOG_PATH):
        return []

    with open(ACCESS_LOG_PATH, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()[-_MAX_LINES_READ:]

    entries = [e for line in lines if (e := parse_line(line)) and e.path.startswith(_TRACKED_PREFIXES)]
    entries.reverse()
    return entries[:limit]
