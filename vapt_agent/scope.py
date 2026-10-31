"""Scope enforcement. Every tool invocation and every ingested asset passes through here."""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from .models import ScopeModel

_SAFE = re.compile(r"^[A-Za-z0-9._:/\-\[\]%@?=&#]+$")   # no whitespace / shell metacharacters


@dataclass
class Decision:
    allowed: bool
    reason: str
    host: str = ""
    port: Optional[int] = None

    def __bool__(self) -> bool:
        return self.allowed


def _parse(raw: str) -> tuple[str, Optional[int]]:
    raw = raw.strip()
    if "://" in raw:
        u = urlparse(raw)
        return (u.hostname or ""), u.port
    if raw.count(":") == 1 and not raw.startswith("["):
        h, p = raw.split(":")
        if p.isdigit():
            return h, int(p)
    return raw.strip("[]"), None


def _net(entry: str):
    try:
        return ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return None


def _host_matches(host: str, entry: str) -> bool:
    entry_host, _ = _parse(entry)
    n = _net(entry_host)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if n is not None and ip is not None:
        return ip in n
    if n is not None and ip is None:
        return False
    host, entry_host = host.lower(), entry_host.lower()
    return host == entry_host or host.endswith("." + entry_host)


def _is_public(ip: ipaddress._BaseAddress) -> bool:
    return not (ip.is_private or ip.is_loopback or ip.is_link_local)


def check(scope: ScopeModel, raw: str, tool: str | None = None, resolve: bool = True) -> Decision:
    """Return an allow/deny Decision with a human-readable reason (written to the audit trail)."""
    if not raw or not _SAFE.match(raw):
        return Decision(False, "target contains characters that are not permitted")
    if not scope.lab_attestation:
        return Decision(False, "scope has no lab attestation: operator must confirm targets are organizer-provided lab systems")
    if tool and tool not in scope.allowed_tools:
        return Decision(False, f"tool '{tool}' is not in the authorised tool list")

    host, port = _parse(raw)
    if not host:
        return Decision(False, "could not parse a host from the target")
    if port and scope.allowed_ports is not None and port not in scope.allowed_ports:
        return Decision(False, f"port {port} is outside the authorised port list", host, port)

    for ex in scope.exclusions:
        if _host_matches(host, ex):
            return Decision(False, f"{host} matches exclusion '{ex}'", host, port)

    if not any(_host_matches(host, t) for t in scope.targets):
        return Decision(False, f"{host} is not inside any registered target", host, port)

    # Public addresses require an explicit, audited override.
    ips: list[ipaddress._BaseAddress] = []
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        if resolve:
            try:
                ips = [ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)]
            except (socket.gaierror, UnicodeError):
                ips = []
    for ip in ips:
        for ex in scope.exclusions:
            n = _net(_parse(ex)[0])
            if n is not None and ip in n:
                return Decision(False, f"{host} resolves to {ip}, which matches exclusion '{ex}'", host, port)
        if _is_public(ip) and not scope.allow_public:
            return Decision(False, f"{host} resolves to public address {ip}; public targets need allow_public=true "
                                   "(only for organizer-provided lab hosts)", host, port)
    return Decision(True, "inside registered scope", host, port)


def validate_scope(scope: ScopeModel) -> list[str]:
    """Sanity problems with a scope definition itself (empty, absurdly wide, etc.)."""
    problems = []
    if not scope.targets:
        problems.append("no targets registered")
    if not scope.lab_attestation:
        problems.append("lab attestation missing")
    for t in scope.targets:
        host, _ = _parse(t)
        n = _net(host)
        if n is not None and n.num_addresses > 1024:
            problems.append(f"target {t} is larger than a /22 ({n.num_addresses} addresses); narrow it")
        if not _SAFE.match(t):
            problems.append(f"target '{t}' has illegal characters")
        if n is not None and not scope.allow_public and any(_is_public(a) for a in (n.network_address, n.broadcast_address)):
            problems.append(f"target {t} is public; set allow_public only for organizer-provided lab hosts")
    return problems
