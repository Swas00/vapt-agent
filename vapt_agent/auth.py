"""Analyst authentication: bearer tokens mapped to *verified* identities.

Why per-analyst tokens rather than one shared secret: PS-1 §13 requires that "every action is
attributable through an audit trail." A single shared secret would prove "someone authorized did
this" but never *who*. Each token here maps to exactly one named analyst, and the API layer writes
that verified name -- never a value the client supplied -- into the audit log and the approval
records.

Configuration:
    VAPT_ANALYST_TOKENS="<token>:<name>,<token>:<name>"
      * token: >= 16 chars, no whitespace (generate with `python -c "import secrets;
        print(secrets.token_urlsafe(24))"`).
      * name:  1-40 chars of [A-Za-z0-9._-], starting alphanumeric. "agent" and "system" are
        reserved: the audit log uses them for automated decisions, so a human must not be able to
        take either name and forge an entry that reads like one.
    If the variable is unset/blank, a single dev token for the identity "analyst" is generated once
    and persisted (mode 0600) so reloads don't invalidate it. It is printed at startup. This keeps
    `uvicorn vapt_agent.api:app` zero-config for a local demo while still requiring a token.

Nothing here ever logs, echoes, or includes a token in an error message.
"""
from __future__ import annotations

import hmac
import os
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Optional

ENV_VAR = "VAPT_ANALYST_TOKENS"
MIN_TOKEN_LEN = 16
DEV_IDENTITY = "analyst"
RESERVED_IDENTITIES = frozenset({"agent", "system"})

_IDENTITY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$")
_WHITESPACE_RE = re.compile(r"\s")


class AuthConfigError(ValueError):
    """Raised for an invalid VAPT_ANALYST_TOKENS value. Messages never contain token text."""


def parse_token_map(raw: str) -> dict[str, str]:
    """Parse "token:name,token:name" into {token: name}, validating every entry."""
    entries = [e.strip() for e in raw.split(",") if e.strip()]
    if not entries:
        raise AuthConfigError(f"{ENV_VAR} is set but contains no entries")
    tokens: dict[str, str] = {}
    for i, entry in enumerate(entries, start=1):
        token, sep, identity = entry.rpartition(":")     # names can't contain ':'; tokens may
        if not sep or not token or not identity:
            raise AuthConfigError(f"{ENV_VAR} entry {i} is not in 'token:name' form")
        if _WHITESPACE_RE.search(token):
            raise AuthConfigError(f"{ENV_VAR} entry {i}: token must not contain whitespace")
        if len(token) < MIN_TOKEN_LEN:
            raise AuthConfigError(
                f"{ENV_VAR} entry {i}: token is shorter than {MIN_TOKEN_LEN} characters")
        if not _IDENTITY_RE.match(identity):
            raise AuthConfigError(
                f"{ENV_VAR} entry {i}: name must be 1-40 chars of [A-Za-z0-9._-], starting alphanumeric")
        if identity.lower() in RESERVED_IDENTITIES:
            raise AuthConfigError(
                f"{ENV_VAR} entry {i}: '{identity}' is reserved for automated audit-log actors")
        if token in tokens:
            raise AuthConfigError(f"{ENV_VAR} entry {i}: duplicate token")
        tokens[token] = identity
    return tokens


def load_dev_token(path: Path) -> str:
    """Return the persisted dev token, creating it (mode 0600) on first use."""
    path = Path(path)
    if path.exists():
        existing = path.read_text().strip()
        if len(existing) >= MIN_TOKEN_LEN and not _WHITESPACE_RE.search(existing):
            os.chmod(path, 0o600)                         # repair loose permissions if any
            return existing
    token = secrets.token_urlsafe(24)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(token + "\n")
    os.chmod(path, 0o600)
    return token


@dataclass
class AuthRegistry:
    tokens: dict[str, str]
    dev_mode: bool = False
    _failure_seen: dict[str, float] = field(default_factory=dict, repr=False)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None,
                 dev_token_path: Optional[Path] = None) -> "AuthRegistry":
        env = os.environ if env is None else env
        raw = env.get(ENV_VAR)
        if raw is not None and raw.strip():
            return cls(parse_token_map(raw))
        if dev_token_path is None:
            raise AuthConfigError(f"{ENV_VAR} is not set and no dev-token path was provided")
        return cls({load_dev_token(dev_token_path): DEV_IDENTITY}, dev_mode=True)

    def authenticate(self, presented: Optional[str]) -> Optional[str]:
        """Return the identity owning `presented`, or None. Compares against every known token
        without short-circuiting so response time doesn't reveal which prefix matched."""
        if not presented:
            return None
        presented_b = presented.encode("utf-8", "replace")
        found: Optional[str] = None
        for token, identity in self.tokens.items():
            if hmac.compare_digest(token.encode("utf-8"), presented_b):
                found = identity
        return found

    def identities(self) -> list[str]:
        return sorted(set(self.tokens.values()))

    def should_log_failure(self, client: str, window: float = 60.0, max_clients: int = 1024,
                           now: Optional[float] = None) -> bool:
        """At most one audit entry per client per `window` seconds, so unauthenticated traffic
        can't grow the (append-only, hash-chained) audit log without bound."""
        now = time.monotonic() if now is None else now
        last = self._failure_seen.get(client)
        if last is not None and now - last < window:
            return False
        if len(self._failure_seen) >= max_clients:
            oldest = min(self._failure_seen, key=self._failure_seen.get)
            del self._failure_seen[oldest]
        self._failure_seen[client] = now
        return True


def startup_banner(registry: AuthRegistry, dev_token_path: Optional[Path] = None) -> str:
    """Human-readable startup notice. Only ever shows a token in dev mode, where the token is
    auto-generated and local; configured tokens are never printed."""
    if registry.dev_mode:
        token = next(iter(registry.tokens))
        return (
            "\n" + "=" * 72 + "\n"
            f"  {ENV_VAR} is not set -> DEV MODE\n"
            f"  Sign in to the UI as '{DEV_IDENTITY}' with this token:\n\n"
            f"      {token}\n\n"
            f"  (persisted at {dev_token_path}, mode 0600)\n"
            f"  For real analyst identities set {ENV_VAR}=\"<token>:<name>,...\"\n"
            + "=" * 72 + "\n"
        )
    names = ", ".join(registry.identities())
    return f"[auth] {len(registry.tokens)} analyst token(s) loaded for: {names}"
