"""Real accounts: username/password login, server-side sessions, and roles -- the system CR-1's
bearer-token-per-analyst scheme has been replaced with. Backed by SQLite (stdlib, one file:
data/auth.db) rather than a new service dependency.

Design choices, and why:

- **Passwords are hashed with scrypt** (`hashlib.scrypt`, stdlib, memory-hard) at N=2^15, r=8, p=1
  (~60ms/verify on this machine -- measured, not guessed). The cost parameters are stored inside
  the hash string itself (`scrypt$n$r$p$salt$hash`), so they can be raised later without
  invalidating existing hashes.
- **Password policy is length + blocklist, not composition rules** (NIST SP 800-63B §5.1.1.2:
  composition rules push users toward predictable patterns and don't meaningfully raise entropy).
  Minimum 12 characters, rejected if it equals/contains the username, rejected if it's one of a
  few hundred of the most common leaked passwords (COMMON_PASSWORDS below) -- not exhaustive, one
  layer among several, not the only control.
- **Sessions are opaque random ids; only a SHA-256 of the id is ever stored**, mirroring how this
  project already treats every other secret (never the token/password itself at rest). A session
  can be presented two ways: an HttpOnly cookie (the browser UI) or an explicit
  `Authorization: Bearer <session id>` header (scripts/API clients). Only the cookie path needs
  CSRF protection, because a cross-site page can make the browser *attach a cookie* automatically
  but cannot make it *set a custom header* -- see api.py's `require_login`.
- **Lockout is per-account (exponential backoff after a threshold) and the login attempt is
  constant-time against an unknown username** (a fixed dummy hash is verified either way), so a
  login failure doesn't reveal whether the username exists.
- **Roles are ordered**: viewer < analyst < lead < admin. Requesting active validation needs
  `analyst`; *approving or executing* it needs `lead` -- a real separation of duties, not just "any
  authenticated person."
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------

ROLES = ("viewer", "analyst", "lead", "admin")
ROLE_RANK = {r: i for i, r in enumerate(ROLES)}


def role_at_least(have: str, need: str) -> bool:
    return ROLE_RANK.get(have, -1) >= ROLE_RANK[need]


# ---------------------------------------------------------------------------
# Password hashing (scrypt, cost parameters embedded in the stored string)
# ---------------------------------------------------------------------------

_SCRYPT_N, _SCRYPT_R, _SCRYPT_P, _DKLEN = 2**15, 8, 1, 32
_SCRYPT_MAXMEM = 64 * 1024 * 1024


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p,
                          maxmem=_SCRYPT_MAXMEM, dklen=_DKLEN)


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = _scrypt(password, salt, _SCRYPT_N, _SCRYPT_R, _SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        derived = _scrypt(password, bytes.fromhex(salt_hex), int(n), int(r), int(p))
        return hmac.compare_digest(derived, bytes.fromhex(hash_hex))
    except (ValueError, TypeError):
        return False


# A real hash of a fixed (never used-for-login) password/salt, computed once at import time, so
# authenticate() against a nonexistent username still does a full scrypt derivation -- the time an
# attacker observes doesn't tell them whether the username exists.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(32))

# Deliberately not exhaustive -- a small, well-known slice of the most common leaked passwords.
# One layer of defense alongside length + the username check, never the only one.
COMMON_PASSWORDS = frozenset(w.lower() for w in """
123456 123456789 12345678 12345 1234567 password 123123 qwerty qwertyuiop 111111
1q2w3e4r 000000 iloveyou 1234 abc123 654321 qwerty123 1q2w3e dragon letmein
monkey football baseball master shadow superman michael jennifer jordan hunter
trustno1 passw0rd welcome admin administrator login princess sunshine flower
freedom whatever nicole chelsea biteme matrix tigger cheese thomas hockey
ranger daniel starwars klaster 123321 654321a a123456 zxcvbnm asdfghjkl
password1 password123 abcd1234 changeme letmein123 qwerty1 1qaz2wsx
access yankees summer internet service canada hello ginger bailey
secret cookie coffee charlie 7777777 1qazxsw2 qazwsx computer michelle
jessica pepper zxcvbn 11111111 target121 mustang george harley
newyork nascar donald liverpool chicken soccer baseball1
""".split())


def validate_password_strength(password: str, username: str = "") -> list[str]:
    """Returns a list of problems (empty = acceptable). NIST 800-63B style: length + blocklist +
    "don't be the username," not composition rules."""
    problems = []
    if len(password) < 12:
        problems.append("must be at least 12 characters")
    if len(password) > 256:
        problems.append("must be at most 256 characters")
    low = password.lower()
    if username and username.lower() in low:
        problems.append("must not contain the username")
    if low in COMMON_PASSWORDS:
        problems.append("is one of the most common leaked passwords -- choose another")
    return problems


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass
class User:
    id: int
    username: str
    role: str
    must_change_password: bool
    disabled: bool


@dataclass
class SessionInfo:
    user: User
    csrf_token: str
    expires_at: datetime


class LoginError(Exception):
    """Raised for an unsuccessful login. `message` is safe to show the caller; it never confirms
    or denies whether the username exists."""


class LockedOutError(LoginError):
    def __init__(self, retry_after: float):
        self.retry_after = retry_after
        super().__init__(f"account temporarily locked; retry after {int(retry_after)}s")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _parse(s: str) -> datetime:
    return datetime.fromisoformat(s)


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

SESSION_IDLE_TIMEOUT = timedelta(minutes=30)
SESSION_ABSOLUTE_TIMEOUT = timedelta(hours=12)
LOCKOUT_THRESHOLD = 5          # failed attempts tolerated before any lockout
LOCKOUT_BASE_SECONDS = 30      # doubles per attempt past the threshold
LOCKOUT_CAP_SECONDS = 3600


class AccountStore:
    """All access goes through one lock: sqlite3 connections aren't safe to share across threads,
    and FastAPI's sync routes run in a thread pool. Fine at this scale (a handful of analysts);
    not a bottleneck worth a connection pool for a hackathon-scoped tool."""

    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('viewer','analyst','lead','admin')),
                    created_at TEXT NOT NULL,
                    password_changed_at TEXT NOT NULL,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until TEXT,
                    disabled INTEGER NOT NULL DEFAULT 0
                )""")
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    csrf_token TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                )""")

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> User:
        return User(id=row["id"], username=row["username"], role=row["role"],
                   must_change_password=bool(row["must_change_password"]),
                   disabled=bool(row["disabled"]))

    # ---- users ---------------------------------------------------------

    def create_user(self, username: str, password: str, role: str,
                    must_change_password: bool = False) -> User:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        problems = validate_password_strength(password, username)
        if problems:
            raise ValueError("weak password: " + "; ".join(problems))
        now = _iso(_now())
        with self._lock, self._conn:
            try:
                cur = self._conn.execute(
                    "INSERT INTO users (username, password_hash, role, created_at, "
                    "password_changed_at, must_change_password) VALUES (?,?,?,?,?,?)",
                    (username, hash_password(password), role, now, now, int(must_change_password)))
            except sqlite3.IntegrityError:
                raise ValueError(f"username {username!r} already exists") from None
            row = self._conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        return self._row_to_user(row)

    def get_user(self, username: str) -> Optional[User]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return self._row_to_user(row) if row else None

    def list_users(self) -> list[User]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM users ORDER BY username").fetchall()
        return [self._row_to_user(r) for r in rows]

    def count_users(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def set_role(self, username: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError(f"unknown role {role!r}")
        with self._lock, self._conn:
            cur = self._conn.execute("UPDATE users SET role=? WHERE username=?", (role, username))
            if cur.rowcount == 0:
                raise ValueError(f"no such user {username!r}")

    def set_disabled(self, username: str, disabled: bool) -> None:
        with self._lock, self._conn:
            cur = self._conn.execute("UPDATE users SET disabled=? WHERE username=?",
                                     (int(disabled), username))
            if cur.rowcount == 0:
                raise ValueError(f"no such user {username!r}")
        if disabled:
            self.revoke_all_sessions(username)

    def unlock(self, username: str) -> None:
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=?", (username,))
            if cur.rowcount == 0:
                raise ValueError(f"no such user {username!r}")

    def _set_password(self, username: str, new_password: str, must_change: bool) -> None:
        problems = validate_password_strength(new_password, username)
        if problems:
            raise ValueError("weak password: " + "; ".join(problems))
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE users SET password_hash=?, password_changed_at=?, must_change_password=?, "
                "failed_attempts=0, locked_until=NULL WHERE username=?",
                (hash_password(new_password), _iso(_now()), int(must_change), username))

    def admin_reset_password(self, username: str) -> str:
        """Generates and sets a new temporary password (forcing a change at next login); returns
        it once. The caller (an admin) must relay it to the user out-of-band."""
        if not self.get_user(username):
            raise ValueError(f"no such user {username!r}")
        temp = secrets.token_urlsafe(18)
        self._set_password(username, temp, must_change=True)
        return temp

    def change_own_password(self, user_id: int, current_password: str, new_password: str) -> None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None or not verify_password(current_password, row["password_hash"]):
            raise LoginError("current password is incorrect")
        self._set_password(row["username"], new_password, must_change=False)

    # ---- authentication --------------------------------------------------

    def authenticate(self, username: str, password: str) -> User:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()

        if row is None:
            verify_password(password, _DUMMY_HASH)              # constant-time: do the work anyway
            raise LoginError("invalid username or password")

        if row["disabled"]:
            verify_password(password, _DUMMY_HASH)
            raise LoginError("invalid username or password")

        locked_until = _parse(row["locked_until"]) if row["locked_until"] else None
        if locked_until and _now() < locked_until:
            verify_password(password, _DUMMY_HASH)
            raise LockedOutError((locked_until - _now()).total_seconds())

        if not verify_password(password, row["password_hash"]):
            backoff = self._record_failure(row["id"], row["failed_attempts"])
            if backoff is not None:
                raise LockedOutError(backoff)         # this attempt is the one that triggers the lock
            raise LoginError("invalid username or password")

        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (row["id"],))
        return self._row_to_user(row)

    def _record_failure(self, user_id: int, prior_failures: int) -> Optional[float]:
        """Records one more failed attempt. Returns the lockout duration in seconds if this
        specific failure is the one that triggers (or extends) a lock, else None."""
        attempts = prior_failures + 1
        locked_until = None
        backoff = None
        if attempts > LOCKOUT_THRESHOLD:
            backoff = min(LOCKOUT_BASE_SECONDS * (2 ** (attempts - LOCKOUT_THRESHOLD - 1)),
                         LOCKOUT_CAP_SECONDS)
            locked_until = _iso(_now() + timedelta(seconds=backoff))
        with self._lock, self._conn:
            self._conn.execute(
                "UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?",
                (attempts, locked_until, user_id))
        return backoff

    # ---- sessions ----------------------------------------------------------

    def create_session(self, user_id: int) -> tuple[str, SessionInfo]:
        session_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        now = _now()
        expires = now + SESSION_ABSOLUTE_TIMEOUT
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen_at, "
                "expires_at) VALUES (?,?,?,?,?,?)",
                (self._hash(session_id), user_id, csrf_token, _iso(now), _iso(now), _iso(expires)))
            row = self._conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        return session_id, SessionInfo(user=self._row_to_user(row), csrf_token=csrf_token,
                                       expires_at=expires)

    @staticmethod
    def _hash(session_id: str) -> str:
        return hashlib.sha256(session_id.encode("utf-8")).hexdigest()

    def validate_session(self, session_id: str) -> Optional[SessionInfo]:
        """Checks idle + absolute expiry, bumps last_seen_at, and returns the CURRENT role/disabled
        state of the owning user (a role change or disablement takes effect immediately, not only
        on next login)."""
        if not session_id:
            return None
        id_hash = self._hash(session_id)
        now = _now()
        with self._lock:
            row = self._conn.execute(
                "SELECT s.*, u.username, u.role, u.must_change_password, u.disabled "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash=?",
                (id_hash,)).fetchone()
            if row is None:
                return None
            expires_at, last_seen = _parse(row["expires_at"]), _parse(row["last_seen_at"])
            if now >= expires_at or now - last_seen > SESSION_IDLE_TIMEOUT or row["disabled"]:
                with self._conn:
                    self._conn.execute("DELETE FROM sessions WHERE id_hash=?", (id_hash,))
                return None
            with self._conn:
                self._conn.execute("UPDATE sessions SET last_seen_at=? WHERE id_hash=?",
                                   (_iso(now), id_hash))
        user = User(id=row["user_id"], username=row["username"], role=row["role"],
                   must_change_password=bool(row["must_change_password"]), disabled=False)
        return SessionInfo(user=user, csrf_token=row["csrf_token"], expires_at=expires_at)

    def revoke_session(self, session_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("DELETE FROM sessions WHERE id_hash=?", (self._hash(session_id),))

    def revoke_all_sessions(self, username: str, except_session_id: str | None = None) -> None:
        keep = self._hash(except_session_id) if except_session_id else None
        with self._lock, self._conn:
            if keep:
                self._conn.execute(
                    "DELETE FROM sessions WHERE id_hash != ? AND user_id = "
                    "(SELECT id FROM users WHERE username=?)", (keep, username))
            else:
                self._conn.execute(
                    "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username=?)",
                    (username,))

    def session_count(self, username: str) -> int:
        with self._lock:
            return self._conn.execute(
                "SELECT COUNT(*) FROM sessions WHERE user_id = "
                "(SELECT id FROM users WHERE username=?)", (username,)).fetchone()[0]

    def cleanup_expired_sessions(self) -> int:
        now = _iso(_now())
        with self._lock, self._conn:
            cur = self._conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
            return cur.rowcount


# ---------------------------------------------------------------------------
# Bootstrap: first-run admin account
# ---------------------------------------------------------------------------

def ensure_bootstrap_admin(store: AccountStore, marker_path: Path,
                           fixed_password: Optional[str] = None) -> Optional[str]:
    """On a store with no users at all, create 'admin' with a password that must be changed at
    first login, and persist it (mode 0600) so a restart before first login doesn't orphan the
    account. The file is deleted once that admin account is no longer pending a forced change
    (first login + password change), so a plaintext password doesn't sit on disk forever.

    `fixed_password`, if given (from the VAPT_BOOTSTRAP_ADMIN_PASSWORD env var), is used instead
    of a freshly random one -- for a deployment whose disk is wiped on every restart (e.g. a free
    hosting tier with no persistent volume), a random password is only ever visible in that
    restart's own logs, which an external visitor has no way to read; a fixed, documented password
    keeps the account reachable across those resets while still forcing a real password change at
    first login, same as the random-password path. Falls back to random if unset, which is the
    only reasonable default for a deployment that genuinely does persist its disk.
    Returns the startup banner text, or None if no bootstrap was needed."""
    marker_path = Path(marker_path)
    admin = store.get_user("admin")
    if admin is not None:
        if not admin.must_change_password and marker_path.exists():
            marker_path.unlink(missing_ok=True)      # setup completed since the last check
        return None
    if store.count_users() > 0:
        return None     # users exist under other names; nothing to bootstrap
    password = fixed_password or secrets.token_urlsafe(18)
    store.create_user("admin", password, "admin", must_change_password=True)
    import os
    fd = os.open(marker_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(password + "\n")
    os.chmod(marker_path, 0o600)
    source_note = " (from VAPT_BOOTSTRAP_ADMIN_PASSWORD)" if fixed_password else ""
    return (
        "\n" + "=" * 72 + "\n"
        "  No accounts exist -> created a bootstrap admin:\n\n"
        "      username: admin\n"
        f"      password: {password}{source_note}\n\n"
        "  You will be required to change this password at first login.\n"
        f"  (also persisted at {marker_path}, mode 0600, until the password is changed)\n"
        + "=" * 72 + "\n"
    )


# ---------------------------------------------------------------------------
# CLI recovery: `python -m vapt_agent.accounts reset-admin [--db PATH]`
# ---------------------------------------------------------------------------

def _cli() -> None:
    import argparse
    from .api import DATA_DIR

    parser = argparse.ArgumentParser(description="VAPT Agent account recovery")
    parser.add_argument("--db", default=str(DATA_DIR / "auth.db"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("reset-admin", help="unlock and issue a new temp password for an admin")
    rp.add_argument("--username", default="admin")
    sub.add_parser("list-users", help="list accounts (no password hashes)")

    args = parser.parse_args()
    store = AccountStore(args.db)
    if args.cmd == "reset-admin":
        store.unlock(args.username)
        temp = store.admin_reset_password(args.username)
        print(f"New temporary password for {args.username!r} (must be changed at next login):")
        print(f"  {temp}")
    elif args.cmd == "list-users":
        for u in store.list_users():
            flags = []
            if u.disabled:
                flags.append("disabled")
            if u.must_change_password:
                flags.append("must-change-password")
            print(f"  {u.username:20s} {u.role:8s}" + (f"  [{', '.join(flags)}]" if flags else ""))


if __name__ == "__main__":
    _cli()
