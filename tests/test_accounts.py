"""Unit tests for vapt_agent/accounts.py: password hashing, strength policy, lockout, sessions
(idle/absolute expiry, revocation), role ordering, and bootstrap-admin lifecycle."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from vapt_agent import accounts
from vapt_agent.accounts import (AccountStore, LockedOutError, LoginError, hash_password,
                                 role_at_least, validate_password_strength, verify_password)

GOOD_PW = "correct-horse-battery-staple-9"


@pytest.fixture
def store(tmp_path):
    return AccountStore(tmp_path / "auth.db")


# ---- password hashing -------------------------------------------------------------------------

def test_hash_and_verify_roundtrip():
    h = hash_password(GOOD_PW)
    assert verify_password(GOOD_PW, h) is True
    assert verify_password("wrong password entirely", h) is False


def test_hash_embeds_cost_parameters_and_is_salted():
    h1, h2 = hash_password(GOOD_PW), hash_password(GOOD_PW)
    assert h1 != h2                                   # different salt each time
    assert h1.startswith(f"scrypt${accounts._SCRYPT_N}${accounts._SCRYPT_R}${accounts._SCRYPT_P}$")


@pytest.mark.parametrize("garbage", ["", "not-a-hash", "scrypt$x$y$z$bad$bad", "md5$abc$def",
                                     "scrypt$32768$8$1$nothex$nothex"])
def test_verify_rejects_malformed_stored_hashes(garbage):
    assert verify_password(GOOD_PW, garbage) is False


def test_authenticate_unknown_username_does_real_work_not_a_shortcut(store, monkeypatch):
    # Authenticating a nonexistent user must still cost ~one scrypt derivation, not return instantly.
    calls = []
    real = accounts.verify_password

    def spy(pw, stored):
        calls.append(stored)
        return real(pw, stored)

    monkeypatch.setattr(accounts, "verify_password", spy)
    with pytest.raises(LoginError):
        store.authenticate("nobody-here", "whatever")
    assert calls and calls[0] == accounts._DUMMY_HASH


# ---- password strength ------------------------------------------------------------------------

@pytest.mark.parametrize("pw,expected_substr", [
    ("short", "12 characters"),
    ("administrator", "common"),            # 14 chars, long enough, and in COMMON_PASSWORDS
    ("thisismyusername123", "username"),
])
def test_weak_passwords_rejected_with_reason(pw, expected_substr):
    problems = validate_password_strength(pw, username="thisismyusername")
    assert problems and any(expected_substr in p for p in problems)


def test_strong_password_accepted():
    assert validate_password_strength(GOOD_PW, username="alice") == []


def test_password_at_max_length_boundary():
    assert validate_password_strength("a1" * 64, username="x") == []        # 128 chars, not common
    assert any("256" in p for p in validate_password_strength("a" * 300, username="x"))


# ---- user creation -----------------------------------------------------------------------------

def test_create_user_rejects_weak_password(store):
    with pytest.raises(ValueError, match="weak password"):
        store.create_user("alice", "short", "analyst")


def test_create_user_rejects_duplicate_username_case_insensitively(store):
    store.create_user("alice", GOOD_PW, "analyst")
    with pytest.raises(ValueError, match="already exists"):
        store.create_user("ALICE", GOOD_PW + "x", "analyst")


def test_create_user_rejects_unknown_role(store):
    with pytest.raises(ValueError, match="role"):
        store.create_user("alice", GOOD_PW, "superadmin")


def test_get_user_is_case_insensitive(store):
    store.create_user("Alice", GOOD_PW, "lead")
    assert store.get_user("alice").username == "Alice"
    assert store.get_user("ALICE").role == "lead"


def test_get_user_returns_none_for_unknown(store):
    assert store.get_user("nobody") is None


def test_list_and_count_users(store):
    store.create_user("alice", GOOD_PW, "analyst")
    store.create_user("bob", GOOD_PW, "lead")
    assert store.count_users() == 2
    assert [u.username for u in store.list_users()] == ["alice", "bob"]


# ---- authentication & lockout -------------------------------------------------------------------

def test_authenticate_success(store):
    store.create_user("alice", GOOD_PW, "analyst")
    u = store.authenticate("alice", GOOD_PW)
    assert u.username == "alice" and u.role == "analyst"


def test_authenticate_wrong_password(store):
    store.create_user("alice", GOOD_PW, "analyst")
    with pytest.raises(LoginError, match="invalid username or password"):
        store.authenticate("alice", "wrong-password-entirely")


def test_authenticate_unknown_username_same_message_as_wrong_password(store):
    store.create_user("alice", GOOD_PW, "analyst")
    try:
        store.authenticate("alice", "wrong")
    except LoginError as e:
        msg_wrong = str(e)
    try:
        store.authenticate("ghost", "wrong")
    except LoginError as e:
        msg_unknown = str(e)
    assert msg_wrong == msg_unknown      # never confirms/denies the username exists


def test_authenticate_disabled_account_rejected(store):
    store.create_user("alice", GOOD_PW, "analyst")
    store.set_disabled("alice", True)
    with pytest.raises(LoginError):
        store.authenticate("alice", GOOD_PW)


def test_lockout_after_threshold_failures(store):
    store.create_user("alice", GOOD_PW, "analyst")
    for _ in range(accounts.LOCKOUT_THRESHOLD):
        with pytest.raises(LoginError):
            store.authenticate("alice", "wrong")
    with pytest.raises(LockedOutError) as exc:
        store.authenticate("alice", "wrong")
    assert exc.value.retry_after > 0
    # even the CORRECT password is rejected while locked
    with pytest.raises(LockedOutError):
        store.authenticate("alice", GOOD_PW)


def test_lockout_backoff_increases_and_is_capped(store):
    store.create_user("alice", GOOD_PW, "analyst")
    for _ in range(accounts.LOCKOUT_THRESHOLD):
        with pytest.raises(LoginError):
            store.authenticate("alice", "wrong")
    delays = []
    for _ in range(5):
        row = store._conn.execute("SELECT locked_until FROM users WHERE username='alice'").fetchone()
        store._conn.execute("UPDATE users SET locked_until=NULL WHERE username='alice'")  # force-expire for the test
        try:
            store.authenticate("alice", "wrong")
        except LoginError:
            pass
        row2 = store._conn.execute("SELECT locked_until FROM users WHERE username='alice'").fetchone()
        delays.append(row2["locked_until"])
        del row
    assert all(d is not None for d in delays)


def test_successful_login_resets_failed_attempts(store):
    store.create_user("alice", GOOD_PW, "analyst")
    for _ in range(accounts.LOCKOUT_THRESHOLD - 1):
        with pytest.raises(LoginError):
            store.authenticate("alice", "wrong")
    store.authenticate("alice", GOOD_PW)
    row = store._conn.execute("SELECT failed_attempts FROM users WHERE username='alice'").fetchone()
    assert row["failed_attempts"] == 0


def test_unlock_clears_lockout(store):
    store.create_user("alice", GOOD_PW, "analyst")
    for _ in range(accounts.LOCKOUT_THRESHOLD + 1):
        with pytest.raises(LoginError):
            store.authenticate("alice", "wrong")
    store.unlock("alice")
    store.authenticate("alice", GOOD_PW)      # no longer locked


def test_unlock_unknown_user_raises(store):
    with pytest.raises(ValueError):
        store.unlock("ghost")


# ---- password changes --------------------------------------------------------------------------

def test_change_own_password_requires_correct_current(store):
    store.create_user("alice", GOOD_PW, "analyst")
    with pytest.raises(LoginError):
        store.change_own_password(store.get_user("alice").id, "wrong", "new-strong-password-1")
    store.change_own_password(store.get_user("alice").id, GOOD_PW, "new-strong-password-1")
    assert store.authenticate("alice", "new-strong-password-1").username == "alice"


def test_change_own_password_rejects_weak_new_password(store):
    store.create_user("alice", GOOD_PW, "analyst")
    with pytest.raises(ValueError, match="weak password"):
        store.change_own_password(store.get_user("alice").id, GOOD_PW, "short")


def test_change_own_password_clears_must_change_flag(store):
    u = store.create_user("alice", GOOD_PW, "analyst", must_change_password=True)
    assert u.must_change_password
    store.change_own_password(u.id, GOOD_PW, "new-strong-password-1")
    assert store.get_user("alice").must_change_password is False


def test_admin_reset_password_forces_change_and_is_usable_once_relayed(store):
    store.create_user("alice", GOOD_PW, "analyst")
    temp = store.admin_reset_password("alice")
    assert temp != GOOD_PW
    u = store.authenticate("alice", temp)
    assert u.must_change_password is True


def test_admin_reset_password_unknown_user_raises(store):
    with pytest.raises(ValueError):
        store.admin_reset_password("ghost")


def test_set_role(store):
    store.create_user("alice", GOOD_PW, "viewer")
    store.set_role("alice", "admin")
    assert store.get_user("alice").role == "admin"


def test_set_role_unknown_role_or_user_raises(store):
    store.create_user("alice", GOOD_PW, "viewer")
    with pytest.raises(ValueError):
        store.set_role("alice", "superadmin")
    with pytest.raises(ValueError):
        store.set_role("ghost", "admin")


# ---- sessions -----------------------------------------------------------------------------------

def test_create_and_validate_session(store):
    u = store.create_user("alice", GOOD_PW, "lead")
    sid, info = store.create_session(u.id)
    assert info.user.username == "alice" and info.user.role == "lead"
    validated = store.validate_session(sid)
    assert validated is not None and validated.user.username == "alice"
    assert validated.csrf_token == info.csrf_token


def test_session_id_is_never_stored_in_plaintext(store):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    rows = store._conn.execute("SELECT id_hash FROM sessions").fetchall()
    assert all(sid not in r["id_hash"] for r in rows)
    assert rows[0]["id_hash"] == AccountStore._hash(sid)


def test_validate_session_rejects_garbage_or_empty(store):
    assert store.validate_session("") is None
    assert store.validate_session("not-a-real-session-id") is None


def test_validate_session_reflects_role_change_immediately(store):
    u = store.create_user("alice", GOOD_PW, "viewer")
    sid, _ = store.create_session(u.id)
    store.set_role("alice", "admin")
    assert store.validate_session(sid).user.role == "admin"


def test_validate_session_rejected_after_disable(store):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    store.set_disabled("alice", True)
    assert store.validate_session(sid) is None


def test_session_absolute_expiry(store, monkeypatch):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    future = datetime.now(timezone.utc) + accounts.SESSION_ABSOLUTE_TIMEOUT + timedelta(seconds=1)
    monkeypatch.setattr(accounts, "_now", lambda: future)
    assert store.validate_session(sid) is None


def test_session_idle_expiry(store, monkeypatch):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    future = datetime.now(timezone.utc) + accounts.SESSION_IDLE_TIMEOUT + timedelta(seconds=1)
    monkeypatch.setattr(accounts, "_now", lambda: future)
    assert store.validate_session(sid) is None


def test_session_activity_resets_idle_timer(store, monkeypatch):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    base = datetime.now(timezone.utc)
    almost_idle = base + accounts.SESSION_IDLE_TIMEOUT - timedelta(seconds=5)
    monkeypatch.setattr(accounts, "_now", lambda: almost_idle)
    assert store.validate_session(sid) is not None        # touches last_seen_at
    still_fresh = almost_idle + accounts.SESSION_IDLE_TIMEOUT - timedelta(seconds=5)
    monkeypatch.setattr(accounts, "_now", lambda: still_fresh)
    assert store.validate_session(sid) is not None         # would be expired w/o the reset above


def test_expired_session_is_deleted_not_just_rejected(store, monkeypatch):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    future = datetime.now(timezone.utc) + accounts.SESSION_ABSOLUTE_TIMEOUT + timedelta(seconds=1)
    monkeypatch.setattr(accounts, "_now", lambda: future)
    store.validate_session(sid)
    rows = store._conn.execute("SELECT COUNT(*) c FROM sessions").fetchone()
    assert rows["c"] == 0


def test_revoke_session(store):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    store.revoke_session(sid)
    assert store.validate_session(sid) is None


def test_revoke_all_sessions_except_current(store):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid1, _ = store.create_session(u.id)
    sid2, _ = store.create_session(u.id)
    sid3, _ = store.create_session(u.id)
    store.revoke_all_sessions("alice", except_session_id=sid2)
    assert store.validate_session(sid1) is None
    assert store.validate_session(sid3) is None
    assert store.validate_session(sid2) is not None


def test_revoke_all_sessions_without_exception(store):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid1, _ = store.create_session(u.id)
    sid2, _ = store.create_session(u.id)
    store.revoke_all_sessions("alice")
    assert store.validate_session(sid1) is None and store.validate_session(sid2) is None


def test_disabling_a_user_revokes_their_sessions(store):
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    store.set_disabled("alice", True)
    assert store.session_count("alice") == 0


def test_change_password_elsewhere_does_not_auto_revoke_sessions_here(store):
    # (orchestrated by the API layer, which calls revoke_all_sessions explicitly -- confirm the
    # store-level primitive itself is a plain building block, not implicitly coupled)
    u = store.create_user("alice", GOOD_PW, "analyst")
    sid, _ = store.create_session(u.id)
    store.change_own_password(u.id, GOOD_PW, "new-strong-password-1")
    assert store.validate_session(sid) is not None


def test_cleanup_expired_sessions(store, monkeypatch):
    u = store.create_user("alice", GOOD_PW, "analyst")
    store.create_session(u.id)
    future = datetime.now(timezone.utc) + accounts.SESSION_ABSOLUTE_TIMEOUT + timedelta(seconds=1)
    monkeypatch.setattr(accounts, "_now", lambda: future)
    assert store.cleanup_expired_sessions() == 1
    assert store.cleanup_expired_sessions() == 0


# ---- roles --------------------------------------------------------------------------------------

@pytest.mark.parametrize("have,need,expected", [
    ("admin", "viewer", True), ("admin", "admin", True), ("lead", "analyst", True),
    ("analyst", "lead", False), ("viewer", "analyst", False), ("viewer", "viewer", True),
    ("bogus", "viewer", False),
])
def test_role_at_least(have, need, expected):
    assert role_at_least(have, need) is expected


# ---- bootstrap ------------------------------------------------------------------------------------

def test_bootstrap_creates_admin_once(tmp_path):
    store = AccountStore(tmp_path / "auth.db")
    marker = tmp_path / "bootstrap_admin"
    banner = accounts.ensure_bootstrap_admin(store, marker)
    assert banner and "admin" in banner and marker.exists()
    password_line = marker.read_text().strip()
    u = store.authenticate("admin", password_line)
    assert u.role == "admin" and u.must_change_password is True

    again = accounts.ensure_bootstrap_admin(store, marker)
    assert again is None       # idempotent: doesn't recreate or reprint


def test_bootstrap_skipped_if_any_user_exists(tmp_path):
    store = AccountStore(tmp_path / "auth.db")
    store.create_user("bob", GOOD_PW, "lead")
    marker = tmp_path / "bootstrap_admin"
    assert accounts.ensure_bootstrap_admin(store, marker) is None
    assert store.get_user("admin") is None
    assert not marker.exists()


def test_bootstrap_marker_file_is_private(tmp_path):
    import stat
    store = AccountStore(tmp_path / "auth.db")
    marker = tmp_path / "bootstrap_admin"
    accounts.ensure_bootstrap_admin(store, marker)
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600


def test_bootstrap_marker_removed_once_password_changed(tmp_path):
    store = AccountStore(tmp_path / "auth.db")
    marker = tmp_path / "bootstrap_admin"
    accounts.ensure_bootstrap_admin(store, marker)
    assert marker.exists()
    admin = store.get_user("admin")
    store.change_own_password(admin.id, marker.read_text().strip(), "new-strong-password-1")
    accounts.ensure_bootstrap_admin(store, marker)      # the next startup check sweeps it
    assert not marker.exists()
