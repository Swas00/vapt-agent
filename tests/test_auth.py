"""Unit tests for vapt_agent/auth.py: token-map parsing, authentication, failure-log throttling,
dev-token file handling, and the guarantee that no error/banner ever leaks a configured token."""
from __future__ import annotations

import os
import stat

import pytest

from vapt_agent import auth
from vapt_agent.auth import AuthConfigError, AuthRegistry, parse_token_map

TOK_A = "alice-token-0123456789abcdef"
TOK_B = "bob-token-0123456789abcdefgh"


# ---- parse_token_map -------------------------------------------------------------------------

def test_parse_single_and_multiple_entries():
    assert parse_token_map(f"{TOK_A}:alice") == {TOK_A: "alice"}
    assert parse_token_map(f"{TOK_A}:alice,{TOK_B}:bob") == {TOK_A: "alice", TOK_B: "bob"}


def test_parse_tolerates_whitespace_and_trailing_comma():
    assert parse_token_map(f"  {TOK_A}:alice , {TOK_B}:bob ,") == {TOK_A: "alice", TOK_B: "bob"}


def test_parse_allows_colons_inside_the_token():
    token = "part1:part2:part3-0123456789"
    assert parse_token_map(f"{token}:alice") == {token: "alice"}


def test_parse_allows_two_tokens_for_one_identity():      # e.g. rotating a token without downtime
    got = parse_token_map(f"{TOK_A}:alice,{TOK_B}:alice")
    assert set(got.values()) == {"alice"} and len(got) == 2


@pytest.mark.parametrize("raw", ["", "   ", ",,,"])
def test_parse_rejects_no_entries(raw):
    with pytest.raises(AuthConfigError, match="no entries"):
        parse_token_map(raw)


@pytest.mark.parametrize("raw", ["justonetokenwithoutcolon0123456789", ":alice", f"{TOK_A}:"])
def test_parse_rejects_malformed_entries(raw):
    with pytest.raises(AuthConfigError, match="token:name"):
        parse_token_map(raw)


def test_parse_rejects_short_token():
    with pytest.raises(AuthConfigError, match="shorter than 16"):
        parse_token_map("short:alice")


def test_parse_rejects_token_with_internal_whitespace():
    with pytest.raises(AuthConfigError, match="whitespace"):
        parse_token_map("abcdefgh ijklmnopqrstuv:alice")


@pytest.mark.parametrize("name", ["-alice", ".alice", "ali ce", "ali/ce", "a" * 41, "ali;ce", "ali\"ce", "é"])
def test_parse_rejects_bad_identity_names(name):
    with pytest.raises(AuthConfigError, match="name must be"):
        parse_token_map(f"{TOK_A}:{name}")


@pytest.mark.parametrize("name", ["agent", "Agent", "AGENT", "system", "System"])
def test_parse_rejects_reserved_identities_case_insensitively(name):
    # "agent"/"system" are the audit log's own actors for automated decisions; a human who could
    # take either name could forge entries that read as machine-made.
    with pytest.raises(AuthConfigError, match="reserved"):
        parse_token_map(f"{TOK_A}:{name}")


def test_parse_rejects_duplicate_tokens():
    with pytest.raises(AuthConfigError, match="duplicate token"):
        parse_token_map(f"{TOK_A}:alice,{TOK_A}:bob")


def test_config_errors_never_contain_token_text():
    secret = "SUPERSECRETTOKENVALUE123456"
    bad_inputs = [f"{secret}:agent", f"{secret}:-bad", f"{secret}:alice,{secret}:bob",
                  f"{secret[:8]}:alice", f"{secret} x:alice"]
    for raw in bad_inputs:
        with pytest.raises(AuthConfigError) as exc:
            parse_token_map(raw)
        assert secret not in str(exc.value) and secret[:8] not in str(exc.value)


# ---- AuthRegistry.authenticate ---------------------------------------------------------------

@pytest.fixture
def registry():
    return AuthRegistry({TOK_A: "alice", TOK_B: "bob"})


def test_authenticate_returns_the_owning_identity(registry):
    assert registry.authenticate(TOK_A) == "alice"
    assert registry.authenticate(TOK_B) == "bob"


@pytest.mark.parametrize("presented", [None, "", "nope", TOK_A + "x", TOK_A[:-1], TOK_A[:5],
                                       TOK_A.upper(), " " + TOK_A, TOK_A + " ", "é" * 30])
def test_authenticate_rejects_everything_else(registry, presented):
    assert registry.authenticate(presented) is None


def test_authenticate_compares_against_every_token_without_short_circuiting(registry, monkeypatch):
    calls = []
    real = auth.hmac.compare_digest

    def counting(a, b):
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(auth.hmac, "compare_digest", counting)
    registry.authenticate(TOK_A)           # matches the FIRST token...
    assert len(calls) == 2                 # ...but both are still compared (no early exit)


# ---- failure-log throttle --------------------------------------------------------------------

def test_failure_log_throttled_per_client_within_window():
    r = AuthRegistry({TOK_A: "alice"})
    assert r.should_log_failure("1.2.3.4", now=1000.0) is True
    assert r.should_log_failure("1.2.3.4", now=1030.0) is False      # inside the 60s window
    assert r.should_log_failure("5.6.7.8", now=1030.0) is True       # a different client
    assert r.should_log_failure("1.2.3.4", now=1061.0) is True       # window elapsed


def test_failure_log_tracking_is_bounded():
    r = AuthRegistry({TOK_A: "alice"})
    for i in range(50):
        r.should_log_failure(f"10.0.0.{i}", max_clients=10, now=float(i))
    assert len(r._failure_seen) <= 10


# ---- dev token -------------------------------------------------------------------------------

def test_dev_token_created_with_owner_only_permissions(tmp_path):
    path = tmp_path / "sub" / ".dev_token"
    token = auth.load_dev_token(path)
    assert len(token) >= auth.MIN_TOKEN_LEN
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_dev_token_is_stable_across_loads(tmp_path):
    path = tmp_path / ".dev_token"
    assert auth.load_dev_token(path) == auth.load_dev_token(path)


def test_dev_token_regenerated_if_file_is_unusable(tmp_path):
    path = tmp_path / ".dev_token"
    path.write_text("short\n")
    token = auth.load_dev_token(path)
    assert token != "short" and len(token) >= auth.MIN_TOKEN_LEN


def test_dev_token_repairs_loose_permissions(tmp_path):
    path = tmp_path / ".dev_token"
    token = auth.load_dev_token(path)
    os.chmod(path, 0o644)
    assert auth.load_dev_token(path) == token
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


# ---- from_env / banner -----------------------------------------------------------------------

def test_from_env_uses_configured_tokens():
    r = AuthRegistry.from_env({auth.ENV_VAR: f"{TOK_A}:alice"})
    assert r.dev_mode is False and r.authenticate(TOK_A) == "alice"


@pytest.mark.parametrize("value", [None, "", "   "])
def test_from_env_falls_back_to_a_dev_token_when_unset_or_blank(tmp_path, value):
    env = {} if value is None else {auth.ENV_VAR: value}
    r = AuthRegistry.from_env(env, dev_token_path=tmp_path / ".dev_token")
    assert r.dev_mode is True
    assert r.identities() == [auth.DEV_IDENTITY]


def test_from_env_without_config_or_dev_path_is_an_error():
    with pytest.raises(AuthConfigError):
        AuthRegistry.from_env({})


def test_from_env_surfaces_malformed_config():
    with pytest.raises(AuthConfigError):
        AuthRegistry.from_env({auth.ENV_VAR: "short:alice"})


def test_banner_shows_token_only_in_dev_mode(tmp_path):
    dev = AuthRegistry.from_env({}, dev_token_path=tmp_path / ".dev_token")
    dev_token = next(iter(dev.tokens))
    assert dev_token in auth.startup_banner(dev, tmp_path / ".dev_token")

    configured = AuthRegistry({TOK_A: "alice", TOK_B: "bob"})
    banner = auth.startup_banner(configured)
    assert TOK_A not in banner and TOK_B not in banner
    assert "alice" in banner and "bob" in banner
