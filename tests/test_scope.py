from vapt_agent.models import ScopeModel
from vapt_agent.scope import check, validate_scope


def scope(**kw):
    base = dict(targets=["10.10.10.0/24"], exclusions=["10.10.10.1"], lab_attestation=True)
    base.update(kw)
    return ScopeModel(**base)


def test_in_scope_host_allowed():
    d = check(scope(), "10.10.10.5", tool="nmap")
    assert d.allowed


def test_exclusion_blocked():
    d = check(scope(), "10.10.10.1", tool="nmap")
    assert not d.allowed
    assert "exclusion" in d.reason


def test_outside_target_blocked():
    d = check(scope(), "8.8.8.8", tool="nmap")
    assert not d.allowed


def test_public_target_requires_opt_in():
    d = check(scope(targets=["93.184.216.34"], allow_public=False), "93.184.216.34", tool="nmap")
    assert not d.allowed
    assert "public" in d.reason


def test_public_target_allowed_with_opt_in():
    d = check(scope(targets=["93.184.216.34"], allow_public=True), "93.184.216.34", tool="nmap")
    assert d.allowed


def test_no_lab_attestation_blocks_everything():
    d = check(scope(lab_attestation=False), "10.10.10.5", tool="nmap")
    assert not d.allowed


def test_disallowed_tool_blocked():
    d = check(scope(allowed_tools=["nmap"]), "10.10.10.5", tool="metasploit")
    assert not d.allowed


def test_shell_metacharacters_rejected():
    d = check(scope(), "10.10.10.5; rm -rf /", tool="nmap")
    assert not d.allowed


def test_validate_scope_flags_huge_range():
    problems = validate_scope(scope(targets=["10.0.0.0/8"]))
    assert any("larger than" in p for p in problems)


def test_validate_scope_requires_targets():
    problems = validate_scope(scope(targets=[]))
    assert any("no targets" in p for p in problems)
