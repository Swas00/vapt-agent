from vapt_agent.diff import compare
from vapt_agent.models import Assessment, Finding, ScopeModel


def _asm(findings):
    a = Assessment(request="retest", scope=ScopeModel(targets=["10.10.10.5"], lab_attestation=True))
    a.findings = findings
    return a


def _f(title, asset="10.10.10.5", port=80):
    return Finding(title=title, asset=asset, port=port)


def test_new_fixed_persisting_split():
    before = _asm([_f("SQLi"), _f("XSS"), _f("Old bug", port=22)])
    after = _asm([_f("SQLi"), _f("New bug", port=443)])

    d = compare(before, after)
    assert {f.title for f in d["new"]} == {"New bug"}
    assert {f.title for f in d["fixed"]} == {"XSS", "Old bug"}
    assert {f.title for f in d["persisting"]} == {"SQLi"}
    assert (d["new_count"], d["fixed_count"], d["persisting_count"]) == (1, 2, 1)
    assert d["before_id"] == before.id and d["after_id"] == after.id


def test_matching_ignores_case_and_surrounding_whitespace_on_asset_and_title():
    before = _asm([_f("SQL Injection", asset="10.10.10.5")])
    after = _asm([_f("  sql injection  ", asset="10.10.10.5")])

    d = compare(before, after)
    assert d["new"] == [] and d["fixed"] == []
    assert len(d["persisting"]) == 1


def test_same_title_different_port_is_a_distinct_finding_not_a_match():
    before = _asm([_f("Weak TLS", port=443)])
    after = _asm([_f("Weak TLS", port=8443)])

    d = compare(before, after)
    assert len(d["new"]) == 1 and len(d["fixed"]) == 1 and d["persisting"] == []


def test_identical_scans_produce_no_new_or_fixed():
    findings = [_f("SQLi"), _f("XSS", port=443)]
    before = _asm(findings)
    after = _asm(list(findings))     # same Finding objects, as a second "scan" would still have

    d = compare(before, after)
    assert d["new"] == [] and d["fixed"] == []
    assert len(d["persisting"]) == 2
