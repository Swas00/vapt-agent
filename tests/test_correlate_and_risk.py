from vapt_agent.correlate import correlate
from vapt_agent.models import Finding, ScopeModel
from vapt_agent.risk import describe_cvss_vector, parse_cvss_vector, score


def test_duplicate_findings_merge_without_losing_evidence():
    a = Finding(title="MS17-010 SMB RCE", asset="10.10.10.5", port=445, source_tools=["nmap"],
               severity="critical", cve=["CVE-2017-0143"], confidence=0.6,
               evidence=[{"tool": "nmap", "raw_ref": "nmap:x#1", "snippet": "a"}])
    b = Finding(title="MS17-010: SMB Remote Code Execution", asset="10.10.10.5", port=445, source_tools=["nessus"],
               severity="high", cve=["CVE-2017-0143"], confidence=0.7,
               evidence=[{"tool": "nessus", "raw_ref": "nessus:y#1", "snippet": "b"}])
    merged = correlate([a, b])
    assert len(merged) == 1
    m = merged[0]
    assert set(m.source_tools) == {"nmap", "nessus"}
    assert len(m.evidence) == 2
    assert m.status == "confirmed"
    assert m.confidence > 0.7


def test_distinct_findings_on_different_ports_not_merged():
    a = Finding(title="Open port", asset="10.10.10.5", port=80, source_tools=["nmap"], severity="info")
    b = Finding(title="Open port", asset="10.10.10.5", port=443, source_tools=["nmap"], severity="info")
    merged = correlate([a, b])
    assert len(merged) == 2


def test_low_confidence_single_source_info_flagged_not_dropped():
    a = Finding(title="X-Content-Type-Options header missing", asset="10.10.10.5", port=80,
               source_tools=["nikto"], severity="info", confidence=0.3)
    merged = correlate([a])
    assert len(merged) == 1
    assert merged[0].status == "false_positive_candidate"


def test_risk_score_higher_for_validated_than_suspected():
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True)
    suspected = Finding(title="t", asset="10.10.10.5", port=80, severity="high", cvss=8.0, confidence=0.5)
    validated = suspected.model_copy(deep=True)
    validated.validation_status = "validated"
    validated.status = "confirmed"
    validated.confidence = 0.95
    score(suspected, scope)
    score(validated, scope)
    assert validated.risk_score > suspected.risk_score
    assert validated.priority in ("P1", "P2")


def test_fabricated_cvss_never_invented_only_estimated_and_flagged():
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True)
    f = Finding(title="t", asset="10.10.10.5", severity="medium", confidence=0.5)   # no cvss given
    score(f, scope)
    assert f.cvss_estimated is True
    assert f.cvss == 5.5   # from the medium band, not a fabricated per-finding number


def test_false_positive_candidate_scores_lower():
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True)
    a = Finding(title="t", asset="10.10.10.5", severity="medium", cvss=5.0, confidence=0.3, status="suspected")
    b = a.model_copy(deep=True)
    b.status = "false_positive_candidate"
    score(a, scope)
    score(b, scope)
    assert b.risk_score < a.risk_score


# F7: boundary tests for risk.score() -- confidence/CVSS at their exact limits, and an asset with
# no asset_criticality entry at all (the no-override default path).

def test_score_handles_confidence_exactly_zero_and_one():
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True)
    lo = Finding(title="t", asset="10.10.10.5", severity="medium", cvss=5.0, confidence=0.0)
    hi = lo.model_copy(deep=True)
    hi.confidence = 1.0
    score(lo, scope)
    score(hi, scope)
    assert lo.risk_breakdown["confidence_factor"] == 0.5    # 0.5 + 0.5*0
    assert hi.risk_breakdown["confidence_factor"] == 1.0    # 0.5 + 0.5*1
    assert abs(hi.risk_score - lo.risk_score * 2) < 0.2      # conf_factor doubles (modulo rounding)
    assert lo.priority in ("P1", "P2", "P3", "P4")
    assert hi.priority in ("P1", "P2", "P3", "P4")


def test_score_handles_cvss_exactly_zero_without_estimating_it():
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True)
    f = Finding(title="t", asset="10.10.10.5", severity="info", cvss=0.0, confidence=0.5)
    score(f, scope)
    assert f.cvss == 0.0
    assert f.cvss_estimated is False    # an explicit 0 was given; never silently replaced
    assert f.risk_score is not None and f.risk_score >= 0
    assert f.priority == "P4"


def test_score_handles_cvss_exactly_ten():
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True)
    f = Finding(title="t", asset="10.10.10.5", severity="critical", cvss=10.0,
               confidence=1.0, exploit_available=True, port=22, service="ssh")
    score(f, scope)
    assert f.cvss == 10.0
    assert f.risk_breakdown["cvss"] == 10.0
    assert 0 <= f.risk_score <= 100
    assert f.priority == "P1"


def test_score_uses_the_medium_default_when_asset_criticality_has_no_entry():
    """No `asset_criticality` override at all for this asset -- not even an empty dict value --
    must fall back to 'medium' rather than raising a KeyError or silently scoring as if the asset
    had no impact weight."""
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True, asset_criticality={})
    f = Finding(title="t", asset="10.10.10.5", severity="medium", cvss=5.0, confidence=0.5)
    score(f, scope)
    assert f.risk_breakdown["asset_impact"]["criticality"] == "medium"
    assert f.risk_breakdown["asset_impact"]["set_by"] == "default"


def test_parse_cvss_vector_extracts_metrics():
    m = parse_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert m == {"CVSS": "3.1", "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
                "C": "H", "I": "H", "A": "H"}


def test_parse_cvss_vector_handles_missing_or_malformed():
    assert parse_cvss_vector(None) == {}
    assert parse_cvss_vector("") == {}
    assert parse_cvss_vector("not a vector") == {}


def test_describe_cvss_vector_high_cia():
    desc = describe_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert "network-exploitable" in desc
    assert "high confidentiality" in desc and "high integrity" in desc and "high availability" in desc


def test_describe_cvss_vector_partial_impact_only_lists_nonzero():
    # Confidentiality-only impact (e.g. an info-disclosure vuln): integrity/availability stay "none"
    desc = describe_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
    assert "high confidentiality" in desc
    assert "integrity" not in desc and "availability" not in desc


def test_describe_cvss_vector_none_for_missing_vector():
    assert describe_cvss_vector(None) is None
    assert describe_cvss_vector("") is None


def test_describe_cvss_vector_never_fabricates_beyond_what_vector_states():
    # A vector with no C/I/A at all (malformed/incomplete) must not produce an impact description
    assert describe_cvss_vector("CVSS:3.1/AV:N/AC:L") is None
