from vapt_agent.correlate import correlate
from vapt_agent.models import Finding, ScopeModel
from vapt_agent.risk import score


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
