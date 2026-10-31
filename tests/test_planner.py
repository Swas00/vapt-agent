"""Tests for the candidate-generation / ranking / materialization pipeline in planner.py.

Covers: service-driven candidates (unchanged behaviour), the NEW finding-driven candidates (the
actual "deepened reasoning" feature -- a severe, single-source finding now triggers a proposal to
corroborate it), deduplication against the existing plan, deterministic rule-based ranking when no
LLM is configured, and LLM-arbitrated ranking (mocked) producing real "skipped" steps with a
recorded reason -- the "avoid unnecessary actions, but show why" property.
"""
from __future__ import annotations

from vapt_agent import planner, reasoning
from vapt_agent.models import Assessment, Finding, ScopeModel, Service


def make_assessment(**scope_kw):
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True, **scope_kw)
    return Assessment(request="test", scope=scope)


def test_service_candidates_cover_web_smb_ftp_tls_db():
    a = make_assessment()
    services = [
        Service(host="10.10.10.5", port=80, name="http", source_tool="nmap"),
        Service(host="10.10.10.5", port=445, name="microsoft-ds", source_tool="nmap"),
        Service(host="10.10.10.5", port=21, name="ftp", source_tool="nmap"),
        Service(host="10.10.10.5", port=443, name="https", tunnel="ssl", source_tool="nmap"),
        Service(host="10.10.10.5", port=3306, name="mysql", source_tool="nmap"),
    ]
    steps = planner.plan_from_services(a, services)
    tools_targets = {(s.tool, s.preset) for s in steps}
    assert ("nikto", "default") in tools_targets
    assert ("zap", "baseline") in tools_targets
    assert ("nmap", "smb_safe") in tools_targets
    assert ("nmap", "ftp_safe") in tools_targets
    assert ("nmap", "ssl") in tools_targets
    assert ("nmap", "vulners") in tools_targets   # the new DB trigger
    assert all(s.status == "proposed" for s in steps)   # rule-only mode never defers
    assert all(s.kind == "service" for s in steps)


def test_no_duplicate_candidates_across_calls():
    a = make_assessment()
    services = [Service(host="10.10.10.5", port=80, name="http", source_tool="nmap")]
    first = planner.plan_from_services(a, services)
    a.plan.extend(first)
    second = planner.plan_from_services(a, services)   # same services ingested again
    assert second == []


def test_finding_driven_candidate_for_single_source_critical():
    """A CVE-bearing finding reported by an infra scanner OTHER than nmap, with nmap not yet
    having surfaced its own CVE evidence at that port, should trigger an nmap vulners corroboration."""
    a = make_assessment()
    f = Finding(title="Critical RCE", asset="10.10.10.5", port=445, severity="critical",
               cve=["CVE-2099-0001"], confidence=0.6, source_tools=["nessus"], risk_score=80.0)
    a.findings = [f]
    steps = planner.plan_from_findings(a)
    assert len(steps) == 1
    assert steps[0].kind == "finding"
    assert steps[0].trigger_finding_id == f.id
    assert steps[0].tool == "nmap" and steps[0].preset == "vulners"


def test_no_corroboration_candidate_when_nmap_already_produced_cve_evidence():
    """nmap itself already surfaced CVE evidence at this exact port (e.g. its own vulners script
    ran) -- re-proposing another nmap vulners check there is pointless and must not happen."""
    a = make_assessment()
    a.raw_findings = [Finding(title="nmap-reported CVE", asset="10.10.10.5", port=445,
                              severity="high", cve=["CVE-2099-0002"], source_tools=["nmap"])]
    f = Finding(title="Same CVE via another tool", asset="10.10.10.5", port=445, severity="critical",
               cve=["CVE-2099-0002"], confidence=0.6, source_tools=["nessus"], risk_score=80.0)
    a.findings = [f]
    assert planner.plan_from_findings(a) == []


def test_no_corroboration_candidate_for_nmap_sourced_cve_finding():
    """A CVE finding that nmap itself produced can't be corroborated by running nmap again.
    Uses a non-web port so the (unrelated) web cross-check rule doesn't also fire."""
    a = make_assessment()
    f = Finding(title="Found by nmap script", asset="10.10.10.5", port=22, severity="critical",
               cve=["CVE-2099-0003"], confidence=0.55, source_tools=["nmap"], risk_score=75.0)
    a.findings = [f]
    assert planner.plan_from_findings(a) == []


def test_no_corroboration_candidate_for_cve_less_finding_outside_web_ports():
    """A non-web, non-CVE finding (e.g. an info-level banner) has no rule-based corroboration
    action available and should not generate a candidate just because it's single-source."""
    a = make_assessment()
    f = Finding(title="SQL injection", asset="10.10.10.5", port=5432, severity="high",
               confidence=0.5, source_tools=["burp"], risk_score=60.0)
    a.findings = [f]
    assert planner.plan_from_findings(a) == []


def test_no_finding_driven_candidate_once_confirmed_by_two_tools():
    a = make_assessment()
    f = Finding(title="Critical RCE", asset="10.10.10.5", port=445, severity="critical",
               source_tools=["nmap", "nessus"], confidence=0.9, risk_score=90.0, status="confirmed")
    a.findings = [f]
    assert planner.plan_from_findings(a) == []


def test_no_finding_driven_candidate_for_false_positive_candidate():
    a = make_assessment()
    f = Finding(title="Weird info banner", asset="10.10.10.5", severity="critical",
               source_tools=["nmap"], confidence=0.2, status="false_positive_candidate", risk_score=10.0)
    a.findings = [f]
    assert planner.plan_from_findings(a) == []


def test_finding_driven_web_candidate_proposes_missing_tool_only():
    a = make_assessment()
    # Nothing has run against this asset yet except the tool that produced the finding itself
    # (zap). The finding has no CVE, so the only applicable corroboration is a second,
    # independent web-layer tool -- not an nmap rescan.
    f = Finding(title="Reflected XSS", asset="10.10.10.5", port=80, service="http", severity="high",
               confidence=0.5, source_tools=["zap"], risk_score=55.0)
    a.findings = [f]
    steps = planner.plan_from_findings(a)
    tools = {s.tool for s in steps}
    assert tools == {"nikto"}   # zap is excluded: it's the finding's own source tool
    assert "nmap" not in tools   # no CVE -> nmap vulners would not help corroborate this


def test_finding_driven_web_candidate_skipped_when_both_web_tools_already_ran():
    a = make_assessment()
    from vapt_agent.models import ToolRun
    a.runs.append(ToolRun(tool="nikto", mode="live", target="http://10.10.10.5:80", status="ok"))
    f = Finding(title="Reflected XSS", asset="10.10.10.5", port=80, service="http", severity="high",
               confidence=0.5, source_tools=["zap"], risk_score=55.0)
    a.findings = [f]
    steps = planner.plan_from_findings(a)
    assert steps == []   # nikto already ran, zap is the finding's own source -- nothing missing


def test_finding_driven_web_candidate_proposes_nmap_vulners_when_cve_present_and_missing():
    a = make_assessment()
    from vapt_agent.models import ToolRun
    a.runs.append(ToolRun(tool="nikto", mode="live", target="http://10.10.10.5:80", status="ok"))
    a.runs.append(ToolRun(tool="zap", mode="live", target="http://10.10.10.5:80", status="ok"))
    f = Finding(title="Outdated Apache with known CVE", asset="10.10.10.5", port=80, service="http",
               severity="critical", cve=["CVE-2099-0004"], confidence=0.5, source_tools=["nessus"],
               risk_score=80.0)
    a.findings = [f]
    steps = planner.plan_from_findings(a)
    assert {s.tool for s in steps} == {"nmap"}   # web tools already covered; CVE still uncorroborated by nmap


def test_rule_ranking_is_deterministic_and_all_kept(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    a = make_assessment()
    services = [Service(host="10.10.10.5", port=445, name="microsoft-ds", source_tool="nmap"),
               Service(host="10.10.10.5", port=21, name="ftp", source_tool="nmap")]
    steps = planner.plan_from_services(a, services)
    assert all(s.origin == "rules" for s in steps)
    assert all(s.status == "proposed" for s in steps)
    # smb_safe has a higher base_priority than ftp_safe -> should sort first
    assert steps[0].preset == "smb_safe"
    assert steps[0].alternatives_considered   # batch of >1 candidates records siblings


def test_llm_arbitration_can_defer_a_candidate_with_a_recorded_reason(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    a = make_assessment()
    services = [Service(host="10.10.10.5", port=80, name="http", source_tool="nmap")]

    class FakeVerdict:
        def __init__(self, id, keep, priority, explanation):
            self.id, self.keep, self.priority, self.explanation = id, keep, priority, explanation

    def fake_arbitrate(context, candidates):
        # candidates[0] is nikto, candidates[1] is zap (insertion order in _candidates_from_services)
        return [FakeVerdict(candidates[0]["id"], True, 1, "run nikto first, it is faster"),
               FakeVerdict(candidates[1]["id"], False, 2, "redundant with nikto for this simple case")]

    monkeypatch.setattr(reasoning, "arbitrate", fake_arbitrate)
    steps = planner.plan_from_services(a, services)
    by_tool = {s.tool: s for s in steps}
    assert by_tool["nikto"].status == "proposed"
    assert by_tool["nikto"].origin == "llm"
    assert by_tool["zap"].status == "skipped"
    assert by_tool["zap"].origin == "llm"
    assert "redundant" in by_tool["zap"].skip_reason
    assert a.llm_mode == "llm-arbitrated"


def test_llm_failure_falls_back_to_rules_and_records_a_note(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    monkeypatch.setattr(reasoning, "arbitrate", lambda context, candidates: None)
    a = make_assessment()
    services = [Service(host="10.10.10.5", port=80, name="http", source_tool="nmap")]
    steps = planner.plan_from_services(a, services)
    assert all(s.origin == "rules" for s in steps)
    assert all(s.status == "proposed" for s in steps)
    assert a.llm_notes   # the fallback was recorded, not silent
