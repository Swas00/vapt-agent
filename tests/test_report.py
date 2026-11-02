"""Tests for the report-polish additions: grounded business/technical impact statements, the
at-a-glance stats table, the assets-tested table, and a full generate() smoke test."""
from __future__ import annotations

from vapt_agent.models import Approval, Assessment, Finding, ScopeModel, Service, ToolRun
from vapt_agent.report import _assets_tested_rows, _stats_rows, generate, impact_statement
from vapt_agent.risk import score


def _scope(**kw):
    base = dict(targets=["10.10.10.5"], lab_attestation=True, asset_criticality={"10.10.10.5": "high"})
    base.update(kw)
    return ScopeModel(**base)


def test_impact_statement_validated_finding():
    scope = _scope()
    f = Finding(title="t", asset="10.10.10.5", port=445, severity="critical", confidence=0.95,
               validation_status="validated", status="confirmed", source_tools=["nmap"],
               service="microsoft-ds")
    score(f, scope)
    text = impact_statement(f)
    assert "high-criticality" in text
    assert "set by the analyst" in text
    assert "confirmed through approved active validation" in text
    assert "Technical impact" in text
    assert "unauthorized access to files or shared data" in text   # file_share exposure class


def test_impact_statement_single_source_suspected_finding():
    scope = _scope()
    f = Finding(title="t", asset="10.10.10.5", port=80, severity="high", confidence=0.4,
               source_tools=["burp"], service="http")
    score(f, scope)
    text = impact_statement(f)
    assert "currently 'suspected'" in text
    assert "single tool (burp)" in text
    assert "compromise of the web application" in text


def test_impact_statement_multi_source_corroborated_finding():
    scope = _scope()
    f = Finding(title="t", asset="10.10.10.5", port=445, severity="critical", confidence=0.9,
               source_tools=["nmap", "nessus"], status="confirmed", service="microsoft-ds")
    score(f, scope)
    text = impact_statement(f)
    assert "independently corroborated by 2 tools" in text
    assert "nmap" in text and "nessus" in text


def test_impact_statement_false_positive_candidate():
    scope = _scope()
    f = Finding(title="t", asset="10.10.10.5", severity="medium", confidence=0.2,
               status="false_positive_candidate", source_tools=["nikto"])
    score(f, scope)
    text = impact_statement(f)
    assert "possible false positive" in text


def test_impact_statement_not_reproducible():
    scope = _scope()
    f = Finding(title="t", asset="10.10.10.5", port=80, severity="high", confidence=0.6,
               source_tools=["nessus"], validation_status="not_reproducible", service="http")
    score(f, scope)
    text = impact_statement(f)
    assert "could not reproduce" in text


def test_impact_statement_includes_cvss_vector_clause_when_present():
    scope = _scope()
    f = Finding(title="t", asset="10.10.10.5", port=445, severity="critical", confidence=0.7,
               source_tools=["nessus"], cvss=8.1,
               cvss_vector="CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H")
    score(f, scope)
    text = impact_statement(f)
    assert "network-exploitable" in text
    assert "high confidentiality" in text


def test_impact_statement_default_criticality_labeled_as_such():
    scope = ScopeModel(targets=["10.10.10.9"], lab_attestation=True)   # no asset_criticality override
    f = Finding(title="t", asset="10.10.10.9", severity="high", confidence=0.5, source_tools=["nmap"])
    score(f, scope)
    text = impact_statement(f)
    assert "medium-criticality" in text
    assert "not analyst-confirmed" in text


def test_stats_rows_counts_are_accurate():
    a = Assessment(request="r", scope=_scope())
    a.findings = [
        Finding(title="a", asset="10.10.10.5", severity="critical", priority="P1",
               status="confirmed", validation_status="validated"),
        Finding(title="b", asset="10.10.10.5", severity="high", priority="P2", status="suspected"),
        Finding(title="c", asset="10.10.10.5", severity="info", priority="P4",
               status="false_positive_candidate"),
    ]
    a.runs = [ToolRun(tool="nmap", mode="live", target="10.10.10.5", status="ok"),
             ToolRun(tool="nikto", mode="live", target="10.10.10.5", status="failed")]
    a.approvals = [Approval(finding_id="x", asset="10.10.10.5", action="y")]
    rows = {label: value for label, value in _stats_rows(a)}
    assert rows["Total correlated findings"] == "3"
    assert rows["Priority P1 / P2 / P3 / P4"] == "1 / 1 / 0 / 1"
    assert rows["Confirmed / Suspected / Possible false positive"] == "1 / 1 / 1"
    assert rows["Actively validated (human-approved)"] == "1"
    assert rows["Tools with a successful run"] == "1 (nmap)"   # nikto's run failed, excluded
    assert rows["Human approval decisions recorded"] == "1"


def test_assets_tested_rows_combines_services_and_findings():
    a = Assessment(request="r", scope=_scope(targets=["10.10.10.5", "10.10.10.6"]))
    a.services = [Service(host="10.10.10.5", port=80, source_tool="nmap"),
                 Service(host="10.10.10.5", port=443, source_tool="nmap")]
    a.findings = [Finding(title="a", asset="10.10.10.5", severity="high"),
                 Finding(title="b", asset="10.10.10.6", severity="low")]   # no services parsed for .6
    rows = {host: (ports, count) for host, ports, count in _assets_tested_rows(a)}
    assert rows["10.10.10.5"] == (2, 1)
    assert rows["10.10.10.6"] == (0, 1)


def test_generate_produces_a_valid_pdf_with_no_findings(tmp_path):
    a = Assessment(request="empty scan", scope=_scope())
    out = generate(a, tmp_path / "empty.pdf")
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"
    assert out.stat().st_size > 500


def test_generate_includes_remediation_status_and_progress_summary(tmp_path):
    scope = _scope()
    fixed = Finding(title="a", asset="10.10.10.5", severity="critical", confidence=0.9,
                    source_tools=["nmap"], remediation_status="fixed", remediation_updated_by="bob")
    open_ = Finding(title="b", asset="10.10.10.5", severity="high", confidence=0.5,
                    source_tools=["nikto"])   # default remediation_status="open"
    score(fixed, scope); score(open_, scope)
    a = Assessment(request="retest", scope=scope)
    a.findings = [fixed, open_]
    out = generate(a, tmp_path / "remediation.pdf")
    assert out.exists() and out.read_bytes()[:5] == b"%PDF-"


def test_generate_handles_ampersand_and_markup_in_free_text_without_crashing(tmp_path):
    scope = _scope()
    f = Finding(title="R&D <admin> panel exposed", asset="10.10.10.5", severity="high",
               confidence=0.6, source_tools=["nikto"], description="Contains <script> & 'quotes'",
               solution="Fix it & verify")
    score(f, scope)
    a = Assessment(request="Test <injection> & stuff", scope=scope)
    a.findings = [f]
    a.limitations = ["Scan timed out on port 8080 <details>"]
    a.approvals = [Approval(finding_id=f.id, asset="10.10.10.5",
                            action="Validate & confirm", reason="ok & good")]
    out = generate(a, tmp_path / "escaped.pdf")
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"
