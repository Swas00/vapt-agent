"""End-to-end: create assessment -> import multi-tool recorded outputs -> correlate -> prioritize ->
request/approve/deny a validation (without actually invoking msfconsole, which test_metasploit_gate
below checks is refused unless a real approval+binary are present) -> generate PDF report.
"""
from pathlib import Path

import pytest

from vapt_agent.audit import AuditLog
from vapt_agent.models import ScopeModel
from vapt_agent.orchestrator import Orchestrator, ScopeError

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def orch(tmp_path):
    return Orchestrator(tmp_path, AuditLog(tmp_path / "audit.log"))


@pytest.fixture
def assessment(orch):
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True, allow_active_validation=True,
                       permissions_note="organizer lab ticket #123")
    return orch.create("Assess the lab host and its web app.", scope)


def test_create_assessment_builds_discovery_plan(assessment):
    assert assessment.state == "planned"
    assert any(s.tool == "nmap" and s.preset == "discovery" for s in assessment.plan)


def test_scope_rejects_out_of_scope_import_target(orch, assessment):
    # import still only accepts findings inside scope -- ingest filters even if the file mentions other hosts
    run = orch.import_result(assessment, "nessus", FIX / "nessus_sample.nessus")
    assert run.status == "ok"
    assert all(f.asset == "10.10.10.5" for f in assessment.raw_findings)


def test_full_pipeline_to_report(orch, assessment, tmp_path):
    orch.import_result(assessment, "nmap", FIX / "nmap_sample.xml")
    orch.import_result(assessment, "nikto", FIX / "nikto_sample.json")
    orch.import_result(assessment, "zap", FIX / "zap_sample.json")
    orch.import_result(assessment, "burp", FIX / "burp_sample.xml")
    orch.import_result(assessment, "nessus", FIX / "nessus_sample.nessus")
    orch.import_result(assessment, "openvas", FIX / "openvas_sample.xml")

    assert len(assessment.raw_findings) > 5
    # the MS17-010 finding seen by both nmap and nessus should have been folded into one
    orch.analyse(assessment)
    ms17 = [f for f in assessment.findings if "MS17-010" in f.title or "CVE-2017-0143" in f.cve]
    assert len(ms17) == 1
    assert set(ms17[0].source_tools) >= {"nmap", "nessus"}
    assert all(f.risk_score is not None for f in assessment.findings)
    assert assessment.findings == sorted(assessment.findings, key=lambda f: -f.risk_score)

    high = next(f for f in assessment.findings if f.severity in ("critical", "high"))
    appr = orch.request_approval(assessment, high.id, f"Validate {high.title}")
    assert appr.state == "pending"
    orch.decide_approval(assessment, appr.id, False, by="lead-analyst", reason="Out of time window")
    assert appr.state == "denied"

    from vapt_agent.report import generate
    out = generate(assessment, tmp_path / "report.pdf")
    assert out.exists() and out.stat().st_size > 1000

    ok, msg = orch.audit.verify()
    assert ok, msg


def test_metasploit_execution_requires_approved_state(orch, assessment, tmp_path):
    orch.import_result(assessment, "nessus", FIX / "nessus_sample.nessus")
    orch.analyse(assessment)
    f = assessment.findings[0]
    appr = orch.request_approval(assessment, f.id, "Validate finding")
    with pytest.raises(ScopeError):
        orch.execute_approval(assessment, appr.id)   # still 'pending', must be refused


def test_scope_blocks_step_run_outside_target(orch, assessment):
    from vapt_agent.models import PlanStep
    bad = PlanStep(tool="nmap", target="8.8.8.8", preset="discovery", rationale="x")
    assessment.plan.append(bad)
    orch.approve_step(assessment, bad.id, True)
    assert bad.status == "rejected"
