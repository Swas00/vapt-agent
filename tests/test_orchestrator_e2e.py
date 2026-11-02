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


def test_import_run_target_becomes_the_real_asset_not_the_file_path(orch, assessment):
    run = orch.import_result(assessment, "nmap", FIX / "nmap_sample.xml")
    assert run.target == "10.10.10.5"   # not the fixture file path
    assert "nmap_sample.xml" not in run.target


def test_analyse_proposes_a_finding_driven_corroboration_step(orch, assessment):
    """The new behaviour: a severe, single-source finding (not just an open port) triggers a
    plan step -- this is the finding-driven replanning the rules-only, service-driven planner
    did not previously have."""
    orch.import_result(assessment, "nessus", FIX / "nessus_sample.nessus")
    before = len(assessment.plan)
    orch.analyse(assessment)
    after = len(assessment.plan)
    assert after > before
    finding_driven = [s for s in assessment.plan if s.kind == "finding"]
    assert finding_driven
    assert finding_driven[0].trigger_finding_id in {f.id for f in assessment.findings}
    assert any("Suggests requesting human-approved active validation" in e.message for e in assessment.events)


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
    assert any(t.startswith("T1210") for t in ms17[0].mitre_attack)   # EternalBlue -> ATT&CK tagged
    sqli = next(f for f in assessment.findings if f.title == "SQL injection")
    assert any(t.startswith("T1190") for t in sqli.mitre_attack)
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


def test_start_step_marks_running_before_finish_step_completes_it(orch, assessment, monkeypatch):
    """start_step/finish_step are the split the API schedules across a BackgroundTask so the
    request returns before the scan finishes; this checks the in-place ToolRun update keeps
    the same run id across that transition (a client polling by id must see one record, not two)."""
    from vapt_agent.models import ToolRun

    def fake_run(target, preset, workdir, timeout=900):
        return ToolRun(tool="nmap", mode="live", target=target, preset=preset, status="ok")
    step = next(s for s in assessment.plan if s.tool == "nmap")
    monkeypatch.setattr(orch.adapters["nmap"], "run", fake_run)
    orch.approve_step(assessment, step.id, True)

    run = orch.start_step(assessment, step.id)
    assert run.status == "running" and step.status == "running"
    run_id = run.id

    orch.finish_step(assessment, step.id, run_id)
    assert run.id == run_id                 # same record, updated in place
    assert run.status == "ok" and step.status == "done"
    assert assessment.runs == [run]         # no stray second ToolRun was appended


def test_scope_blocks_step_run_outside_target(orch, assessment):
    from vapt_agent.models import PlanStep
    bad = PlanStep(tool="nmap", target="8.8.8.8", preset="discovery", rationale="x")
    assessment.plan.append(bad)
    orch.approve_step(assessment, bad.id, True)
    assert bad.status == "rejected"
