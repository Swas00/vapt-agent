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


def test_set_remediation_status_records_who_and_when(orch, assessment):
    orch.import_result(assessment, "nessus", FIX / "nessus_sample.nessus")
    orch.analyse(assessment)
    f = assessment.findings[0]
    assert f.remediation_status == "open"            # the default, nothing inferred

    updated = orch.set_remediation_status(assessment, f.id, "fixed", by="bob")
    assert updated.remediation_status == "fixed"
    assert updated.remediation_updated_by == "bob"
    assert updated.remediation_updated_at
    entry = next(e for e in orch.audit.entries() if e["action"] == "finding.remediation_updated")
    assert entry["actor"] == "bob" and entry["details"]["status"] == "fixed"


def test_set_false_positive_overrides_inferred_status_and_rescoes(orch, assessment):
    """A9: a weak, single-source info finding gets inferred as 'false_positive_candidate' by
    correlate.py; an analyst explicitly confirming it is a no-op on the verdict but records who
    and when; an analyst explicitly overturning the inference raises its risk score back up."""
    from vapt_agent.models import Finding, is_false_positive
    from vapt_agent.risk import score as risk_score

    f = Finding(title="X-Content-Type-Options header missing", asset="10.10.10.5", port=80,
               source_tools=["nikto"], severity="info", confidence=0.3,
               status="false_positive_candidate")
    assessment.findings = [f]
    risk_score(f, assessment.scope)
    inferred_score = f.risk_score
    assert is_false_positive(f)

    overturned = orch.set_false_positive(assessment, f.id, False, by="bob", reason="verified real on the host")
    assert overturned.analyst_marked_false_positive is False
    assert overturned.analyst_fp_reason == "verified real on the host"
    assert overturned.analyst_fp_set_by == "bob"
    assert overturned.analyst_fp_set_at
    assert not is_false_positive(overturned)
    assert overturned.risk_score > inferred_score     # no longer discounted

    entry = next(e for e in orch.audit.entries() if e["action"] == "finding.false_positive_marked")
    assert entry["actor"] == "bob" and entry["details"]["marked"] is False


def test_set_false_positive_can_confirm_a_finding_the_system_never_flagged(orch, assessment):
    """The reverse direction: a finding with no inferred flag at all can still be explicitly
    marked a false positive by an analyst, and gets discounted accordingly."""
    from vapt_agent.models import Finding, is_false_positive
    from vapt_agent.risk import score as risk_score

    f = Finding(title="Open port", asset="10.10.10.5", port=8080, severity="medium", cvss=5.0,
               confidence=0.6, source_tools=["nmap"], status="suspected")
    assessment.findings = [f]
    risk_score(f, assessment.scope)
    before = f.risk_score
    assert not is_false_positive(f)

    confirmed = orch.set_false_positive(assessment, f.id, True, by="alice", reason="known test harness noise")
    assert is_false_positive(confirmed)
    assert confirmed.risk_score < before


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


def test_analyse_calibrates_confidence_from_other_assessments_history(orch, assessment):
    """FS-6: orchestrator.analyse() accepts an optional `history` of OTHER assessments; a finding
    whose signature (here, title -- the Nessus fixture's findings carry no CVE) was repeatedly
    validated elsewhere should have its confidence nudged up and the adjustment logged."""
    from vapt_agent.models import Assessment, Finding, ScopeModel

    target_title = "Default credentials on admin panel"
    assessment.raw_findings.append(
        Finding(title=target_title, asset="10.10.10.5", confidence=0.4, source_tools=["nikto"]))

    other_scope = ScopeModel(targets=["10.10.10.9"], lab_attestation=True)
    history_assessment = Assessment(request="other", scope=other_scope)
    # Match on title (this synthetic finding carries no CVE) with enough repeated 'validated'
    # outcomes elsewhere to clear MIN_SAMPLE.
    history_assessment.findings = [
        Finding(title=target_title, asset="10.10.10.9", confidence=0.9, validation_status="validated")
        for _ in range(4)
    ]

    orch.analyse(assessment, history=[history_assessment])
    calibrated = [f for f in assessment.findings if f.title == target_title]
    assert calibrated
    f = calibrated[0]
    assert any("Confidence calibrated" in note for note in f.inference)
    entry = next(e for e in orch.audit.entries() if e["action"] == "analysis.confidence_calibrated")
    assert entry["details"]["count"] >= 1


def test_analyse_without_history_is_unchanged_from_before_fs6(orch, assessment):
    """Omitting `history` entirely (every pre-FS-6 caller, e.g. demo.py) must behave exactly as
    before -- no calibration attempted, no 'analysis.confidence_calibrated' audit entry."""
    orch.import_result(assessment, "nessus", FIX / "nessus_sample.nessus")
    orch.analyse(assessment)
    assert not any(e["action"] == "analysis.confidence_calibrated" for e in orch.audit.entries())
    assert all(not any("calibrated" in note.lower() for note in f.inference) for f in assessment.findings)


def test_create_batch_makes_one_assessment_per_target(orch):
    scope = ScopeModel(targets=["placeholder"], lab_attestation=True)
    batch, members = orch.create_batch("sweep", "Assess the subnet.",
                                       ["10.10.10.5", "10.10.10.6", "10.10.10.7"], scope)
    assert len(members) == 3
    assert batch.assessment_ids == [a.id for a in members]
    assert [a.scope.targets for a in members] == [["10.10.10.5"], ["10.10.10.6"], ["10.10.10.7"]]
    assert all(a.state == "planned" for a in members)
    assert len({a.id for a in members}) == 3   # genuinely independent assessments


def test_create_batch_skips_a_target_the_shared_scope_rejects_but_keeps_the_rest(orch):
    """A public IP fails validate_scope's own-scope sanity check (allow_public defaults False) --
    the same check a single-target orch.create() would raise ScopeError for. In a batch, one
    target failing that check must not take down the other, valid targets."""
    scope = ScopeModel(targets=["placeholder"], lab_attestation=True)
    batch, members = orch.create_batch("sweep", "Assess the subnet.",
                                       ["10.10.10.5", "8.8.8.8"], scope)
    assert [a.scope.targets[0] for a in members] == ["10.10.10.5"]
    entry = next(e for e in orch.audit.entries() if e["action"] == "batch.create")
    assert entry["details"]["rejected_targets"]
    assert "8.8.8.8" in entry["details"]["rejected_targets"][0]


def test_create_batch_raises_when_every_target_is_rejected(orch):
    scope = ScopeModel(targets=["placeholder"], lab_attestation=True)
    with pytest.raises(ScopeError):
        orch.create_batch("sweep", "Assess.", ["8.8.8.8"], scope)


def test_concurrent_start_step_calls_on_the_same_step_only_one_wins(orch, assessment):
    """F4: two threads calling start_step for the SAME approved step at once (e.g. a doubled
    click, or a client retrying a request that actually succeeded) must not both launch a scan.
    Exactly one call should return a ToolRun; every other concurrent call should raise ScopeError
    because the step is no longer 'approved' by the time it gets the lock, and exactly one
    ToolRun must have been appended to a.runs -- not one per racing thread."""
    import threading

    step = next(s for s in assessment.plan if s.tool == "nmap")
    orch.approve_step(assessment, step.id, True)

    results = []
    barrier = threading.Barrier(8)

    def attempt():
        barrier.wait()
        try:
            run = orch.start_step(assessment, step.id)
            results.append(("ok", run))
        except ScopeError as e:
            results.append(("rejected", str(e)))

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successes = [r for r in results if r[0] == "ok"]
    rejections = [r for r in results if r[0] == "rejected"]
    assert len(successes) == 1
    assert len(rejections) == 7
    assert len(assessment.runs) == 1
    assert assessment.runs[0].id == successes[0][1].id
    assert step.run_id == successes[0][1].id


def test_scope_blocks_step_run_outside_target(orch, assessment):
    from vapt_agent.models import PlanStep
    bad = PlanStep(tool="nmap", target="8.8.8.8", preset="discovery", rationale="x")
    assessment.plan.append(bad)
    orch.approve_step(assessment, bad.id, True)
    assert bad.status == "rejected"
