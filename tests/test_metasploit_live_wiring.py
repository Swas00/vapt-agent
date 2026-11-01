"""Exercises the REAL subprocess-invocation code in adapters/infra.py:Metasploit.validate()
(command construction, timeout handling, raw-output capture) end-to-end through the orchestrator's
approval workflow, using a locally-authored stand-in `msfconsole` script on PATH (see
tests/fixtures/fake_msfconsole.sh) instead of the real Metasploit Framework, which this environment
cannot install without bypassing macOS Gatekeeper and installing Rosetta 2 / a system .pkg -- steps
this project does not take. The command built and the subprocess call made are identical to what
would run against a real msfconsole binary of the same name on PATH.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from vapt_agent.audit import AuditLog
from vapt_agent.models import ScopeModel
from vapt_agent.orchestrator import Orchestrator, ScopeError

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def fake_msf_on_path(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    target = bin_dir / "msfconsole"
    target.write_text(FIX.joinpath("fake_msfconsole.sh").read_text())
    target.chmod(target.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    return bin_dir


@pytest.fixture
def orch(tmp_path):
    return Orchestrator(tmp_path, AuditLog(tmp_path / "audit.log"))


@pytest.fixture
def assessment(orch):
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True, allow_active_validation=True)
    return orch.create("Validate a critical SMB finding.", scope)


def _seed_finding(assessment):
    from vapt_agent.models import Finding
    f = Finding(title="MS17-010 SMB RCE", asset="10.10.10.5", port=445, severity="critical",
               cve=["CVE-2017-0143"], confidence=0.6, source_tools=["nmap"])
    assessment.raw_findings.append(f)
    return f


def test_approved_validation_runs_real_subprocess_and_marks_validated(fake_msf_on_path, orch, assessment):
    f = _seed_finding(assessment)
    orch.analyse(assessment)
    target = next(x for x in assessment.findings if x.title == f.title)

    appr = orch.request_approval(assessment, target.id, "Validate MS17-010", module="auxiliary/vuln_module")
    orch.decide_approval(assessment, appr.id, True, by="lead-analyst", reason="lab-only check")
    run = orch.execute_approval(assessment, appr.id)

    assert run.status == "ok", run.error
    assert "fake-msfconsole" in Path(run.raw_path).read_text()
    assert appr.state == "executed"
    assert appr.outcome == "validated"
    assert target.validation_status == "validated"
    assert target.status == "confirmed"


def test_approved_validation_can_be_not_reproducible(fake_msf_on_path, orch, assessment):
    f = _seed_finding(assessment)
    orch.analyse(assessment)
    target = next(x for x in assessment.findings if x.title == f.title)

    appr = orch.request_approval(assessment, target.id, "Validate MS17-010", module="auxiliary/safe_module")
    orch.decide_approval(assessment, appr.id, True, by="lead-analyst")
    run = orch.execute_approval(assessment, appr.id)

    assert run.status == "ok"
    assert appr.outcome == "not_reproducible"
    assert target.validation_status == "not_reproducible"


def test_execution_refused_without_approval(fake_msf_on_path, orch, assessment):
    _seed_finding(assessment)
    orch.analyse(assessment)
    target = assessment.findings[0]
    appr = orch.request_approval(assessment, target.id, "Validate", module="auxiliary/vuln_module")
    with pytest.raises(ScopeError):
        orch.execute_approval(assessment, appr.id)   # still pending, must be refused


def test_execution_refused_for_malformed_module_name(fake_msf_on_path, orch, assessment):
    _seed_finding(assessment)
    orch.analyse(assessment)
    target = assessment.findings[0]
    appr = orch.request_approval(assessment, target.id, "Validate", module="rm -rf /; echo pwned")
    orch.decide_approval(assessment, appr.id, True, by="lead-analyst")
    run = orch.execute_approval(assessment, appr.id)
    assert run.status == "failed"
    assert "module" in run.error.lower()
