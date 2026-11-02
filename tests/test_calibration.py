"""FS-6: confidence calibration against historical validation outcomes."""
from __future__ import annotations

from vapt_agent import calibration
from vapt_agent.models import Assessment, Finding, ScopeModel


def make_assessment(findings):
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True)
    a = Assessment(request="test", scope=scope)
    a.findings = findings
    return a


def validated(title="X", cve=None, confidence=0.5):
    return Finding(title=title, asset="10.10.10.5", cve=cve or [], confidence=confidence,
                   validation_status="validated")


def not_reproducible(title="X", cve=None, confidence=0.5):
    return Finding(title=title, asset="10.10.10.5", cve=cve or [], confidence=confidence,
                   validation_status="not_reproducible")


def test_build_history_groups_by_cve_when_present():
    history = calibration.build_history([
        make_assessment([validated(cve=["CVE-2020-0001"]), not_reproducible(cve=["CVE-2020-0001"])]),
    ])
    h = history["cve:CVE-2020-0001"]
    assert (h.validated, h.not_reproducible, h.total) == (1, 1, 2)


def test_build_history_falls_back_to_title_without_a_cve():
    history = calibration.build_history([make_assessment([validated(title="Anonymous FTP login")])])
    assert "title:anonymous ftp login" in history


def test_build_history_ignores_findings_without_a_recorded_outcome():
    unvalidated = Finding(title="X", asset="10.10.10.5", validation_status="not_validated")
    history = calibration.build_history([make_assessment([unvalidated])])
    assert history == {}


def test_calibrate_requires_minimum_sample_size():
    history = {"title:x": calibration.HistoricalOutcome("title:x", validated=1, not_reproducible=0)}
    f = Finding(title="X", asset="10.10.10.5", confidence=0.5)
    changed = calibration.calibrate(f, history)
    assert changed is False
    assert f.confidence == 0.5
    assert f.inference == []


def test_calibrate_nudges_confidence_up_toward_a_high_historical_validated_rate():
    history = {"title:x": calibration.HistoricalOutcome("title:x", validated=5, not_reproducible=0)}
    f = Finding(title="X", asset="10.10.10.5", confidence=0.4)
    changed = calibration.calibrate(f, history)
    assert changed is True
    assert f.confidence > 0.4
    assert f.confidence <= 0.4 + calibration.MAX_SHIFT + 1e-9
    assert "[inference] Confidence calibrated" in f.inference[0]


def test_calibrate_nudges_confidence_down_toward_a_low_historical_validated_rate():
    history = {"title:x": calibration.HistoricalOutcome("title:x", validated=0, not_reproducible=5)}
    f = Finding(title="X", asset="10.10.10.5", confidence=0.8)
    changed = calibration.calibrate(f, history)
    assert changed is True
    assert f.confidence < 0.8


def test_calibrate_shift_is_capped_even_with_an_extreme_historical_rate():
    history = {"title:x": calibration.HistoricalOutcome("title:x", validated=50, not_reproducible=0)}
    f = Finding(title="X", asset="10.10.10.5", confidence=0.1)
    calibration.calibrate(f, history)
    assert round(f.confidence, 2) == round(0.1 + calibration.MAX_SHIFT, 2)


def test_calibrate_never_touches_severity_status_or_validation_status():
    history = {"title:x": calibration.HistoricalOutcome("title:x", validated=5, not_reproducible=0)}
    f = Finding(title="X", asset="10.10.10.5", confidence=0.3, severity="low",
               status="suspected", validation_status="not_validated")
    calibration.calibrate(f, history)
    assert (f.severity, f.status, f.validation_status) == ("low", "suspected", "not_validated")
