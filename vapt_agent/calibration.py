"""FS-6: confidence calibration against historical validation outcomes.

When human-approved active validation (orchestrator.execute_approval, gated behind a `lead`
approval -- see SECURITY.md) reports an outcome for a finding, that's real signal: this exact kind
of finding turned out to be validated or not_reproducible. This module looks across OTHER
assessments' already-validated findings for the same signature (same CVE, or -- when there's no
CVE -- the same title) and nudges a brand-new finding's confidence toward what similar findings
have actually turned out to be, rather than leaving every finding at whatever single-assessment
score correlate.py/risk.py computed on their own.

Deliberately conservative, mirroring how the rest of this codebase treats anything derived rather
than observed (models.py's `inference` list is never silently folded into `evidence`; frameworks.py
labels its MITRE mapping "indicative only"):
- Only applies with at least MIN_SAMPLE matching historical outcomes -- one past data point proves
  nothing about a new finding.
- The adjustment is capped at MAX_SHIFT per analysis pass, and always recorded as an inference with
  the sample it was based on -- never a silent, unexplained confidence change.
- It can only move a finding's confidence. It never changes severity, status, or validation_status.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Assessment, Finding

MIN_SAMPLE = 3
MAX_SHIFT = 0.15


def _signature(f: Finding) -> str:
    """CVE is the strongest signature (specific, versioned); fall back to the finding title,
    lower-cased, when there's no CVE -- e.g. a Nikto web-misconfiguration finding."""
    if f.cve:
        return "cve:" + ",".join(sorted(f.cve))
    return "title:" + f.title.strip().lower()


@dataclass
class HistoricalOutcome:
    signature: str
    validated: int = 0
    not_reproducible: int = 0

    @property
    def total(self) -> int:
        return self.validated + self.not_reproducible

    @property
    def validated_rate(self) -> float:
        return self.validated / self.total if self.total else 0.0


def build_history(assessments: list[Assessment]) -> dict[str, HistoricalOutcome]:
    """Scans every already-validated finding (validation_status 'validated' or
    'not_reproducible' -- i.e. an actual approved active-validation run reported an outcome, not
    just a tool's initial guess) across the given assessments, grouped by signature."""
    out: dict[str, HistoricalOutcome] = {}
    for a in assessments:
        for f in a.findings:
            if f.validation_status not in ("validated", "not_reproducible"):
                continue
            h = out.setdefault(_signature(f), HistoricalOutcome(_signature(f)))
            if f.validation_status == "validated":
                h.validated += 1
            else:
                h.not_reproducible += 1
    return out


def calibrate(f: Finding, history: dict[str, HistoricalOutcome]) -> bool:
    """Mutates f.confidence in place when there's enough matching history. Returns True iff it
    made a change, so the caller knows whether to re-score risk and whether there's anything to
    audit/announce."""
    h = history.get(_signature(f))
    if h is None or h.total < MIN_SAMPLE:
        return False
    # Pull confidence toward the historical validated-rate, capped so one calibration pass can't
    # swing a finding from e.g. 0.3 straight to 1.0.
    shift = max(-MAX_SHIFT, min(MAX_SHIFT, h.validated_rate - f.confidence))
    if abs(shift) < 0.01:
        return False
    f.confidence = round(max(0.0, min(1.0, f.confidence + shift)), 2)
    f.inference.append(
        f"[inference] Confidence calibrated from {h.total} historical validation outcome(s) for "
        f"findings with this signature ({h.validated} validated, {h.not_reproducible} not "
        f"reproducible elsewhere) -- adjusted by {shift:+.2f}.")
    return True
