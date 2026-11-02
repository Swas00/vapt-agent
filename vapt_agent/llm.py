"""Optional LLM enrichment layer (Claude). Strictly read-and-explain: it never creates findings, never
invents CVEs/scores, and never chooses a tool that scope.check() has not already approved. If no API
key is configured, the rules-engine rationale strings already attached to each PlanStep are used as-is
and the system runs in pure "rules-engine" mode, which is fully demonstrable without network access.

Plan-step *arbitration* (ranking/keeping/deferring candidates) lives in reasoning.py, which applies a
much stricter closed-set validation than a free-text rewrite would allow -- see its module docstring.
This module is left with the one LLM use that is pure prose generation over already-finalized facts:
the report's executive summary.
"""
from __future__ import annotations

import json
import logging
import os

from .models import Assessment, Finding

logger = logging.getLogger(__name__)

_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")


def _client():
    import anthropic
    return anthropic.Anthropic()


_HEDGE_THRESHOLD = 0.6   # fraction of findings still 'suspected' that triggers an explicit caveat


def _uncertainty_note(findings: list[Finding]) -> str:
    """A confidence-aware caveat (CA-4): when most of the findings a summary is about are still
    'suspected' rather than independently confirmed or analyst-validated, say so explicitly in
    the summary itself, rather than letting a severity count alone imply more certainty than the
    assessment actually has. Computed here (not left to the LLM to volunteer) so the disclosure
    is guaranteed regardless of whether the LLM path is used at all."""
    if not findings:
        return ""
    suspected = sum(1 for f in findings if f.status == "suspected")
    if suspected / len(findings) < _HEDGE_THRESHOLD:
        return ""
    return (f" Note: {suspected} of {len(findings)} finding(s) above are still 'suspected' rather "
            "than independently confirmed or analyst-validated -- treat the severity distribution "
            "as an upper bound on confirmed risk, not a final verdict, pending further validation.")


def summarize_assessment(a: Assessment, findings: list[Finding]) -> str:
    """Executive-summary prose for the report, grounded strictly in the counted findings passed in.
    Falls back to a deterministic template if no API key is present or the call fails."""
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    hedge = _uncertainty_note(findings)
    template = (
        f"This assessment covered {len(a.scope.targets)} authorized target(s) and produced "
        f"{len(findings)} correlated finding(s): " +
        ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: -_rank(kv[0]))) + "." + hedge
    )
    if not os.environ.get("ANTHROPIC_API_KEY"):
        return template
    try:
        client = _client()
        facts = json.dumps([{"title": f.title, "asset": f.asset, "severity": f.severity,
                             "status": f.status, "confidence": f.confidence} for f in findings[:40]])
        prompt = ("Write a 3-4 sentence executive summary of a penetration test for a non-technical "
                  "stakeholder, using ONLY the facts in this JSON list of findings (do not invent any "
                  f"finding not listed, do not state a severity or count not supported by it):\n{facts}")
        if hedge:
            prompt += (" Most of these findings are 'suspected,' not independently confirmed -- "
                      "hedge accordingly and do not imply certainty about them.")
        resp = client.messages.create(model=_MODEL, max_tokens=250,
                                      messages=[{"role": "user", "content": prompt}])
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        return (text + hedge) if text else template
    except Exception:  # noqa: BLE001
        logger.warning("LLM executive-summary call failed; falling back to the deterministic template",
                       exc_info=True)
        return template


def _rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)
