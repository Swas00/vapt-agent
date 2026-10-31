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
import os

from .models import Assessment, Finding

_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5")


def _client():
    import anthropic
    return anthropic.Anthropic()


def summarize_assessment(a: Assessment, findings: list[Finding]) -> str:
    """Executive-summary prose for the report, grounded strictly in the counted findings passed in.
    Falls back to a deterministic template if no API key is present or the call fails."""
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    template = (
        f"This assessment covered {len(a.scope.targets)} authorized target(s) and produced "
        f"{len(findings)} correlated finding(s): " +
        ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: -_rank(kv[0]))) + "."
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
        resp = client.messages.create(model=_MODEL, max_tokens=250,
                                      messages=[{"role": "user", "content": prompt}])
        text = "".join(b.text for b in resp.content if b.type == "text").strip()
        return text or template
    except Exception:  # noqa: BLE001
        return template


def _rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)
