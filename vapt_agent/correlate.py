"""Normalization and correlation: map raw per-tool findings onto a common model and merge true duplicates.

Merging rule: same asset + same port (when known) + a title/CWE/CVE signature that overlaps closely enough
to plausibly be the same underlying issue. We never merge findings that disagree on asset or port, and we
never drop evidence on merge -- all source evidence and tool names are kept on the merged record.
"""
from __future__ import annotations

import re
from difflib import SequenceMatcher

from .models import Finding, SEVERITY_ORDER

_STOP = re.compile(r"[^a-z0-9]+")


def _norm_title(t: str) -> str:
    return _STOP.sub(" ", t.lower()).strip()


def _signature(f: Finding) -> tuple:
    cve_sig = tuple(sorted(f.cve)) if f.cve else None
    cwe_sig = tuple(sorted(f.cwe)) if f.cwe else None
    return (f.asset, f.port, cve_sig, cwe_sig)


def _similar(a: Finding, b: Finding) -> bool:
    if a.asset != b.asset or a.port != b.port:
        return False
    if a.cve and b.cve and set(a.cve) & set(b.cve):
        return True
    if a.cwe and b.cwe and set(a.cwe) & set(b.cwe) and SequenceMatcher(
            None, _norm_title(a.title), _norm_title(b.title)).ratio() > 0.45:
        return True
    return SequenceMatcher(None, _norm_title(a.title), _norm_title(b.title)).ratio() > 0.78


def _merge_two(a: Finding, b: Finding) -> Finding:
    """Fold b into a. a is kept as the surviving record; nothing from b is discarded."""
    keep, drop = (a, b) if SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[b.severity] else (b, a)
    merged = keep.model_copy(deep=True)
    merged.merged_from = sorted(set(keep.merged_from) | set(drop.merged_from) | {drop.id})
    merged.source_tools = sorted(set(keep.source_tools) | set(drop.source_tools))
    merged.evidence = keep.evidence + [e for e in drop.evidence if e not in keep.evidence]
    merged.cve = sorted(set(keep.cve) | set(drop.cve))
    merged.cwe = sorted(set(keep.cwe) | set(drop.cwe))
    merged.owasp = sorted(set(keep.owasp) | set(drop.owasp))
    merged.references = sorted(set(keep.references) | set(drop.references))
    merged.inference = keep.inference + [i for i in drop.inference if i not in keep.inference]
    # cross-tool confirmation raises confidence and status, but only because two independent
    # tools observed it -- the bump is explained in the finding's inference trail.
    if len(merged.source_tools) > 1 and merged.status != "confirmed":
        merged.status = "confirmed"
        merged.confidence = round(min(0.98, max(keep.confidence, drop.confidence) + 0.15), 2)
        merged.inference.append(
            f"[inference] Confirmed independently by {len(merged.source_tools)} tools "
            f"({', '.join(merged.source_tools)}); confidence raised accordingly.")
    else:
        merged.confidence = round(max(keep.confidence, drop.confidence), 2)
    if not merged.description and drop.description:
        merged.description = drop.description
    if not merged.solution and drop.solution:
        merged.solution = drop.solution
    if not merged.cvss and drop.cvss:
        merged.cvss = drop.cvss
    return merged


def correlate(raw_findings: list[Finding]) -> list[Finding]:
    """Greedy clustering: O(n^2) over raw findings, fine at hackathon-prototype scale (hundreds, not millions)."""
    buckets: dict[tuple, list[Finding]] = {}
    for f in raw_findings:
        buckets.setdefault((f.asset, f.port), []).append(f)

    merged: list[Finding] = []
    for group in buckets.values():
        clusters: list[Finding] = []
        for f in group:
            placed = False
            for i, c in enumerate(clusters):
                if _similar(c, f):
                    clusters[i] = _merge_two(c, f)
                    placed = True
                    break
            if not placed:
                clusters.append(f.model_copy(deep=True))
        merged.extend(clusters)

    # Low-confidence single-source findings with no CVE/CWE and generic info banners are flagged,
    # never silently removed -- the human reviewer sees them tagged, not hidden.
    for f in merged:
        if f.severity == "info" and len(f.source_tools) == 1 and not f.cve and f.confidence < 0.5:
            f.status = "false_positive_candidate" if f.status != "confirmed" else f.status
    return merged
