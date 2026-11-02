"""Compare two assessments of the same scope to show what changed between scans -- the retest
workflow PS calls out ("reduces manual coordination effort over time") as distinct from a
one-shot scan. Matching is by (asset, port, title) rather than Finding.id, since a fresh
assessment re-parses raw tool output into brand-new Finding objects with their own ids even
when the underlying vulnerability is identical.
"""
from __future__ import annotations

from .models import Assessment, Finding


def _key(f: Finding) -> tuple[str, object, str]:
    return (f.asset.strip().lower(), f.port, f.title.strip().lower())


def compare(before: Assessment, after: Assessment) -> dict:
    """`before`/`after` should be two assessments of the same scope, `before` run first.
    Returns the new/fixed/persisting split based on the correlated `findings`, not the raw
    per-tool output."""
    before_map = {_key(f): f for f in before.findings}
    after_map = {_key(f): f for f in after.findings}
    new = [after_map[k] for k in after_map if k not in before_map]
    fixed = [before_map[k] for k in before_map if k not in after_map]
    persisting = [after_map[k] for k in after_map if k in before_map]
    return {
        "before_id": before.id,
        "after_id": after.id,
        "new": new,
        "fixed": fixed,
        "persisting": persisting,
        "new_count": len(new),
        "fixed_count": len(fixed),
        "persisting_count": len(persisting),
    }
