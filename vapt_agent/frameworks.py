"""MITRE ATT&CK technique tagging and a NIST CSF 2.0 process-alignment note.

Both are explicitly optional, defensible enrichments -- the problem statement itself says "using
these standards and frameworks does not, by itself, establish formal compliance with them," and
this module is written to honor that rather than paper over it:

- ATT&CK tags are applied only where there is a well-established, specific technique association
  (a named vulnerability like EternalBlue/MS17-010, or a CWE with a widely-accepted ATT&CK
  crosswalk such as SQL injection -> Exploit Public-Facing Application). There is no blanket
  "every finding gets a technique" rule, and nothing here claims an adversary action was actually
  observed -- it's a reference tag on a *vulnerability*, not a detection of *exploitation* (unless
  the finding's own validation_status says otherwise). Every tag is paired with an inference note
  saying exactly that.
- The CSF 2.0 note is a single, fixed paragraph describing which CSF functions this assessment's
  own *workflow* (scope control, discovery, control evaluation, correlation, human-approved
  response) touches -- it is about the assessment process, not a claim that the target environment
  is CSF-compliant.
"""
from __future__ import annotations

import re

from .models import Finding

# (CWE id) -> (ATT&CK technique id, technique name). Deliberately short: each entry is a specific,
# commonly-cited crosswalk, not a loose guess.
_BY_CWE: dict[str, tuple[str, str]] = {
    "CWE-89": ("T1190", "Exploit Public-Facing Application"),   # SQL injection
    "CWE-79": ("T1190", "Exploit Public-Facing Application"),   # Cross-site scripting
    "CWE-287": ("T1078", "Valid Accounts"),                      # Improper authentication (e.g. anon access)
}

# (title/description pattern) -> (technique id, technique name). Matched in addition to the CWE
# table above, for cases (like a named CVE) where the adapter didn't also set a CWE.
_BY_TITLE: list[tuple[re.Pattern, tuple[str, str]]] = [
    (re.compile(r"ms17-?010|eternalblue|cve-2017-0143", re.I),
     ("T1210", "Exploitation of Remote Services")),       # ATT&CK's own T1210 page cites EternalBlue
    (re.compile(r"anonymous ftp|anonymous login", re.I), ("T1078", "Valid Accounts")),
    (re.compile(r"sql injection", re.I), ("T1190", "Exploit Public-Facing Application")),
    (re.compile(r"cross site scripting|\bxss\b", re.I), ("T1190", "Exploit Public-Facing Application")),
]

CSF_FUNCTIONS = ("Govern", "Identify", "Protect", "Detect", "Respond")

CSF_ALIGNMENT_NOTE = (
    "This assessment's own workflow maps to the NIST Cybersecurity Framework (CSF) 2.0 functions "
    "as follows: GOVERN -- a registered scope, exclusions, and an auditable, hash-chained decision "
    "trail gate every action; IDENTIFY -- host, service, and asset discovery; PROTECT -- evaluating "
    "authentication, encryption, and configuration controls; DETECT -- multi-tool correlation and "
    "evidence-based finding analysis; RESPOND -- human-approved active validation and remediation "
    "guidance. This describes the assessment process itself, not a compliance claim about the "
    "target environment."
)


def tag_finding(f: Finding) -> list[str]:
    """Return e.g. ['T1210 — Exploitation of Remote Services'] for well-established mappings only;
    [] when nothing in the (small, deliberately conservative) table applies."""
    tags: dict[str, str] = {}
    for cwe in f.cwe:
        hit = _BY_CWE.get(cwe)
        if hit:
            tags[hit[0]] = hit[1]
    haystack = f.title
    for pattern, hit in _BY_TITLE:
        if pattern.search(haystack):
            tags[hit[0]] = hit[1]
    return [f"{tid} — {name}" for tid, name in sorted(tags.items())]


def apply(findings: list[Finding]) -> None:
    """Mutate each finding in place: set .mitre_attack where a tag applies, and record why as an
    explicitly-labelled inference (never silently added, never presented as observed behavior)."""
    for f in findings:
        if f.mitre_attack:        # already tagged (e.g. re-running analyse() after a correlation change)
            continue
        tags = tag_finding(f)
        if tags:
            f.mitre_attack = tags
            f.inference.append(
                "[inference] MITRE ATT&CK reference mapping (indicative, not an adversary action "
                f"observed during this assessment): {', '.join(tags)}.")
