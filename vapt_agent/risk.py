"""Transparent, deterministic risk scoring. No LLM involvement: every number is reproducible.

score = 100 * (0.45*cvss/10 + 0.20*exploitability + 0.15*exposure + 0.20*asset_impact) * (0.5 + 0.5*confidence)
"""
from __future__ import annotations

from .models import Finding, ScopeModel, SEVERITY_ORDER, is_false_positive

# Used ONLY when a tool gave a severity band but no CVSS. Flagged as estimated everywhere it appears.
BAND_TO_CVSS = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0.0}
CRIT = {"low": 0.3, "medium": 0.5, "high": 0.8, "critical": 1.0}

EXPOSURE = {
    "remote_admin": (0.9, {"ssh", "telnet", "rdp", "ms-wbt-server", "vnc"}),
    "file_share": (0.85, {"smb", "microsoft-ds", "netbios-ssn", "ftp", "nfs", "rsync"}),
    "database": (0.7, {"mysql", "postgresql", "ms-sql-s", "oracle", "mongodb", "redis", "memcached"}),
    "web": (0.8, {"http", "https", "http-proxy", "http-alt", "ssl/http"}),
}


def severity_from_cvss(c: float) -> str:
    if c >= 9.0:
        return "critical"
    if c >= 7.0:
        return "high"
    if c >= 4.0:
        return "medium"
    if c > 0:
        return "low"
    return "info"


def exposure_of(f: Finding) -> tuple[float, str]:
    svc = f.service.lower()
    for label, (w, names) in EXPOSURE.items():
        if any(n in svc for n in names):
            return w, label
    if f.port in (80, 443, 8080, 8443):
        return 0.8, "web"
    return (0.5, "other") if f.port else (0.4, "host-level")


def exploitability_of(f: Finding) -> tuple[float, str]:
    if f.validation_status == "validated":
        return 1.0, "validated by approved exploitation check"
    if f.exploit_available is True:
        return 0.8, "tool reports a public exploit is available"
    if f.exploit_available is False:
        return 0.3, "tool reports no known exploit"
    if f.cve:
        return 0.5, "CVE assigned; exploit availability unknown"
    return 0.3, "no CVE; exploitability unknown"


def score(f: Finding, scope: ScopeModel) -> Finding:
    if f.cvss is None:
        f.cvss = BAND_TO_CVSS[f.severity]
        f.cvss_estimated = True
    base = f.cvss / 10
    expl, expl_why = exploitability_of(f)
    expo, expo_label = exposure_of(f)
    crit_label = scope.asset_criticality.get(f.asset, "medium")
    impact = CRIT[crit_label]
    raw = 0.45 * base + 0.20 * expl + 0.15 * expo + 0.20 * impact
    conf_factor = 0.5 + 0.5 * f.confidence
    s = round(100 * raw * conf_factor, 1)
    if is_false_positive(f):
        s = round(s * 0.4, 1)
    f.risk_score = s
    f.priority = "P1" if s >= 65 else "P2" if s >= 45 else "P3" if s >= 25 else "P4"
    f.risk_breakdown = {
        "cvss": f.cvss, "cvss_estimated": f.cvss_estimated,
        "exploitability": {"value": expl, "why": expl_why},
        "exposure": {"value": expo, "class": expo_label},
        "asset_impact": {"value": impact, "criticality": crit_label,
                         "set_by": "analyst" if f.asset in scope.asset_criticality else "default"},
        "confidence": f.confidence, "confidence_factor": round(conf_factor, 2),
        "formula": "100*(0.45*cvss/10+0.20*expl+0.15*expo+0.20*impact)*(0.5+0.5*confidence)",
    }
    return f


def rank(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-(f.risk_score or 0), -SEVERITY_ORDER[f.severity], f.asset, f.port or 0))


_AV = {"N": "network", "A": "adjacent-network", "L": "local", "P": "physical"}
_CIA = {"N": "none", "L": "low", "H": "high"}


def parse_cvss_vector(vector: str | None) -> dict[str, str]:
    """Parse a CVSS v3/v3.1 vector string (e.g. 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')
    into its component metrics. Returns {} for anything missing or not in the expected shape --
    this is read-only parsing of a value a tool already reported, never a score we compute."""
    if not vector:
        return {}
    parts = {}
    for seg in vector.split("/"):
        if ":" in seg:
            k, _, v = seg.partition(":")
            parts[k] = v
    return parts


def describe_cvss_vector(vector: str | None) -> str | None:
    """Plain-English clause from a CVSS vector's own metrics -- 'network-exploitable, with high
    confidentiality, integrity, and availability impact if successful' -- or None if the vector is
    absent/unparseable. Never invents an impact level the vector doesn't itself state."""
    m = parse_cvss_vector(vector)
    if "C" not in m or "I" not in m or "A" not in m:
        return None
    av = _AV.get(m.get("AV", ""), None)
    cia = []
    for label, key in (("confidentiality", "C"), ("integrity", "I"), ("availability", "A")):
        level = _CIA.get(m.get(key, ""))
        if level and level != "none":
            cia.append(f"{level} {label}")
    prefix = f"{av}-exploitable, with " if av else "with "
    if not cia:
        return f"{prefix}no confidentiality, integrity, or availability impact reported by this vector"
    return prefix + ", ".join(cia) + " impact if successful"
