"""Adaptive planning.

Three things changed from a "run a fixed script" agent to one that demonstrates real reasoning:

1. Planning reacts to *services discovered* (as before) AND to *findings' severity/confidence*
   (new) -- a lone, low-confidence critical finding from one tool now triggers a proposal to
   corroborate it with another angle, not just "open port -> run scanner X".
2. Every batch of candidate next-steps is explicitly *ranked*, not just appended in discovery
   order: a deterministic, reproducible rule-based score is always computed; when an LLM key is
   configured, `reasoning.arbitrate()` is additionally asked to keep/defer/explain each candidate,
   strictly bounded to the ids already produced by the rules (see reasoning.py for why that bound
   is the actual safety property, not just a style choice).
3. Steps that were considered and deliberately NOT run yet are kept on the plan with
   status="skipped" and a reason, not silently dropped -- "avoid unnecessary actions" means being
   able to show *why* something wasn't done, not just not doing it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from .models import Assessment, Finding, PlanStep, Service

TOOL_FOR_WEB = ["nikto", "zap"]

# base_priority: 0..1, higher = more urgent. Purely a deterministic fallback/seed score; an LLM
# arbitration pass (when configured) can re-rank on top of this, never below the closed candidate set.
SERVICE_TRIGGER_PRIORITY = {"web": 0.55, "smb": 0.70, "ftp": 0.50, "ssl": 0.35, "db": 0.60, "dns": 0.30}

DB_PORT_NAMES = {"mysql", "ms-sql-s", "postgresql", "oracle", "mongodb", "redis", "memcached"}
DB_PORTS = {3306, 5432, 1433, 1521, 27017, 6379, 11211}


@dataclass
class Candidate:
    """One not-yet-decided option for the next step. Already a legitimate, rules-chosen
    (tool, target, preset) -- an LLM arbitration pass can only accept/defer/reorder these, never
    invent a different one. See reasoning.py."""
    tool: str
    target: str
    preset: str
    rationale: str
    kind: str                                   # "discovery" | "service" | "finding"
    depends_on_evidence: list[str] = field(default_factory=list)
    trigger_finding_id: str | None = None
    intrusive: bool = False
    base_priority: float = 0.5

    @property
    def key(self) -> tuple:
        return (self.tool, self.target, self.preset)

    def summary(self) -> dict:
        return {"tool": self.tool, "target": self.target, "preset": self.preset}


@dataclass
class RankedCandidate:
    candidate: Candidate
    keep: bool
    priority: float          # 0..1, higher = more urgent
    explanation: str
    origin: str               # "rules" | "llm"
    alternatives: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Candidate generation (pure rules; never calls the LLM)
# ---------------------------------------------------------------------------

def _initial_candidates(a: Assessment) -> list[Candidate]:
    return [Candidate(tool="nmap", target=t, preset="discovery", kind="discovery", base_priority=1.0,
                      rationale=f"No services are known on {t} yet; run host/port/service discovery "
                                "first so every later step can be scoped to what is actually running.")
            for t in a.scope.targets]


def _candidates_from_services(a: Assessment, services: list[Service]) -> list[Candidate]:
    out: list[Candidate] = []
    seen_web_hosts: set[str] = set()
    for svc in services:
        ref = f"nmap:host={svc.host}/port={svc.port}"
        if svc.is_web and svc.host not in seen_web_hosts:
            seen_web_hosts.add(svc.host)
            for tool in TOOL_FOR_WEB:
                out.append(Candidate(
                    tool=tool, target=svc.url(), preset="default" if tool == "nikto" else "baseline",
                    kind="service", depends_on_evidence=[ref], base_priority=SERVICE_TRIGGER_PRIORITY["web"],
                    rationale=f"nmap found an HTTP(S) service on {svc.host}:{svc.port} "
                               f"({svc.product or svc.name or 'unidentified'}); {tool} targets web-layer "
                               "misconfigurations and vulnerabilities that a port scan cannot see."))
        if svc.name in ("microsoft-ds", "netbios-ssn") or svc.port == 445:
            out.append(Candidate(tool="nmap", target=svc.host, preset="smb_safe", kind="service",
                                 depends_on_evidence=[ref], base_priority=SERVICE_TRIGGER_PRIORITY["smb"],
                                 rationale=f"SMB exposed on {svc.host}:445; checking protocol/signing "
                                           "posture and known critical SMB CVEs (e.g. MS17-010) with "
                                           "safe, non-intrusive NSE scripts."))
        if svc.port == 21 or svc.name == "ftp":
            out.append(Candidate(tool="nmap", target=svc.host, preset="ftp_safe", kind="service",
                                 depends_on_evidence=[ref], base_priority=SERVICE_TRIGGER_PRIORITY["ftp"],
                                 rationale=f"FTP exposed on {svc.host}:21; checking for anonymous access."))
        if svc.tunnel == "ssl" or svc.port in (443, 8443):
            out.append(Candidate(tool="nmap", target=f"{svc.host}:{svc.port}", preset="ssl", kind="service",
                                 depends_on_evidence=[ref], base_priority=SERVICE_TRIGGER_PRIORITY["ssl"],
                                 rationale=f"TLS detected on {svc.host}:{svc.port}; enumerating protocol "
                                           "versions and cipher strength."))
        if svc.name in DB_PORT_NAMES or svc.port in DB_PORTS:
            out.append(Candidate(tool="nmap", target=svc.host, preset="vulners", kind="service",
                                 depends_on_evidence=[ref], base_priority=SERVICE_TRIGGER_PRIORITY["db"],
                                 rationale=f"A database service ({svc.name or svc.port}) is exposed on "
                                           f"{svc.host}:{svc.port}; database ports carry high impact if "
                                           "misconfigured, so version/vuln fingerprinting is prioritized."))
    return out


def _candidates_from_findings(a: Assessment, findings: list[Finding]) -> list[Candidate]:
    """The genuinely new behaviour: react to a FINDING's severity/confidence, not just to a port
    being open. A single-source critical/high finding is weak evidence on its own (one tool's
    interpretation, unconfirmed) -- propose a concrete, scope-safe way to try to corroborate it
    before it reaches a client report as anything stronger than 'suspected'.

    The corroborating action is chosen to actually be *capable* of corroborating the finding, not
    just "run something else": an nmap vulners-style CVE check is only proposed for CVE-bearing
    findings nmap itself didn't already surface at that exact port (re-running nmap can't say
    anything new about a Burp-reported SQL injection, for instance -- that needs a second web-layer
    opinion, which is the separate nikto/zap cross-check below)."""
    out: list[Candidate] = []
    # Ports/assets where nmap has already produced CVE evidence of its own -- re-proposing an
    # nmap vulners check there would tell us nothing we don't already know.
    nmap_cve_ports = {(rf.asset, rf.port) for rf in a.raw_findings if "nmap" in rf.source_tools and rf.cve}
    for f in findings:
        if f.status == "false_positive_candidate" or f.severity not in ("critical", "high"):
            continue
        if len(f.source_tools) > 1:          # already corroborated by an independent tool
            continue
        urgency = min(1.0, max(0.5, (f.risk_score or 50) / 100))
        if f.cve and "nmap" not in f.source_tools and (f.asset, f.port) not in nmap_cve_ports:
            out.append(Candidate(
                tool="nmap", target=f.asset, preset="vulners", kind="finding",
                trigger_finding_id=f.id, base_priority=urgency,
                rationale=f"'{f.title}' on {f.asset}:{f.port} is {f.severity}, carries {', '.join(f.cve)}, "
                           f"and was reported only by {f.source_tools[0]} at confidence {f.confidence:.2f}; "
                           "an independent vulnerability-database check (nmap vulners) on the same host "
                           "was not yet run and may corroborate or weaken it before it is reported as "
                           "anything stronger than 'suspected'."))
        if f.port in (80, 443, 8080, 8443) or "http" in f.service.lower():
            have = {r.tool for r in a.runs if r.status == "ok" and f.asset in r.target} | set(f.source_tools)
            for tool in TOOL_FOR_WEB:
                if tool not in have:
                    out.append(Candidate(
                        tool=tool, target=f"http{'s' if f.port == 443 else ''}://{f.asset}:{f.port}",
                        preset="default" if tool == "nikto" else "baseline", kind="finding",
                        trigger_finding_id=f.id, base_priority=urgency,
                        rationale=f"'{f.title}' ({f.severity}) on {f.asset}:{f.port} has not yet been "
                                   f"cross-checked with {tool}; a second, independent web-layer tool may "
                                   "confirm or contradict a single-tool finding before it is prioritized "
                                   "as validated."))
    return out


# ---------------------------------------------------------------------------
# Ranking: deterministic rules, with optional bounded LLM arbitration on top
# ---------------------------------------------------------------------------

def _dedupe(a: Assessment, candidates: list[Candidate]) -> list[Candidate]:
    existing = {(s.tool, s.target, s.preset) for s in a.plan}
    out, seen = [], set()
    for c in candidates:
        if c.key in existing or c.key in seen:
            continue
        seen.add(c.key)
        out.append(c)
    return out


def _rule_rank(candidates: list[Candidate]) -> list[RankedCandidate]:
    ordered = sorted(candidates, key=lambda c: -c.base_priority)
    ranked = []
    for c in ordered:
        others = [o for o in ordered if o is not c]
        alts = [{**o.summary(), "note": f"also proposed in this batch; rule priority "
                                        f"{o.base_priority:.2f} vs {c.base_priority:.2f}"} for o in others]
        ranked.append(RankedCandidate(candidate=c, keep=True, priority=c.base_priority,
                                      explanation=c.rationale, origin="rules", alternatives=alts))
    return ranked


def _llm_rank(context: str, candidates: list[Candidate]) -> list[RankedCandidate] | None:
    from . import reasoning
    ids = [f"c{i}" for i in range(len(candidates))]
    payload = [{"id": ids[i], "tool": c.tool, "target": c.target, "preset": c.preset,
               "rationale": c.rationale, "evidence_summary": "; ".join(c.depends_on_evidence) or "n/a"}
              for i, c in enumerate(candidates)]
    verdicts = reasoning.arbitrate(context, payload)
    if verdicts is None:
        return None
    by_id = {v.id: v for v in verdicts}
    ranked = []
    for i, c in enumerate(candidates):
        v = by_id.get(ids[i])
        if v is None:   # LLM omitted this id -- keep it, rule-ranked, rather than silently drop it
            ranked.append(RankedCandidate(candidate=c, keep=True, priority=c.base_priority,
                                          explanation=c.rationale, origin="rules"))
            continue
        alts = [{**candidates[j].summary(), "keep": by_id[ids[j]].keep,
                "reason": by_id[ids[j]].explanation} for j in range(len(candidates))
               if j != i and ids[j] in by_id]
        priority_norm = max(0.0, min(1.0, 1.0 - (max(v.priority, 1) - 1) * 0.15))
        ranked.append(RankedCandidate(candidate=c, keep=v.keep, priority=priority_norm,
                                      explanation=v.explanation, origin="llm", alternatives=alts))
    ranked.sort(key=lambda r: (-r.keep, -r.priority))
    return ranked


def rank_candidates(a: Assessment, candidates: list[Candidate], context: str) -> list[RankedCandidate]:
    candidates = _dedupe(a, candidates)
    if not candidates:
        return []
    if len(candidates) > 1 and os.environ.get("ANTHROPIC_API_KEY"):
        llm_ranked = _llm_rank(context, candidates)
        if llm_ranked is not None:
            a.llm_mode = "llm-arbitrated"
            return llm_ranked
        a.llm_notes.append(f"LLM arbitration unavailable or returned an unusable response for a batch "
                           f"of {len(candidates)} candidate(s); fell back to rule-based ranking.")
    return _rule_rank(candidates)


def materialize(ranked: list[RankedCandidate]) -> list[PlanStep]:
    steps = []
    for r in ranked:
        c = r.candidate
        rationale = c.rationale
        if r.origin == "llm" and r.explanation and r.explanation not in rationale:
            rationale = f"{rationale} [LLM arbitration: {r.explanation}]"
        steps.append(PlanStep(
            tool=c.tool, target=c.target, preset=c.preset, kind=c.kind, origin=r.origin,
            rationale=rationale, depends_on_evidence=c.depends_on_evidence,
            trigger_finding_id=c.trigger_finding_id, intrusive=c.intrusive,
            status="proposed" if r.keep else "skipped",
            skip_reason="" if r.keep else (r.explanation or "deprioritized by rule ranking"),
            priority_score=r.priority, llm_explanation=r.explanation if r.origin == "llm" else "",
            alternatives_considered=r.alternatives))
    return steps


# ---------------------------------------------------------------------------
# Public entry points used by the orchestrator
# ---------------------------------------------------------------------------

def build_initial_plan(a: Assessment) -> list[PlanStep]:
    """The very first step(s): always discovery, never arbitrated (there is no real choice yet)."""
    return materialize([RankedCandidate(candidate=c, keep=True, priority=1.0, explanation=c.rationale,
                                        origin="rules") for c in _initial_candidates(a)])


def plan_from_services(a: Assessment, services: list[Service]) -> list[PlanStep]:
    candidates = _candidates_from_services(a, services)
    context = (f"Assessment {a.id}: reacting to {len(services)} newly observed service(s) on "
              f"{len({s.host for s in services})} host(s).")
    return materialize(rank_candidates(a, candidates, context))


def plan_from_findings(a: Assessment) -> list[PlanStep]:
    """Called after correlation/risk scoring: reacts to a FINDING's severity/confidence rather
    than to an open port. This is the adaptive-replanning behaviour the rules-only, service-driven
    version did not have."""
    candidates = _candidates_from_findings(a, a.findings)
    context = (f"Assessment {a.id}: reacting to {len(a.findings)} correlated finding(s) after "
              "risk scoring, looking for single-source critical/high findings worth corroborating.")
    return materialize(rank_candidates(a, candidates, context))


def propose_validation_steps(a: Assessment, findings: list[Finding]) -> list[dict]:
    """For findings severe enough to warrant active validation, propose an approval request.
    This NEVER runs anything -- it only produces the request for a human to approve or deny."""
    proposals = []
    for f in findings:
        if f.severity in ("critical", "high") and f.status != "false_positive_candidate" and f.cve:
            proposals.append({
                "finding_id": f.id, "asset": f.asset,
                "action": f"Run msfconsole in 'check' mode (non-exploitative where the module supports it) "
                          f"against {f.asset}:{f.port} to confirm {', '.join(f.cve) or f.title}.",
                "rationale": f"{f.title} is {f.severity} severity with confidence {f.confidence:.2f}; "
                             "active validation would move it from 'suspected' to a defensibly 'validated' "
                             "or 'not_reproducible' status before it reaches the client report.",
            })
    return proposals
