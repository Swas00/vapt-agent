"""Adaptive planning: rules-first, LLM-explained. Every step carries a rationale and, where it exists,
the evidence that triggered it -- so "adaptive" is demonstrable rather than asserted.

If ANTHROPIC_API_KEY is set, the LLM is used only to (a) phrase rationale for a human reader and
(b) suggest *additional* candidate steps from an allow-listed menu; it can never invent a tool, a
target, or a finding, and every suggestion still passes through scope.check() before it can run.
"""
from __future__ import annotations

import os

from .models import Assessment, Finding, PlanStep, Service

TOOL_FOR_WEB = ["nikto", "zap"]
INTRUSIVE_PRESETS = {("zap", "active")}


def _rule_plan(a: Assessment) -> list[PlanStep]:
    steps: list[PlanStep] = []
    for target in a.scope.targets:
        steps.append(PlanStep(
            tool="nmap", target=target, preset="discovery", origin="rules",
            rationale=f"No services are known on {target} yet; run host/port/service discovery first "
                       "so every later step can be scoped to what is actually running."))
    return steps


def expand_from_services(a: Assessment, services: list[Service]) -> list[PlanStep]:
    """Called after discovery (and after any new scan) to propose the next, evidence-driven steps."""
    steps: list[PlanStep] = []
    existing = {(s.tool, s.target, s.preset) for s in a.plan}
    seen_web_hosts = set()
    for svc in services:
        ref = f"nmap:host={svc.host}/port={svc.port}"
        if svc.is_web and svc.host not in seen_web_hosts:
            seen_web_hosts.add(svc.host)
            for tool in TOOL_FOR_WEB:
                key = (tool, svc.url(), "default" if tool == "nikto" else "baseline")
                if key in existing:
                    continue
                steps.append(PlanStep(
                    tool=tool, target=svc.url(), preset=key[2], origin="rules",
                    depends_on_evidence=[ref],
                    rationale=f"nmap found an HTTP(S) service on {svc.host}:{svc.port} "
                               f"({svc.product or svc.name or 'unidentified'}); {tool} targets web-layer "
                               "misconfigurations and vulnerabilities that a port scan cannot see."))
        if svc.name in ("microsoft-ds", "netbios-ssn") or svc.port == 445:
            key = ("nmap", svc.host, "smb_safe")
            if key not in existing:
                steps.append(PlanStep(tool="nmap", target=svc.host, preset="smb_safe", origin="rules",
                                      depends_on_evidence=[ref],
                                      rationale=f"SMB exposed on {svc.host}:445; checking protocol/signing "
                                                "posture and known critical SMB CVEs (e.g. MS17-010) with "
                                                "safe, non-intrusive NSE scripts."))
        if svc.port == 21 or svc.name == "ftp":
            key = ("nmap", svc.host, "ftp_safe")
            if key not in existing:
                steps.append(PlanStep(tool="nmap", target=svc.host, preset="ftp_safe", origin="rules",
                                      depends_on_evidence=[ref],
                                      rationale=f"FTP exposed on {svc.host}:21; checking for anonymous access."))
        if svc.tunnel == "ssl" or svc.port in (443, 8443):
            key = ("nmap", f"{svc.host}:{svc.port}", "ssl")
            if key not in existing:
                steps.append(PlanStep(tool="nmap", target=f"{svc.host}:{svc.port}", preset="ssl", origin="rules",
                                      depends_on_evidence=[ref],
                                      rationale=f"TLS detected on {svc.host}:{svc.port}; enumerating protocol "
                                                "versions and cipher strength."))
    new = [s for s in steps if (s.tool, s.target, s.preset) not in existing]
    return new


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


def build_initial_plan(a: Assessment) -> list[PlanStep]:
    plan = _rule_plan(a)
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            from .llm import explain_plan
            explain_plan(a, plan)
            a.llm_mode = "llm-explained"
        except Exception as e:  # noqa: BLE001 - LLM is an optional enrichment, never a hard dependency
            a.llm_notes.append(f"LLM rationale enrichment unavailable: {e}")
    return plan
