#!/usr/bin/env python3
"""Headless demo: builds a sample assessment from the fixture tool outputs and writes a sample
VAPT PDF report to data/sample_report.pdf, printing the audit trail summary. No live scanning.

Usage: .venv/bin/python demo.py
"""
from pathlib import Path

from vapt_agent.audit import AuditLog
from vapt_agent.models import ScopeModel
from vapt_agent.orchestrator import Orchestrator
from vapt_agent.report import generate

ROOT = Path(__file__).parent
FIX = ROOT / "tests" / "fixtures"
DATA = ROOT / "data"


def main():
    audit = AuditLog(DATA / "demo_audit.log")
    orch = Orchestrator(DATA, audit)

    scope = ScopeModel(
        targets=["10.10.10.5"],
        lab_attestation=True,
        allow_active_validation=True,
        asset_criticality={"10.10.10.5": "high"},
        permissions_note="Organizer-provided hackathon lab target, ticket #DEMO-001.",
    )
    a = orch.create(
        "Assess the lab web server and host for vulnerabilities ahead of the client demo; "
        "flag anything that would need urgent remediation.",
        scope,
    )
    print(f"[+] Created assessment {a.id}, initial plan has {len(a.plan)} step(s):")
    for s in a.plan:
        print(f"    - {s.tool} -> {s.target} ({s.preset}): {s.rationale}")

    for tool, fname in [("nmap", "nmap_sample.xml"), ("nikto", "nikto_sample.json"),
                        ("zap", "zap_sample.json"), ("burp", "burp_sample.xml"),
                        ("nessus", "nessus_sample.nessus"), ("openvas", "openvas_sample.xml")]:
        run = orch.import_result(a, tool, FIX / fname)
        print(f"[+] Imported {tool}: status={run.status} services={run.services} findings={run.findings}")

    print(f"[+] Adaptive plan grew to {len(a.plan)} step(s) after ingesting discovery evidence.")
    orch.analyse(a)
    print(f"[+] Correlated {len(a.raw_findings)} raw findings -> {len(a.findings)} unique findings.")
    for f in a.findings[:8]:
        print(f"    [{f.priority} {f.severity:>8}] {f.title} (asset={f.asset} risk={f.risk_score} "
              f"tools={','.join(f.source_tools)} status={f.status})")

    high = next((f for f in a.findings if f.severity in ("critical", "high")), None)
    if high:
        appr = orch.request_approval(a, high.id, f"Human-approved check-mode validation of '{high.title}'")
        orch.decide_approval(a, appr.id, True, by="lead-analyst",
                             reason="Approved for lab-only check-mode validation ahead of report sign-off.")
        print(f"[+] Approval {appr.id} recorded as {appr.state} (execution needs msfconsole on PATH; "
              "skipped in this headless demo environment).")

    out = generate(a, DATA / "sample_report.pdf")
    print(f"[+] Sample VAPT report written to {out}")

    ok, msg = audit.verify()
    print(f"[+] Audit trail: {msg} (hash-chain intact: {ok})")


if __name__ == "__main__":
    main()
