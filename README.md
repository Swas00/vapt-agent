# VAPT Agent — AI Agent for Automated Penetration Testing

A conversational, evidence-driven, human-in-the-loop AI agent that guides an **authorized** security
assessment from reconnaissance through a client-ready VAPT report — built for the DataOps Innovation
Hackathon (Problem Statement 1: *AI-Powered Unified VAPT Agent*).

> **Scope boundary**: this tool is designed to run **only** against organizer-provided / explicitly
> authorized lab targets. See [`vapt_agent/scope.py`](vapt_agent/scope.py) for the enforcement logic and
> [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#4-security-boundaries) for how it's wired in. Active
> exploitation (Metasploit) never runs without a recorded human approval.

## What it does

1. **Analyst request** — natural-language request + authorized target/scope.
2. **Agent planning** — generates a tool-selection plan with an explicit rationale per step; discovery
   (Nmap) always runs first, and later steps are proposed **only from evidence actually observed**
   (an HTTP port → web scanners; SMB → safe SMB checks; TLS → cipher checks), not a fixed script.
3. **Approved scan orchestration** — the analyst approves/rejects each step before it runs; scope
   enforcement re-checks every target regardless.
4. **Result ingestion** — live scans and imported tool exports (Nessus, OpenVAS, Burp, ZAP, Nikto, Nmap)
   are normalized onto one `Finding` schema with evidence, timestamps, and confidence preserved.
5. **Correlation** — genuine duplicates across tools are merged (keeping *all* evidence); weak,
   single-source, generic findings are tagged as false-positive candidates rather than hidden.
6. **Risk prioritization** — a transparent, reproducible formula (CVSS, exploitability, exposure,
   asset criticality, confidence) ranks every finding; the full breakdown ships in the report.
7. **Human review & approved validation** — critical/high findings can be escalated for a human-approved,
   check-mode-only Metasploit validation; denials and approvals are both recorded and shown in the report.
8. **Professional reporting** — a PDF with executive summary, methodology/RoE, severity distribution,
   per-finding evidence, remediation, limitations/assumptions, and the integration transparency matrix.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the component map and
[`docs/INTEGRATIONS.md`](docs/INTEGRATIONS.md) for the truthful live/import/planned status of all
seven required tools.

## Setup

Requires Python 3.11+.

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

Optional, for live tool execution (none of these are required to run the demo or the tests, which use
recorded fixture outputs):

- `nmap` on `PATH` for live discovery/vuln scans.
- `nikto` on `PATH` for live web-server checks.
- A running OWASP ZAP daemon + `ZAP_URL` / `ZAP_API_KEY` env vars for live web-app scanning.
- `msfconsole` on `PATH` for human-approved validation.
- `ANTHROPIC_API_KEY` env var to enable LLM-phrased rationale/summaries (optional; the system is fully
  functional and deterministic without it — see [`vapt_agent/llm.py`](vapt_agent/llm.py)).

## Running it

**Headless demo** (fixtures → correlated findings → sample PDF report, no live scanning, no network):

```bash
.venv/bin/python demo.py
# -> data/sample_report.pdf
```

**Interactive API + UI**:

```bash
.venv/bin/uvicorn vapt_agent.api:app --reload
# then open http://127.0.0.1:8000/ui/
```

**Tests** (27 tests: scope enforcement, all 6 parsers, correlation/dedup, risk scoring, full
orchestrator pipeline end-to-end, approval gating):

```bash
.venv/bin/python -m pytest -q
```

## Dependencies & licensing

All dependencies are open-source and declared in [`requirements.txt`](requirements.txt): FastAPI,
Uvicorn, Pydantic, ReportLab, httpx, defusedxml, the official `anthropic` SDK (optional). Nmap, Nikto,
OWASP ZAP and Metasploit are GPL/open-source security tools invoked as external processes/APIs, not
redistributed. Nessus and Burp Suite Professional are commercial products; this project integrates with
their **export formats only** (`.nessus` XML, Burp issue XML) and does not claim, bundle, or require a
license for live control of either — see `docs/INTEGRATIONS.md`.

## Project layout

```
vapt_agent/
  models.py        common data model (Finding, Assessment, ScopeModel, ToolRun, Approval, ...)
  scope.py          scope/target enforcement, called before every scan/finding/validation
  audit.py          append-only, hash-chained audit log
  planner.py        rules-first adaptive planning (+ optional LLM rationale phrasing)
  llm.py            optional Claude enrichment layer (explain-only, never decides)
  orchestrator.py   the only caller of adapters/scope/correlate/risk; owns Assessment lifecycle
  correlate.py      cross-tool normalization & duplicate merging
  risk.py           transparent, reproducible risk scoring
  report.py         client-ready PDF generation
  adapters/         one module per tool (nmap, nessus, openvas, nikto, zap, burp, metasploit)
  api.py            FastAPI surface
  static/index.html minimal UI exercising the full workflow
tests/              pytest suite + recorded fixture tool outputs
demo.py             headless end-to-end demo script
docs/               architecture overview + integration transparency matrix
```
