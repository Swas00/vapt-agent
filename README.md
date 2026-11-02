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

**Live scanning demo** (real `nmap` + `nikto` subprocesses against `127.0.0.1` only — this machine's
own loopback interface serving a throwaway local HTTP server started by the script; never a
third-party host):

```bash
brew install nmap nikto     # one-time
.venv/bin/python live_demo.py
```

**Interactive API + UI**:

```bash
.venv/bin/uvicorn vapt_agent.api:app --reload
# then open http://127.0.0.1:8000/ui/ and sign in with an analyst token (next section)
```

### Authentication — who did what

Every state-changing endpoint (create assessment, approve/run a step, import, analyse, request/decide/
execute an approval, generate the report) requires `Authorization: Bearer <analyst token>`. Each token
belongs to exactly one named analyst, and **that verified name — never anything the client sends — is what
the audit log and the approval records store** (PS-1 §13: "every action is attributable"). A `by=` query
parameter, if a client still sends one, is ignored. Read-only `GET` routes (the audit trail, integration
matrix, assessment views) stay open so the trail is inspectable.

```bash
# real identities (tokens >= 16 chars; names [A-Za-z0-9._-]; "agent" and "system" are reserved
# for automated audit-log actors and can't be assigned to a person):
export VAPT_ANALYST_TOKENS="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))'):alice,$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))'):bob"
```

With `VAPT_ANALYST_TOKENS` unset, the server starts in **dev mode**: it generates one token for the identity
`analyst`, prints it at startup, and persists it (mode `0600`) at `data/.dev_token` so `--reload` doesn't
invalidate it. Paste the token into the UI's sign-in card (kept in `sessionStorage` — cleared when the tab
closes). From a script: `curl -H "Authorization: Bearer $TOKEN" -X POST ...`. A malformed
`VAPT_ANALYST_TOKENS` stops the server at startup rather than silently running open. Failed attempts are
audited (throttled per client, and the presented token is never recorded).

**Tests** (304 Python + 51 jsdom: scope enforcement, all 6 parsers, correlation/dedup, risk scoring &
CVSS-vector parsing (incl. boundary cases), candidate-based planning + bounded LLM arbitration (incl. a
prompt-injection test), MITRE/CSF tagging, report generation (incl. a load test), full orchestrator
pipeline (incl. concurrency/race tests and live scan cancellation), approval gating, live nmap/nikto
subprocess runs, ZAP and Metasploit wiring, **authentication** — config parsing, constant-time comparison,
a meta-test that fails if any POST route lacks the guard, negative-path/malformed-input tests, and
HTTP-level tests through FastAPI's `TestClient` — plus a jsdom suite that executes the real web page,
including structural keyboard-nav/accessible-name regression tests):

```bash
.venv/bin/python -m pytest -q

# optional: enables the jsdom UI suite (otherwise that one test is skipped, not failed)
cd tests/frontend && npm install && npm test
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
  auth.py           per-analyst bearer tokens -> verified identities (what the audit log records)
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
tests/              pytest suite + recorded fixture tool outputs; tests/frontend = jsdom UI tests
demo.py             headless end-to-end demo script
docs/               architecture overview + integration transparency matrix
```
