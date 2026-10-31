# Architecture Overview — AI-Powered Unified VAPT Agent

## 1. Workflow

```
Analyst Request → Agent Planning → Approved Scan Orchestration → Result Ingestion
   → AI Correlation & Analysis → Risk Prioritization → Human Review & Approved Validation
   → Professional Reporting
```

Implemented 1:1 as an `Assessment` object that moves through
`created → planned → scanning → analysed → reviewed → reported`, with every transition
written to an append-only, hash-chained audit log (`vapt_agent/audit.py`).

## 2. Components

| Layer | Module | Responsibility |
|---|---|---|
| Data model | `vapt_agent/models.py` | Common schema: `Assessment`, `ScopeModel`, `PlanStep`, `ToolRun`, `Finding`, `Evidence`, `Approval`, `Event`. Every finding carries source tool, asset, timestamps, raw reference, evidence snippet, confidence, confirmed/suspected status. |
| Scope enforcement | `vapt_agent/scope.py` | Parses every target, rejects shell metacharacters, enforces exclusions, registered targets, allowed ports/tools, lab attestation, and blocks public IPs unless explicitly opted in. Called before *every* scan, *every* ingested finding, and *every* validation execution — not just once at the start. |
| Adaptive planning | `vapt_agent/planner.py` | Rules-first: discovery is always step one. After each ingestion, `expand_from_services()` proposes next steps **only from evidence actually observed** (an open web port → nikto/ZAP; SMB → safe NSE checks; TLS → cipher enumeration). Each step carries `depends_on_evidence` pointing at the triggering observation, so "adaptive" is demonstrable, not asserted. |
| Tool adapters | `vapt_agent/adapters/*.py` | One adapter per tool, each declaring its own truthful `live_status` (`live` / `import-only` / `planned`). See [`INTEGRATIONS.md`](INTEGRATIONS.md). |
| Orchestration | `vapt_agent/orchestrator.py` | The only place that calls adapters, scope checks, the correlator and the risk engine. Owns plan execution, result ingestion, and the human-approval workflow for active validation. |
| Normalization & correlation | `vapt_agent/correlate.py` | Maps all adapters' output onto the common `Finding` schema, then merges genuine duplicates (same asset+port and matching CVE/CWE/title similarity) while **keeping all evidence and source tools** on the surviving record — nothing is hidden, only folded. Low-confidence single-source generic findings are tagged `false_positive_candidate`, never silently dropped. |
| Risk prioritization | `vapt_agent/risk.py` | Deterministic, fully transparent formula combining CVSS, exploitability, exposure class, asset criticality and confidence (see `risk_breakdown` on every finding). CVSS is **never fabricated**: a missing score is estimated from the tool's own severity band and explicitly flagged `cvss_estimated`. |
| Human-in-the-loop | `vapt_agent/orchestrator.py` (`request_approval`/`decide_approval`/`execute_approval`) | No active validation (Metasploit `check` against an analyst-named module) can run without a recorded approval. Denials, approvals, and outcomes are all written to the audit log and shown in the final report. |
| Reporting | `vapt_agent/report.py` | Generates the client-ready PDF with every required section: executive summary, methodology/RoE/tool summary, severity distribution, detailed findings with evidence, impact & remediation, limitations/assumptions, and the integration transparency matrix. |
| LLM enrichment (optional) | `vapt_agent/llm.py` | If `ANTHROPIC_API_KEY` is set, Claude is used strictly to *phrase* rationale for steps that the rules engine already decided on, and to *summarize* (never invent) the findings already produced. Without a key, the system runs in a fully deterministic "rules-engine" mode — nothing in the pipeline hard-depends on the LLM. |
| API | `vapt_agent/api.py` | FastAPI surface: create assessment, approve/run plan steps, import tool outputs, analyse, request/decide/execute approvals, download the PDF, inspect the audit log and integration matrix. |
| UI | `vapt_agent/static/index.html` | Minimal single-page UI exercising the whole workflow end to end: request → plan approval → import/scan → correlate → review findings → approve/deny active validation → download report. |

## 3. State & memory

State lives on the `Assessment` object (in-process for the demo; trivially swappable for a DB-backed
store since it is a single Pydantic model). Every tool run's raw output is written to
`data/<assessment-id>/raw/` with its SHA-256 recorded on the `ToolRun`, so every finding's evidence is
traceable back to an unmodified source artifact. The audit log (`data/audit.log`) is a separate,
append-only, hash-chained file — tampering with any entry breaks the chain, which `GET /audit` verifies.

## 4. Security boundaries

- All scope checks happen in one module (`scope.py`) and are invoked from the orchestrator before any
  scan, before any finding is accepted into the assessment, and before any validation executes.
- Public IP addresses are rejected unless the operator explicitly sets `allow_public=true` on the scope
  (for organizer-hosted lab targets that happen to sit on a public range); this is itself audited.
- Metasploit is **never** invoked without a `state=="approved"` `Approval` record naming a specific
  module; the orchestrator refuses execution otherwise (`ScopeError`), and the module name is validated
  against a `module/path` shape so it cannot be used to smuggle shell arguments.
- Nmap NSE scripts are restricted to an allow-list of non-intrusive scripts per preset; there is no
  "run arbitrary script" path exposed to the planner or the LLM.
- The LLM layer cannot add a plan step, pick a tool, or create/alter a finding — it only rewrites
  rationale text and summarizes finding counts that already exist in the `Assessment` object.

## 5. Running it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python demo.py                 # headless: fixtures -> report, no live scanning
.venv/bin/uvicorn vapt_agent.api:app --reload   # then open http://127.0.0.1:8000/ui/
.venv/bin/python -m pytest -q             # 34 tests: scope, adapters, correlation, risk, e2e, live scans
```
