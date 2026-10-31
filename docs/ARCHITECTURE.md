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
| Adaptive planning | `vapt_agent/planner.py` | Candidate-generation + ranking pipeline (§2a below). Discovery is always step one; after each ingestion, service-driven candidates react to what was actually observed, and after correlation, **finding-driven candidates react to a finding's own severity/confidence** — a single-source critical/high finding now triggers a proposal to corroborate it, independent of whether a port happens to be open. |
| Bounded LLM arbitration (optional) | `vapt_agent/reasoning.py` | When candidates compete, an optional Claude call *ranks* them — keep/defer/explain — but only over the closed id set the rules already produced (§2a). This is the "genuine reasoning" layer: it weighs trade-offs and can defer a redundant candidate with a stated reason, not just append everything in discovery order. |
| Tool adapters | `vapt_agent/adapters/*.py` | One adapter per tool, each declaring its own truthful `live_status` (`live` / `import-only` / `planned`). See [`INTEGRATIONS.md`](INTEGRATIONS.md). |
| Orchestration | `vapt_agent/orchestrator.py` | The only place that calls adapters, scope checks, the correlator and the risk engine. Owns plan execution, result ingestion, finding-driven replanning (after `analyse()`), and the human-approval workflow for active validation. |
| Normalization & correlation | `vapt_agent/correlate.py` | Maps all adapters' output onto the common `Finding` schema, then merges genuine duplicates (same asset+port and matching CVE/CWE/title similarity) while **keeping all evidence and source tools** on the surviving record — nothing is hidden, only folded. Low-confidence single-source generic findings are tagged `false_positive_candidate`, never silently dropped. |
| Risk prioritization | `vapt_agent/risk.py` | Deterministic, fully transparent formula combining CVSS, exploitability, exposure class, asset criticality and confidence (see `risk_breakdown` on every finding). CVSS is **never fabricated**: a missing score is estimated from the tool's own severity band and explicitly flagged `cvss_estimated`. |
| Human-in-the-loop | `vapt_agent/orchestrator.py` (`request_approval`/`decide_approval`/`execute_approval`) | No active validation (Metasploit `check` against an analyst-named module) can run without a recorded approval. Denials, approvals, and outcomes are all written to the audit log and shown in the final report. The agent *suggests* when a finding warrants requesting one (`planner.propose_validation_steps`, surfaced as an `Event` after `analyse()`) but never creates an `Approval` itself. |
| Reporting | `vapt_agent/report.py` | Generates the client-ready PDF with every required section: executive summary, methodology/RoE/tool summary, severity distribution, detailed findings with evidence, impact & remediation, limitations/assumptions, and the integration transparency matrix. |
| LLM prose (optional) | `vapt_agent/llm.py` | If `ANTHROPIC_API_KEY` is set, Claude writes the report's executive-summary prose, strictly grounded in the already-finalized finding counts passed to it. Candidate *ranking* is a separate, much more tightly bounded concern — see `reasoning.py`. Without a key, a deterministic template is used; nothing in the pipeline hard-depends on the LLM. |
| API | `vapt_agent/api.py` | FastAPI surface: create assessment, approve/run plan steps, import tool outputs, analyse, request/decide/execute approvals, download the PDF, inspect the audit log and integration matrix. |
| UI | `vapt_agent/static/index.html` | Single-page UI exercising the whole workflow end to end: request → plan approval → import/scan → correlate → review findings → approve/deny active validation → download report. Each plan step shows its `kind` (discovery/service/finding), whether it was `llm-arbitrated`, and a collapsible "alternatives considered" panel listing the other candidates weighed in the same batch and why they were or weren't run. |

### 2a. How a plan step actually gets decided (the "AI reasoning" pipeline)

```
observed evidence (services, or findings after correlation)
        │
        ▼
candidate generation (planner.py, pure rules, deterministic)
   _candidates_from_services()  -- open port -> relevant scanner(s)
   _candidates_from_findings()  -- severe + single-source finding -> a *topically appropriate*
                                    corroboration action (an infra CVE gets an nmap vulners
                                    re-check; a web-layer finding gets a second web tool --
                                    never a mismatched suggestion like "nmap can corroborate
                                    this SQL injection")
        │
        ▼
dedupe against the existing plan (never propose the same tool/target/preset twice)
        │
        ▼
rank_candidates() -- if 2+ candidates compete AND an API key is configured:
   reasoning.arbitrate() -- Claude ranks/defers/explains, but ONLY over the closed set of
   candidate ids already produced above; any id it invents is dropped; any structural failure
   (bad JSON, network error, empty result) falls back to deterministic rule-based ranking,
   recorded in Assessment.llm_notes so the fallback is never silent
        │
        ▼
materialize() -- every candidate becomes a PlanStep: status="proposed" if kept, status="skipped"
   with a recorded skip_reason if deferred. Nothing considered is ever just dropped.
```

Why the candidate id is the actual security boundary, not a style choice: the LLM call in
`reasoning.py` receives candidates as inert JSON data (including any scanner-derived text, which may
be attacker-influenced) and is explicitly told to treat all of it as data, not instructions. But the
real guarantee doesn't rely on the model behaving — even a fully-hijacked response that tries to
smuggle a new tool/target can only emit ids, and `materialize()` physically cannot build a `PlanStep`
from an id that wasn't already in the rules-generated candidate list. `tests/test_reasoning.py`
includes an explicit adversarial test of this (`test_prompt_injection_in_candidate_evidence_cannot_smuggle_a_new_target`).

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
- The LLM layer cannot add a plan step, pick a tool/target/preset outside what the rules engine
  already proposed, or create/alter a finding — `reasoning.arbitrate()` validates every returned id
  against the closed candidate set before any `PlanStep` is built (§2a), and `llm.py` only writes
  report prose grounded in already-finalized finding counts.

## 5. Running it

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python demo.py                 # headless: fixtures -> report, no live scanning
.venv/bin/uvicorn vapt_agent.api:app --reload   # then open http://127.0.0.1:8000/ui/
.venv/bin/python -m pytest -q             # 60 tests: scope, adapters, correlation, risk, planning/
                                           # reasoning (incl. a prompt-injection test), e2e, live scans
```
