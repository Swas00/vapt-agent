# PS-1 Requirements Checklist — "AI Agent for Automated Penetration Testing"

This is a line-by-line pass over the problem statement, with the current build's status against
each item. Status legend: ✅ Done · 🟡 Partial · ⬜ To do.

---

## 1. Background / 2. Problem Statement

The agent must behave like a research assistant for pentesting: select tools, interpret results,
decide what's next, correlate evidence across tools, prioritize risk, and **explain its reasoning** —
not run a fixed script.

| Capability required | Status | Where |
|---|---|---|
| Select tools based on assessment requirements | ✅ | `planner.py` candidate generation (service- and finding-driven) |
| Interpret scan results, identify vulnerabilities | ✅ | adapter `parse()` methods |
| Decide what to investigate next | ✅ | `plan_from_services()` reacts to discovered services (web→nikto/zap, SMB→safe checks, TLS→cipher checks, DB ports→vulners fingerprinting); `plan_from_findings()` reacts to a correlated **finding's severity/confidence**, independent of services |
| Correlate evidence from multiple tools | ✅ | `correlate.py` |
| Prioritize identified risks | ✅ | `risk.py` |
| Explain decisions/reasoning | ✅ | Every `PlanStep.rationale` is a real sentence tied to `depends_on_evidence`/`trigger_finding_id`. When 2+ candidates compete, an optional bounded LLM pass (`reasoning.py`) actually **ranks, keeps, or defers** candidates with a stated reason (never just rephrases a pre-decided choice); deferred candidates stay on the plan as `status="skipped"` with the reason recorded, not silently dropped. See `docs/ARCHITECTURE.md` §2a. |

---

## 3. Security Boundary

- All live testing confined to organizer-provided/authorized sandbox — ✅ enforced in `scope.py`
  (`lab_attestation`, target/exclusion matching, public-IP opt-in).
- Active exploitation requires explicit human approval before execution — ✅ `orchestrator.py`
  (`request_approval` → `decide_approval` → `execute_approval`), Metasploit adapter refuses to run
  without `state == "approved"`.

## 4. End-to-End Workflow

`Analyst Request → Agent Planning → Approved Scan Orchestration → Result Ingestion → AI Analysis →
Risk Prioritization → Human Review → Unified VAPT Report`

| Step | Status | Where |
|---|---|---|
| Accept natural-language request + target/scope | ✅ | `api.py: POST /assessments`, UI request box |
| Generate plan with tool selection + rationale | ✅ | `planner.build_initial_plan` |
| Execute approved scans | ✅ | `orchestrator.approve_step` / `run_step` |
| Collect/process tool outputs | ✅ | `orchestrator._ingest` |
| Correlate findings, evidence-based analysis | ✅ | `correlate.py` |
| Risk prioritization | ✅ | `risk.py` |
| Human review + approved validation | ✅ | approval workflow |
| Professional reporting | ✅ | `report.py` |
| Display progress, tool status, decisions, failures | ✅ | `Assessment.events`, UI activity log |
| Explain why the next scan is necessary | ✅ | `PlanStep.rationale` |
| Avoid unnecessary/repeated actions | ✅ | `expand_from_services` dedupes against `existing` steps |
| Distinguish observed evidence vs. AI inference | ✅ | `Finding.evidence` (tool-sourced) vs `Finding.inference` (always prefixed `[inference]`) |

## 5. Tool Integration Scope (7 required tools)

See [`INTEGRATIONS.md`](INTEGRATIONS.md) for the full, judge-facing matrix. Summary:

| Tool | Declared status | Verified how |
|---|---|---|
| Nmap | Live | ✅ Real subprocess, real scan against localhost |
| Nessus | Import-only (licensed product) | ✅ Real `.nessus` parser, tested |
| OpenVAS/Greenbone | Import-only (planned live via GMP) | ✅ Real XML parser, tested |
| Nikto | Live | ✅ Real subprocess, real scan against localhost |
| OWASP ZAP | Live (REST API) | 🟡 Real HTTP control-flow code verified against a local stub of ZAP's own API contract — real daemon not installed (Gatekeeper-disabled cask) |
| Burp Suite | Import-only (Pro REST API is licensed) | ✅ Real issue-XML parser, tested |
| Metasploit | Live, human-approved only | 🟡 Real subprocess/approval/interpretation path verified against a locally-authored stand-in script — real framework not installed (Gatekeeper + Rosetta 2 + system `.pkg`, deliberately not done) |

Integration-transparency requirement ("disclose live vs import-only, don't misrepresent licensing") —
✅ done: `adapters.integration_matrix()` is computed from code, surfaced via `GET /integration-matrix`
and printed in PDF report section 7.

⬜ **To do when a real ZAP/Metasploit install becomes available** (e.g. on a Linux CI box or judge's
machine without the Gatekeeper restriction): point `ZAP_URL`/`PATH` at the real binaries — no code
changes needed, same adapters.

## 6. Functional Requirements (5.1–5.8)

| # | Requirement | Status | Notes |
|---|---|---|---|
| 5.1 | Scope enforcement: register targets/exclusions/permissions/boundaries, reject out-of-scope actions | ✅ | `scope.py`, called before every scan/finding/validation |
| 5.2 | Adaptive planning: select tools from discovered hosts/services/tech, explain rationale | ✅ | Web/SMB/FTP/TLS/DB-port/DNS/SNMP triggers (`_candidates_from_services`) plus finding-severity triggers (`_candidates_from_findings`) with topically-matched corroboration (an infra CVE gets `nmap vulners`; a web finding gets a second web tool). |
| 5.3 | Scan orchestration: execute, monitor, handle timeouts/errors, record status | ✅ | Timeouts/errors/status all recorded on `ToolRun`; `POST .../plan/{step}/run` dispatches via FastAPI `BackgroundTasks` (not synchronous/blocking) — the UI polls the resulting `ToolRun` until it leaves `running`, and a live scan can be cancelled mid-flight (A2: `orchestrator.cancel_run`, real subprocess termination). |
| 5.4 | Normalization & correlation: common model, merge true duplicates without hiding assets/evidence | ✅ | `correlate.py` |
| 5.5 | Evidence preserved: source tool, asset, timestamps, raw refs, evidence, confidence, confirmed/suspected | ✅ | `models.Finding` / `models.Evidence` |
| 5.6 | Risk prioritization: severity/CVSS, exposure, exploitability, asset impact, confidence; no fabricated CVEs/scores | ✅ | `risk.py`; `cvss_estimated` flag whenever a score isn't tool-reported |
| 5.7 | Human-in-the-loop: explicit approval before active validation, approval+outcome recorded | ✅ | approval workflow + audit log |
| 5.8 | Reporting: client-ready PDF, executive + technical views, remediation, limitations | ✅ | `report.py` |

## 7. Minimum Prototype vs. Advanced/Bonus

**Mandatory (all ✅ done, and exceeded):**
- Conversational request, scope validation, auditable plan.
- ≥3 tool integrations incl. network + web — we have **6** wired (nmap/nikto live, zap code-verified,
  nessus/openvas/burp import) + metasploit gated.
- Common schema, evidence links, dup handling, risk ranking.
- Downloadable PDF + analyst approval gate.

**Advanced/Bonus — current state, biggest opportunities for extra points:**

| Bonus item | Status | Gap |
|---|---|---|
| Multi-step adaptive replanning with state/memory | ✅ | State is durable, not just in-memory: `AssessmentStore`/`BatchStore` (SQLite, `vapt_agent/store.py`) persist every `Assessment` across process restarts (FS-1, verified by `test_assessment_survives_a_simulated_restart`). Planning reacts to both *services* and a *finding's* severity/confidence (`orchestrator.analyse()` calls `planner.plan_from_findings()`) — a critical/high single-source finding automatically proposes a topically-matched confirmatory step. |
| All 7 adapters with reliable live/API support | 🟡 | All 7 exist; 3 are import-only by deliberate licensing/Gatekeeper decision (documented, not a gap to "fix" so much as a scope call) |
| Confidence calibration, false-positive triage | ✅ | Two independent layers: (1) `calibration.py` (FS-6) nudges a new finding's confidence toward what same-signature findings (same CVE, or same title when there's no CVE) have *actually* been validated as across other assessments' human-approved outcomes — conservative by design (minimum sample size, capped shift, always recorded as an `[inference]`, never silently applied). (2) An analyst can explicitly mark any finding a false positive or overturn the system's own inference in either direction (A9: `orchestrator.set_false_positive`, UI "Mark FP"/"Not FP" buttons) — `models.is_false_positive()` is the single predicate every consumer (risk scoring, planner, report counts) reads, so the two layers can never disagree with each other. |
| Remediation tracking | ✅ | `Finding.remediation_status` (`open → in_progress → fixed → retested`), settable via `POST .../findings/{id}/remediation`, shown + editable in the UI (read-only for `viewer` role), attributed to the analyst who changed it. |
| Retesting / change comparison | ✅ | `GET /assessments/{after}/diff/{before}` (`diff.py`) computes new/fixed/persisting findings between two assessments of the same scope; surfaced in the UI's "Compare to a previous assessment" panel. |
| Export formats beyond PDF | ✅ | `POST .../evidence-pack` bundles the PDF report, the assessment's scoped slice of the hash-chained audit log, and every raw tool-output file into a downloadable zip — independently verifiable provenance, not just the report. |
| Team workflows | ✅ | Real multi-user accounts (`accounts.py`): username/password login, server-side sessions, four ordered roles (`viewer < analyst < lead < admin`) with actual separation of duties enforced server-side (requesting active validation needs `analyst`; approving/executing it needs `lead`+). `by` is never client-supplied free text — every attribution field is the verified session's own username. |

## 8. Standards & Reference Frameworks

| Framework | Status |
|---|---|
| NIST SP 800-115 | ✅ named in report methodology text |
| OWASP Top 10 | ✅ `Finding.owasp` populated for ZAP/Burp findings via CWE mapping |
| CVE | ✅ throughout |
| CVSS | ✅ throughout, with `cvss_estimated` honesty flag |
| CWE | ✅ throughout |
| MITRE ATT&CK | ✅ `Finding.mitre_attack`, populated by `frameworks.tag_finding()` for a small, deliberately conservative set of well-established mappings (named vulnerabilities like MS17-010/EternalBlue → T1210; CWE-89/79 → T1190; CWE-287/anonymous access → T1078). No blanket tagging — most findings correctly get none. Every tag is paired with an `[inference]` note saying it's an indicative reference, not an observed adversary action. Shown in both the PDF (§4) and the UI finding cards. |
| NIST CSF 2.0 | ✅ `frameworks.CSF_ALIGNMENT_NOTE`, a fixed paragraph in report §2 mapping the assessment's own *workflow* (not the target environment) to Govern/Identify/Protect/Detect/Respond, explicitly disclaimed as process description, not a compliance claim. |

Framework use doesn't establish compliance (the PS says so explicitly, and the report repeats that
disclaimer verbatim) — this closes the gap as demonstrable rigor, not a checkbox. See `vapt_agent/
frameworks.py` and `tests/test_frameworks.py` (11 tests, including that unrelated/generic findings
get no tag).

## 9. Required Deliverables (9.1–9.6)

| Deliverable | Status | Gap |
|---|---|---|
| 9.1 Working agent demonstrated against an organizer-authorized lab target | 🟡 | Demonstrated against our own fixtures + localhost; ⬜ **re-run once organizers hand out the actual lab target** |
| 9.2 Architecture overview (models, orchestration, adapters, data flow, state/memory, security boundaries) | ✅ | `docs/ARCHITECTURE.md` |
| 9.3 Sample AI-generated, evidence-backed VAPT report (PDF) | ✅ | Committed and tracked at `docs/sample_report.pdf`; `demo.py` regenerates the live equivalent at `data/sample_report.pdf` (gitignored, since it's a build artifact). |
| 9.4 Source repository: setup, dependencies, licensing, execution instructions | ✅ | `README.md`, `requirements.txt`, pushed to [github.com/Swas00/vapt-agent](https://github.com/Swas00/vapt-agent) |
| 9.5 Human-approval demonstration + decision/audit trace | ✅ | approval workflow + hash-chained `audit.py`; sequenced walkthrough script ready at `docs/DEMO_SCRIPT.md`; ⬜ **record the actual clip** (a presentation task, not code) |
| 9.6 Integration status matrix: limitations, assumptions, unsupported scenarios | ✅ | `docs/INTEGRATIONS.md` |

## 10. Judges' Live Demonstration Checklist (11 §)

| # | Judge will check | Status | Notes |
|---|---|---|---|
| 1 | Authorized target + conversational request, scope validation shown | ✅ | UI: targets/exclusions/attestation fields |
| 2 | Agent generates plan with tool selections + reasoning | ✅ | plan panel shows rationale per step |
| 3 | Execute/import multi-tool assessments with genuine status | ✅ | run/import buttons, real `ToolRun.status` |
| 4 | Normalization, correlation, dup/false-positive handling, uncertainty | ✅ | Finding cards show a "⇄ N tools merged" badge when `merged_from` is non-empty, and a false-positive badge distinguishing the system's own inference ("possible false positive") from an analyst's explicit, overriding verdict ("false positive (confirmed)", with Mark FP / Not FP controls). |
| 5 | Severity/risk prioritization + explicit approval checkpoint | ✅ | priority badges + approve/deny buttons |
| 6 | Download report, trace a finding back to source evidence | ✅ | evidence snippet + raw_ref + a truncated SHA-256 of the raw artifact file shown per evidence item in the PDF, for a verifiable chain-of-custody story |
| 7 | Safe failure handling + honest unsupported-integration disclosure | ✅ | `ToolRun.status` failure modes recorded + shown in limitations; integration matrix is honest |

✅ **Rehearsed against the live deployment**: an unattested/public-IP assessment create is rejected
with a specific `400` (not a generic failure), and a malformed/wrong-extension tool import fails
cleanly with a specific `400` rather than a raw exception. See `docs/DEMO_SCRIPT.md` §2/§5 for the
exact sequence to reproduce live on camera.

## 11. Judging Criteria (100 pts) — where to spend remaining effort

| Criterion | Pts | Current strength | Priority to improve |
|---|---|---|---|
| AI Reasoning & Decisions | **20** | ✅ candidate generation reacts to both services (incl. DNS/SNMP) and finding severity; optional bounded LLM arbitration genuinely keeps/defers/explains among competing candidates (never just rephrasing), with a closed-id-set safety property tested against adversarial input | low — further upside only in richer candidate types (e.g. remediation-aware replanning) |
| End-to-End Coverage | 15 | ✅ strong | low |
| Technical Accuracy | 15 | ✅ strong | low |
| Correlation & False Positives | 15 | ✅ merge keeps all evidence/tools; false-positive signal now has two independent layers — historical-outcome calibration (`calibration.py`) and explicit analyst override (A9) that can never disagree with each other | low |
| Risk Prioritization | 10 | ✅ strong, transparent formula | low |
| Safety & Scope Control | 10 | ✅ strong | low |
| Report Quality | 10 | ✅ per-finding business + technical impact statements grounded in asset criticality/exposure class/CVSS vector, an at-a-glance stats table, an "assets actually tested" table distinct from scope, MITRE/CSF framework references, and evidence SHA-256 traceability | low |
| Efficiency & Robustness | 5 | ✅ decent | low |

## 12. Near-Perfect Solution Characteristics (§12) — self-check

High lifecycle coverage ✅ · evidence-based adaptive reasoning ✅ · low false-positive rate 🟡 ·
strong cross-tool correlation ✅ · defensible risk prioritization ✅ · complete evidence traceability ✅ ·
strict scope enforcement ✅ · mandatory human approval ✅ · transparent uncertainty ✅ ·
efficient execution ✅ · graceful failure recovery ✅ · professional/technically accurate report 🟡.

## 13. Safety, Ethics, Assessment Integrity (§13)

All satisfied by construction: no third-party/public targets have been tested (only our own fixtures
and `127.0.0.1`), no scope evasion path exists, no uncontrolled exploitation (Metasploit gated + stand-in
only), no fabricated scanner output (every finding traces to a real parsed file or a flagged `[inference]`
line), lab boundaries/rate limits respected (`scope.py`, `--max-rate`), audit trail is hash-chained and
attributable (`audit.py`).

---

## Remaining TODO list

Every item that was code work on this list has shipped: deeper AI reasoning (bounded LLM
arbitration), MITRE ATT&CK/NIST CSF references, grounded per-finding impact statements, a tracked
sample report (`docs/sample_report.pdf`), finding-driven replanning, finding-card dedup/FP
visualization, remediation tracking, retest/diff, exports beyond PDF, real multi-user
roles/accounts, DNS/SNMP planning triggers, and (added after this checklist was first written)
live scan cancellation (A2), explicit analyst false-positive override (A9), per-tool upload
extension validation (B3), a full negative-path API test suite (F2), and a real keyboard-nav/
screen-reader accessibility audit (C1/F5) — see `docs/HACKATHON_ROADMAP.md` for the full ledger.

What's left is not code, and this document shouldn't claim otherwise:
1. **9.1**: re-run `demo.py`/`live_demo.py` against the organizer's actual lab target once issued —
   genuinely blocked on an address this project has no way to obtain; see `docs/HACKATHON_ROADMAP.md`
   item A4 for the full disposition.
2. **9.5 / judges' checklist item 7**: record the actual demo clip — `docs/DEMO_SCRIPT.md` has the
   full sequenced walkthrough, including the two rehearsed-live failure moments, ready to follow.
