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
| 5.2 | Adaptive planning: select tools from discovered hosts/services/tech, explain rationale | ✅ | Web/SMB/FTP/TLS/DB-port triggers (`_candidates_from_services`) plus finding-severity triggers (`_candidates_from_findings`) with topically-matched corroboration (an infra CVE gets `nmap vulners`; a web finding gets a second web tool). ⬜ DNS/SNMP triggers still not added — low-value, left for later. |
| 5.3 | Scan orchestration: execute, monitor, handle timeouts/errors, record status | 🟡 | Timeouts/errors/status all recorded on `ToolRun`; ⬜ execution is synchronous/blocking, no background job polling for long-running scans |
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
| Multi-step adaptive replanning with state/memory | ✅ | State lives per-`Assessment` (in-memory, trivially persistable); planning now reacts to both *services* and a *finding's* severity/confidence (`orchestrator.analyse()` calls `planner.plan_from_findings()`) — a critical/high single-source finding automatically proposes a topically-matched confirmatory step. ⬜ still in-memory only, not durable across process restarts. |
| All 7 adapters with reliable live/API support | 🟡 | All 7 exist; 3 are import-only by deliberate licensing/Gatekeeper decision (documented, not a gap to "fix" so much as a scope call) |
| Confidence calibration, false-positive triage | 🟡 | Simple heuristic only (`single tool + info + low confidence → false_positive_candidate`); ⬜ no calibration against historical accuracy, no cross-check rules beyond that one |
| Remediation tracking | ⬜ | Not implemented — no "remediated/open/retested" lifecycle field on findings |
| Retesting / change comparison | ⬜ | Not implemented — no diff between two assessments of the same target |
| Export formats beyond PDF | ⬜ | Only PDF; no JSON/CSV/HTML export |
| Team workflows | ⬜ | `by` is a free-text string, not real multi-user auth/roles |

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
| 9.3 Sample AI-generated, evidence-backed VAPT report (PDF) | 🟡 | `demo.py` generates one at `data/sample_report.pdf`, but `data/` is **gitignored** — ⬜ **commit a copy somewhere tracked** (e.g. `docs/sample_report.pdf`) before submission |
| 9.4 Source repository: setup, dependencies, licensing, execution instructions | ✅ | `README.md`, `requirements.txt`, pushed to [github.com/Swas00/vapt-agent](https://github.com/Swas00/vapt-agent) |
| 9.5 Human-approval demonstration + decision/audit trace | ✅ | approval workflow + hash-chained `audit.py`; ⬜ **record an actual demo clip/walkthrough for judges** (this is a presentation task, not code) |
| 9.6 Integration status matrix: limitations, assumptions, unsupported scenarios | ✅ | `docs/INTEGRATIONS.md` |

## 10. Judges' Live Demonstration Checklist (11 §)

| # | Judge will check | Status | Notes |
|---|---|---|---|
| 1 | Authorized target + conversational request, scope validation shown | ✅ | UI: targets/exclusions/attestation fields |
| 2 | Agent generates plan with tool selections + reasoning | ✅ | plan panel shows rationale per step |
| 3 | Execute/import multi-tool assessments with genuine status | ✅ | run/import buttons, real `ToolRun.status` |
| 4 | Normalization, correlation, dup/false-positive handling, uncertainty | 🟡 | works, but UI doesn't strongly *visualize* merged-finding count / false-positive tag — ⬜ polish the finding card to show `merged_from` and highlight `false_positive_candidate` |
| 5 | Severity/risk prioritization + explicit approval checkpoint | ✅ | priority badges + approve/deny buttons |
| 6 | Download report, trace a finding back to source evidence | 🟡 | evidence snippet + raw_ref shown in PDF; ⬜ could also surface the raw file's SHA-256 in the report for a stronger chain-of-custody story |
| 7 | Safe failure handling + honest unsupported-integration disclosure | ✅ | `ToolRun.status` failure modes recorded + shown in limitations; integration matrix is honest |

⬜ **To do before the live demo**: deliberately rehearse one scope-rejection (scan something outside
the registered target) and one tool failure (e.g. a bad target host) so judges see graceful handling
live, not just in theory.

## 11. Judging Criteria (100 pts) — where to spend remaining effort

| Criterion | Pts | Current strength | Priority to improve |
|---|---|---|---|
| AI Reasoning & Decisions | **20** | ✅ candidate generation reacts to both services and finding severity; optional bounded LLM arbitration genuinely keeps/defers/explains among competing candidates (never just rephrasing), with a closed-id-set safety property tested against adversarial input | low — further upside only in richer candidate types (e.g. DNS/SNMP triggers, remediation-aware replanning) |
| End-to-End Coverage | 15 | ✅ strong | low |
| Technical Accuracy | 15 | ✅ strong | low |
| Correlation & False Positives | 15 | 🟡 good, heuristic is simple | medium |
| Risk Prioritization | 10 | ✅ strong, transparent formula | low |
| Safety & Scope Control | 10 | ✅ strong | low |
| Report Quality | 10 | 🟡 good, could add business-impact depth per finding + framework references | medium |
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

## Prioritized TODO list (in order of expected impact)

1. ~~**Deepen AI reasoning**~~ — **done.** `planner.py` now generates candidates from both services
   and finding severity/confidence; `reasoning.py` adds an optional, strictly bounded LLM arbitration
   pass (closed candidate-id set, validated, with a tested prompt-injection defense); deferred
   candidates stay visible on the plan as `status="skipped"` with a recorded reason. See
   `docs/ARCHITECTURE.md` §2a and `tests/test_reasoning.py` / `tests/test_planner.py`.
2. **Commit a tracked sample report** — `data/` is gitignored; add a sample PDF somewhere tracked
   (e.g. `docs/sample_report.pdf`) for deliverable 9.3.
3. ~~**Add MITRE ATT&CK / NIST CSF 2.0 references**~~ — **done**, see §8: `frameworks.py`, wired into
   `orchestrator.analyse()`, shown in both the PDF report and the UI.
4. **Polish report §7.5** — explicit business-impact sentence per critical/high finding, not just a
   remediation line.
5. ~~**Finding-driven (not just service-driven) replanning**~~ — **done**, see item 1.
6. **UI polish** for judging-checklist item 6 (surface evidence file SHA-256 in the PDF). Item 4
   (dedup/false-positive visibility) is now partly addressed by the plan's "alternatives considered"
   panel; findings themselves could still show `merged_from` count more prominently.
7. **Rehearse failure/rejection demo moments** before the live round.
8. Optional/lower priority: remediation tracking, retest/diff, export formats, real multi-user auth,
   DNS/SNMP planning triggers — genuinely "bonus," worth doing only if time remains after 2–4.
