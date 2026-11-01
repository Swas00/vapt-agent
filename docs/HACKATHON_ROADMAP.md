# PS-1 Deep Re-Analysis & Exhaustive Implementation Roadmap
**AI Agent for Automated Penetration Testing — DataOps Innovation Hackathon**

This supersedes `REQUIREMENTS_CHECKLIST.md` in depth (that file stays as a lighter running log).
Every claim below was checked against the actual code in this session — grep/read on the real
files, not the docs about them — per the instruction not to assume a feature exists because it's
documented. Where I say "confirmed absent," I ran a command that proves it.

---

## 0. Executive Assessment

**How well does the current solution address PS-1?** Strong on the parts PS-1 weighs most
heavily, genuinely thin on two structural things judges will notice if they poke at the live app
rather than just the PDF.

- **AI Reasoning & Decisions (20 pts, the single biggest line item)** — well covered. Planning is
  genuinely evidence-driven (service- *and* finding-severity triggered, not a fixed script), the
  optional LLM arbitration layer has a real, tested closed-set safety property, and every decision
  (including *not* running something) is visible with a reason. This is the system's strongest
  area and it should be the centerpiece of the live demo.
- **Safety & Scope Control (10 pts)** — strong on the parts that were built (scope.py, the
  hash-chained audit log, the Metasploit approval gate) but has a real hole the PS's own language
  ("every action is attributable") exposes: **the API has no authentication at all**, so the `by=`
  field on every approval/decision is an unverified string the caller supplies, not an identity.
  Section 2 and the Critical checklist below cover this.
- **End-to-End Coverage / Correlation / Risk / Report Quality** — all solidly built and tested.
- **Efficiency & Robustness (5 pts)** — the weakest-tested of the eight criteria in practice: scan
  execution is fully synchronous (confirmed below), so "monitor running jobs" (PS §5.3) isn't
  really demonstrable yet — a long scan just makes the browser's fetch() hang.
- **Testing** — 88 passing tests, but **zero of them exercise the actual HTTP API** (confirmed
  below: no `TestClient` anywhere in the test suite). Everything is tested through `orchestrator.py`
  directly, which is real and valuable, but it means the FastAPI routing/serialization/error-path
  layer that the live demo actually runs through has never been automatically tested.

None of this is a rebuild. It's targeted hardening on top of an already-solid core.

---

## 1. PS-1 Requirement Breakdown (explicit + implicit)

### 1.1 Explicit requirements, decomposed

| PS section | Requirement | Decomposed into |
|---|---|---|
| §2 | Conversational agent, recon→report | (a) NL request intake, (b) scope capture, (c) tool selection w/ rationale, (d) result interpretation, (e) next-step decisions, (f) cross-tool correlation, (g) risk prioritization, (h) explainability |
| §3 Security Boundary | Lab-only, human-approved active validation | (a) target registration + exclusions, (b) reject out-of-scope actions, (c) no autonomous exploitation, (d) explicit approval gate, (e) approval outcome recorded |
| §4 Workflow | 8-stage pipeline + 4 display requirements | request→plan→orchestrate→ingest→analyse→prioritize→review→report, plus: progress/status display, "why next" explanations, no repeated actions, evidence-vs-inference labeling |
| §4 Tool scope | 7 named tools | Nmap, Nessus, OpenVAS, Nikto, ZAP, Burp, Metasploit — each needs a *disclosed* live/import/planned/unsupported status |
| §5.1 | Scope enforcement | register targets/exclusions/perms/boundaries; reject out-of-scope |
| §5.2 | Adaptive planning | tool selection from discovered hosts/services/tech; explain rationale |
| §5.3 | Scan orchestration | execute, **monitor running jobs**, handle timeouts/errors, record execution status |
| §5.4 | Normalization & correlation | common schema; merge true dups without hiding assets/evidence |
| §5.5 | Evidence preservation | source tool, asset, timestamps, raw refs, evidence, confidence, confirmed/suspected |
| §5.6 | Risk prioritization | severity/CVSS, exposure, exploitability, asset impact, confidence; **no fabricated CVEs/scores** |
| §5.7 | Human-in-the-loop | explicit approval before active validation; approval+outcome recorded |
| §5.8 | Reporting | client-ready PDF, exec+technical views, remediation, limitations |
| §7.1–7.6 | 6 mandatory report sections | exec summary; methodology/RoE/assets/tools; severity distribution; detailed findings (id/asset/desc/sev/CVSS/CVE-CWE/evidence/confidence/validation); impact+remediation+refs; limitations/assumptions/failures/approvals/timestamps |
| §8 | Standards | NIST SP 800-115, OWASP Top 10, CVE, CVSS, CWE, MITRE ATT&CK, NIST CSF 2.0 — "does not, by itself, establish compliance" |
| §9.1–9.6 | 6 deliverables | working prototype vs. **organizer-authorized lab target**; architecture overview; sample PDF report; source repo w/ setup docs; approval demo + audit trace; integration matrix |
| §10 | 7-point live demo checklist | scope validation demo; plan+rationale demo; multi-tool execution w/ real status; correlation/dedup/FP/uncertainty demo; risk + approval checkpoint demo; report traceability demo; failure handling + honest integration disclosure |
| §11 | 100-pt judging | 15/20/15/15/10/10/10/5 split across the 8 criteria above |
| §13 | Ethics | no third-party testing, no autonomous exploitation, no fabricated output, secure data storage, **every action attributable** |

### 1.2 Implicit requirements judges will expect even though the PS doesn't spell them out

1. **The live demo must actually run** — a slide describing architecture isn't the same as clicking
   "Approve & run" and watching a real tool execute. Judges' checklist item 3 says "genuine tool
   execution status," which means they *will* watch the network tab or the UI update live.
2. **The tool can't be trivially broken by normal use** — a title with an apostrophe, a file that's
   too big, a double-click on a button — judges testing edge cases is normal, not adversarial.
3. **The "human-in-the-loop" story has to survive the question "who approved this?"** — an
   unauthenticated `by=` string is the kind of thing a sharp judge asks about directly.
4. **Honesty about limitations scores better than silence** — the PS says this explicitly in §4
   ("clearly distinguish...") and §13; a demo that proactively shows a scope rejection or a failed
   scan is *stronger*, not weaker, than one that only shows happy paths.
5. **"Reconnaissance to report" should feel like one continuous session**, not six disconnected
   screenshots — the live demo needs a rehearsed, uninterrupted run.

---

## 2. Complete Solution Gap Analysis

Status legend: ✅ Done & verified this session · 🟡 Partial · ⬜ Missing · 🔴 Verified absent (checked, not assumed)

### 2.1 Already implemented (verified, not assumed)

| Area | Evidence |
|---|---|
| Scope enforcement, exclusions, public-IP opt-in | `vapt_agent/scope.py`, 10 passing tests |
| Hash-chained, append-only audit log | `vapt_agent/audit.py`, `GET /audit` verifies the chain |
| Service- and finding-driven adaptive planning | `planner.py` — candidates generated from both; 9 tests |
| Bounded LLM arbitration w/ prompt-injection defense | `reasoning.py` — closed candidate-id set; adversarial test passing |
| 6-tool real parsing (XXE-safe via `defusedxml`, verified: no stdlib `xml.etree` anywhere) | `adapters/*.py` |
| Live Nmap + Nikto (real subprocess, tested against localhost) | `adapters/nmap.py`, `adapters/web.py` |
| Cross-tool correlation/dedup keeping all evidence | `correlate.py`, 6 tests |
| Transparent, reproducible risk formula + CVSS-vector parsing | `risk.py`, 12 tests |
| Metasploit gated behind a recorded approval; module-name injection rejected | `orchestrator.py`, `adapters/infra.py`, 4 tests |
| MITRE ATT&CK (conservative) + NIST CSF 2.0 alignment, both disclaimed | `frameworks.py`, 11 tests |
| PDF report: all 6 mandatory sections, grounded per-finding impact statements, stats table, assets-tested table, evidence SHA-256 | `report.py` |
| Integration transparency matrix (computed, not asserted) | `adapters/integration_matrix()`, surfaced in UI + report + `/integration-matrix` |
| XSS-safe UI rendering (fixed this session; verified via jsdom execution of a crafted payload) | `static/index.html` |

### 2.2 Partially implemented — needs work

| Feature | What's there | What's missing |
|---|---|---|
| Scan orchestration "monitor running jobs" (§5.3) | Status recorded on `ToolRun`/`PlanStep` | 🔴 **Confirmed synchronous**: `def run_step` (not `async def`), blocks on `subprocess.run()` until completion/timeout. The HTTP request itself just hangs — there's no live "running → done" transition the client can observe mid-scan. |
| Confidence calibration / FP triage (§5.6 bonus row) | One heuristic (`single tool + info + low confidence`) | No calibration against outcome history, no cross-rule triage |
| Finding-driven replanning breadth | Web + infra-CVE triggers | No DNS/SNMP/cloud-metadata triggers |
| Remediation tracking | Findings have a static `solution` string | No lifecycle (open → remediating → verified-fixed → retested) |
| Live ZAP / Metasploit | Code-path verified against faithful local stubs | Real daemon/framework not installed in this environment (documented honestly in `INTEGRATIONS.md`, not a code gap) |

### 2.3 Missing entirely (verified absent, not assumed)

| Feature | Verification | Why it matters |
|---|---|---|
| **Any authentication on the API** | `grep -n "CORSMiddleware\|HTTPBasic\|APIKey\|OAuth\|Depends" api.py` → zero hits | Anyone reaching the port can approve active validation, impersonate any `by=` identity in the audit trail, pull reports. Directly weakens §13's "every action is attributable." |
| **API-level rate limiting** | No `slowapi`/limiter/middleware anywhere; not in `requirements.txt` | A buggy or malicious client can hammer `/plan/{id}/run` (triggers real scans) or `/approvals/{id}/execute` (triggers Metasploit) with no throttle |
| **Upload size/type limits** | `dest.write_bytes(await file.read())` — whole file buffered, no size check, no content-type allow-list before parsing | A large/malformed upload can exhaust memory; defusedxml protects against XXE but not against a 2GB file |
| **Async/background scan execution** | `def run_step` synchronous (see 2.2) | No "monitor running jobs" experience; no cancel |
| **Any FastAPI-level test (`TestClient`)** | `grep -rln "TestClient" tests/ vapt_agent/` → zero hits | 88/88 passing tests never once go through HTTP routing, request parsing, or file-upload handling — only `orchestrator.py` directly |
| **Persistence beyond the process lifetime** | `ASSESSMENTS: dict[str, Assessment] = {}` at module scope in `api.py` | Restarting the server during a live demo loses all state. (Raw tool outputs + audit log *do* survive on disk; the in-memory Assessment index does not.) |
| **Export formats besides PDF** | Only `report.generate()` → PDF | No JSON/CSV export for a SIEM/ticketing handoff |
| **Retest / change comparison between two assessments** | No diff logic anywhere | Can't show "this was fixed since last scan" |
| **Pagination/filtering on `GET /assessments`** | Returns the full in-memory list, unbounded | Fine at hackathon scale; a real multi-team deployment would need it |
| **CSP / security headers on the FastAPI responses** | No `SecurityHeadersMiddleware` or manual header-setting found | Defense-in-depth the XSS fix doesn't need to work, but judges doing a security-minded review will look for it given the product's own subject matter |
| **A tracked sample PDF report in the repo** | `data/` is gitignored; `demo.py` only writes there | PS §9.3 deliverable technically unmet as a *repo artifact* (it's trivially producible, just not committed) |

---

## 3. Exhaustive Implementation Checklist

### A. Core Functionalities
- [ ] A1. Async/background execution for `run_step` and `execute_approval`, with a pollable job status endpoint
- [ ] A2. "Cancel a running scan" action (kill the subprocess, mark `ToolRun.status="cancelled"`)
- [ ] A3. `GET /assessments` pagination (`limit`/`offset`) and basic filtering (`state=`)
- [ ] A4. Re-run `demo.py`/`live_demo.py` against the organizer's actual lab target once issued (PS §9.1)
- [ ] A5. JSON/CSV export of findings alongside the PDF (ticketing/SIEM handoff)
- [ ] A6. Retest workflow: re-run the same scope, diff findings against the prior assessment (new/fixed/persisting)
- [ ] A7. Remediation status lifecycle on `Finding` (open/in-progress/fixed/retested), surfaced in report §5
- [ ] A8. Multi-target batch assessments (today one `ScopeModel.targets` list works, but there's no "assessment group" concept for comparing N hosts)
- [ ] A9. Explicit "mark finding as false positive" analyst action (today it's inferred, not analyst-confirmable)
- [ ] A10. Persist `Assessment` objects to disk (even flat JSON per-id) so a server restart during a demo doesn't lose state

### B. Security and Privacy
- [ ] B1. **Minimal actor authentication** — at minimum, a shared bearer token / API key required on all mutating endpoints, with the authenticated identity (not a client-supplied string) written to `by`/`decided_by`
- [ ] B2. Upload size cap (e.g. 25MB) enforced before `file.read()`, with a clear 413 response
- [ ] B3. Upload content-type/extension allow-list per tool (reject a `.xml` labeled import that isn't well-formed XML before handing it to the parser)
- [ ] B4. Rate limiting on scan-triggering and Metasploit-execution endpoints specifically (not just globally)
- [ ] B5. Security response headers (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, a CSP) on the FastAPI app and the static UI
- [ ] B6. `SECURITY.md` documenting the threat model: this app is designed to run against untrusted scan output — state that explicitly, since it's the system's whole selling point
- [ ] B7. Secrets handling audit: confirm `ANTHROPIC_API_KEY` / future tokens are never logged (spot-checked: `llm.py`/`reasoning.py` never print the key; good, but add an explicit test)
- [ ] B8. CSRF consideration *if* B1 adds cookie-based sessions (token-header auth sidesteps this; flag only if session cookies are chosen)
- [ ] B9. Verify the `Metasploit.MODULE_RE` regex (already tested against `rm -rf /; echo pwned`) also rejects path traversal / null bytes in the module string
- [ ] B10. Add a `/healthz` endpoint that does *not* leak environment/version info (useful for judges' own smoke test, safe by default)

### C. User Experience and Accessibility
- [ ] C1. Keyboard navigation audit: confirm every button/pill/details-summary is reachable and operable via Tab/Enter/Space (the motion system already respects `:focus-visible`; untested with an actual screen reader)
- [ ] C2. ARIA live region on `#events` so the activity log announces updates to assistive tech (currently silent DOM mutation)
- [ ] C3. Loading/empty/error states for every panel (today "No steps yet." exists for plan/findings/approvals — verify this is consistent and add a genuine loading spinner for in-flight `api()` calls, since those currently show nothing until they resolve)
- [ ] C4. Inline validation on the request form (targets field format, at least one target required) before "Start assessment" is even clickable, rather than only server-side 400s
- [ ] C5. Toast/inline error display instead of `alert()` (currently `api()` uses `alert(await res.text())` for every failure — functional but jarring and blocks the UI thread)
- [ ] C6. Color-contrast check of the new orange/amber palette against WCAG AA, specifically the `--muted` text on `--panel` background
- [ ] C7. Mobile/tablet layout check for the two-column `main{grid-template-columns:420px 1fr}` (fixed 420px left column will overflow on narrow viewports — confirm a responsive breakpoint exists; currently none does)
- [ ] C8. A "copy assessment ID" / shareable link affordance (today the id is just text)
- [ ] C9. Persist the analyst's last-used scope inputs (targets/exclusions) in `localStorage` for convenience across sessions (pure client-side nicety, no backend change)

### D. Advanced Features and Innovation
- [ ] D1. Live progress streaming (SSE or WebSocket) once A1 lands, so the activity log updates in real time during a running scan — this is the natural companion to the async-execution fix and a strong demo moment
- [ ] D2. A "replay" view: given the audit log, reconstruct and visually step through exactly what the agent decided and why, for judges to inspect post-hoc
- [ ] D3. Confidence-weighted executive summary tone (already partially done via `llm.summarize_assessment`; extend to flag when the summary itself should hedge more given many `suspected`-only findings)
- [ ] D4. Export the integration matrix + audit log as a standalone "evidence pack" zip for judges to inspect offline

### E. Technical Architecture and Scalability
- [ ] E1. Convert `run_step`/`execute_approval` to `BackgroundTasks` (or a small task queue) + a `GET /assessments/{id}/runs/{run_id}` status-poll endpoint
- [ ] E2. Structured application logging (Python `logging` module, not bare prints) with request IDs, separate from the audit log (which is a product feature, not ops tooling)
- [ ] E3. `FastAPI` dependency-injected config object instead of module-level globals (`DATA_DIR`, `audit`, `orch`) — easier to test in isolation
- [ ] E4. Add `TestClient`-based API tests (see Testing section) — this is both an architecture and QA item
- [ ] E5. Document a real deployment story (systemd unit / Docker) even if not executed for the hackathon — strengthens "production-oriented" framing
- [ ] E6. Basic backup story for `data/audit.log` (it's the one thing that can't be regenerated)

### F. Testing and Reliability
- [ ] F1. `tests/test_api.py` using FastAPI `TestClient`: create → import → analyse → approve → execute → report, through real HTTP, not direct orchestrator calls
- [ ] F2. Negative-path API tests: malformed JSON body, missing required field, wrong content-type on upload, oversized upload (once B2 lands)
- [ ] F3. Auth tests once B1 lands: unauthenticated request rejected, wrong token rejected, `by`/`decided_by` reflects the authenticated identity not a client-supplied string
- [ ] F4. Concurrency test: two simultaneous `run_step` calls on the same assessment don't corrupt `a.plan`/`a.runs` (today nothing guards against a race; low risk at hackathon scale, real at production scale)
- [ ] F5. Accessibility test pass (axe-core or manual) once C1–C2 land
- [ ] F6. Load/perf sanity: confirm report generation stays fast with 100+ findings (currently only tested with the ~14-finding fixture set)
- [ ] F7. Boundary tests for `risk.score()`: confidence exactly 0 and 1, CVSS exactly 0 and 10, an asset with no `asset_criticality` entry at all

---

## 4. Security Hardening Checklist (consolidated from B above, ordered by what's actually exploitable today)

1. **[Critical]** Add minimal auth (B1) — today, *any* network-reachable client can trigger Metasploit execution against a finding with zero identity check.
2. **[Critical]** Upload size cap (B2) — today, a single large POST to `/import/{tool}` is read fully into memory with no limit.
3. **[High]** Rate limiting on `/plan/{id}/run` and `/approvals/{id}/execute` (B4).
4. **[High]** Content-type/extension validation before parsing an import (B3) — defusedxml already stops XXE; this stops wasted parse cycles on garbage input and gives a cleaner error.
5. **[Medium]** Security response headers (B5).
6. **[Medium]** `SECURITY.md` threat-model statement (B6) — cheap, and directly answers the "but your tool parses untrusted scanner output" question a judge might ask.
7. **[Low]** `/healthz` without info leakage (B10).
8. **[Low]** Path-traversal/null-byte hardening on the Metasploit module regex, already strong, add explicit tests (B9).

---

## 5. Feature Enhancement & Innovation Roadmap

Ordered by genuine differentiation potential, not novelty for its own sake:

1. **Live job status + streaming activity log (D1/A1/E1 combined)** — turns "the agent is thinking" into something judges can literally watch happen, which is exactly what judging criterion "AI Reasoning & Decisions" rewards *demonstrably*, not just on paper.
2. **Retest/diff workflow (A6)** — directly answers "does this reduce manual coordination effort *over time*," which is the PS's own stated success criterion, not just a one-shot scan.
3. **Audit-trail replay view (D2)** — makes the "attributable through an audit trail" requirement something judges can *see*, not just trust exists.
4. **Remediation lifecycle (A7)** — closes the loop the PS's own "Advanced/Bonus" row explicitly names ("remediation tracking").
5. **Evidence pack export (D4)** — a small, cheap feature that makes the whole system's integrity independently verifiable by someone who wasn't in the room for the demo.

Explicitly **not** recommended: adding more LLM calls for their own sake, a chatbot-style free-form interface layered on top of the structured workflow, or any feature whose primary value is "looks AI-y" rather than closing a named PS requirement or judging-criterion gap.

---

## 6. UI/UX and Accessibility Improvement Checklist

(Cross-referenced to section C above; this is the UI-specific subset.)

- [ ] Fixed-width left column → responsive grid for <900px viewports (C7)
- [ ] Replace `alert()`-based error surfacing with inline/toast UI (C5)
- [ ] Add loading states to every `api()`-backed button (C3)
- [ ] ARIA live region on the activity log (C2)
- [ ] Full keyboard-nav + screen-reader pass (C1)
- [ ] WCAG AA contrast check on the new palette (C6)
- [ ] Inline client-side form validation before submission (C4)

---

## 7. Testing and Quality Assurance Checklist

(Cross-referenced to section F; concrete test cases.)

| # | Test | Type | Currently exists? |
|---|---|---|---|
| T1 | Full create→report flow via `TestClient`, not direct orchestrator calls | API/integration | ⬜ No |
| T2 | Upload >size-cap file → 413 | API, negative | ⬜ No (cap doesn't exist yet) |
| T3 | Upload a `.xml`-named file containing JSON → clean error, not a stack trace | API, negative | ⬜ No |
| T4 | Unauthenticated request → 401 | API, auth | ⬜ No (auth doesn't exist yet) |
| T5 | `by=` reflects authenticated identity, not client-supplied string | Security | ⬜ No |
| T6 | Two concurrent `run_step` calls on one assessment | Concurrency | ⬜ No |
| T7 | `risk.score()` at CVSS=0, CVSS=10, confidence=0, confidence=1 | Boundary | ⬜ No |
| T8 | Finding title containing `<script>`, apostrophes, ampersands → renders as inert text | Security/UI | ✅ Yes (jsdom test this session, not yet a committed automated test) |
| T9 | Report generation with 100+ findings, timing | Performance | ⬜ No |
| T10 | Keyboard-only full workflow completion | Accessibility | ⬜ No |
| T11 | Screen-reader announces activity-log updates | Accessibility | ⬜ No (feature doesn't exist yet) |
| T12 | Metasploit module string with path traversal (`../../etc/passwd`) and null bytes rejected | Security | ⬜ No (apostrophe/injection case is tested; these specific variants aren't) |

**Action item**: T8's jsdom verification should be ported into a committed, repeatable test (e.g.
a small Node test script checked into `tests/frontend/`, or equivalent Python-side check using
`html.parser` to assert the template strings always wrap dynamic fields in `esc()`), so this
doesn't silently regress on the next UI edit.

---

## 8. Prioritized Implementation Sequence

### Tier 1 — Critical

| ID | Task | Description | Why required | Expected outcome | Frontend | Backend | DB | Security | Depends on | Acceptance criteria |
|---|---|---|---|---|---|---|---|---|---|---|
| CR-1 | Minimal API authentication | Require a bearer token (env-configured shared secret, or per-analyst token map) on every mutating endpoint; derive `by`/`decided_by` from the authenticated identity, ignore any client-supplied value | §13 "every action attributable"; currently false — `by=` is free text | Audit trail entries are trustworthy | Add token input to UI, send as header | FastAPI `Depends()` auth guard on all POST routes; `audit.append(actor=...)` uses the verified identity | N/A (in-memory) | Closes the biggest live gap | None | Unauthenticated POST → 401; `by=` in the response always matches the token's mapped identity, never the query string |
| CR-2 | Upload size + type cap | Read `Content-Length` (or stream with a cap) before buffering; reject >25MB with 413; sniff the first bytes against the declared tool's expected format before parsing | Prevents memory-exhaustion DoS on a public-facing demo instance | A malformed/huge upload fails fast and cleanly | Show the 413 message in the import panel | `UploadFile` size check in `api.import_result` | N/A | Closes an unbounded-memory gap | None | 30MB upload → 413, not a hang or crash |
| CR-3 | Async scan execution + status polling | Move `run_step`/`execute_approval` to `BackgroundTasks`; add `GET /assessments/{id}/runs/{run_id}` returning live status; UI polls every 1–2s while a run is `running` | PS §5.3 explicitly requires "monitor running jobs" — today it's un-demonstrable | Judges can watch a scan go pending→running→done live | Poll loop + visible spinner/progress on the running step's card | `BackgroundTasks`, a `run_id`→status lookup, `ToolRun` status transitions already exist, just need to be observable mid-flight | N/A | Low (internal only) | None | Click "Approve & run," UI shows "running" within 2s, updates to "done" without a page reload, request returns immediately rather than hanging |
| CR-4 | Committed sample PDF report | Generate a sample report (already working via `demo.py`) and commit it to a tracked path (`docs/sample_report.pdf`), refreshed whenever report.py changes meaningfully | PS §9.3 deliverable — currently only producible, not present in the repo | Judges can open the PDF directly from the repo without running anything | N/A | N/A | N/A | N/A | None | File exists at a tracked path, opens cleanly, reflects current report.py output |
| CR-5 | API-level test suite (`TestClient`) | Cover the full create→import→analyse→approve→execute→report flow through real HTTP | Zero current coverage of the actual demo-time code path (routing, serialization, file upload, error responses) | Confidence the live demo's actual code path is tested, not just the library underneath it | N/A | N/A | N/A | Surfaces auth/upload bugs before judges do | CR-1, CR-2 (to test the new guards) | `pytest tests/test_api.py` green, covers every route in `api.py` |

### Tier 2 — High Priority

| ID | Task | Description | Why | Outcome | FE | BE | DB | Security | Depends on | Acceptance criteria |
|---|---|---|---|---|---|---|---|---|---|---|
| HP-1 | Rate limiting on scan/execute endpoints | `slowapi` or a hand-rolled token-bucket keyed by auth identity, applied to `/plan/{id}/run` and `/approvals/{id}/execute` | Prevents abuse of the two endpoints that trigger real external processes | A misbehaving client can't hammer live scans | N/A | Middleware/dependency | N/A | Abuse prevention | CR-1 | >N requests/min from one identity → 429 |
| HP-2 | Security response headers | `nosniff`, `X-Frame-Options`, a basic CSP allowing only same-origin scripts (the inline `<script>` tags need a nonce or `'unsafe-inline'` — document the tradeoff) | Defense-in-depth consistent with the product's own subject matter | Headers present on every response | N/A | Middleware | N/A | Direct | None | `curl -I` shows the headers |
| HP-3 | Replace `alert()` with inline error UI | Toast/banner component, non-blocking | UX polish + accessibility (native `alert()` is a poor screen-reader experience) | Errors visible without blocking the thread | New error-banner component | N/A | N/A | N/A | None | A failed API call shows an inline message, page remains interactive |
| HP-4 | Loading states on every async button | Disable + spinner while an `api()` call is in flight | PS/"meaningful feedback for every user action" (implicit UX expectation) | No more "did my click register?" moments | CSS spinner + disabled state | N/A | N/A | N/A | None | Click a button, it visibly disables until the response lands |
| HP-5 | Responsive layout for the app shell | Replace the fixed `420px 1fr` grid with a responsive breakpoint (stacked columns under ~900px) | Judges may open the live demo on a laptop at an unusual resolution, or a tablet at a booth | No horizontal scroll/overflow at common widths | CSS media query | N/A | N/A | N/A | None | 768px viewport renders without horizontal scroll |
| HP-6 | Retest/diff workflow | New vs. fixed vs. persisting findings between two assessments of the same scope | Directly demonstrates the PS's own "reduces manual coordination effort" success criterion over time, not just once | A second scan visibly shows what changed | Diff view in UI | `diff_assessments(a, b)` in a new module | N/A (compares two in-memory Assessment objects) | None new | None | Two assessments of the same target produce a correct new/fixed/persisting split |
| HP-7 | Remediation status lifecycle | Add `remediation_status` to `Finding` (open/in-progress/fixed/retested), analyst-settable, shown in report §5 | PS's own named "Advanced/Bonus" item | Report can show remediation progress, not just a static solution string | UI control per finding | New field + endpoint to set it | N/A | None new | None | Setting a finding's status persists and appears in the next-generated report |

### Tier 3 — Competitive Advantage

| ID | Task | Why it differentiates |
|---|---|---|
| CA-1 | Live SSE/WebSocket activity-log streaming (builds on CR-3) | Watching the agent reason in real time, not polling, is the single most demo-impressive moment available given what's already built |
| CA-2 | Audit-trail replay view | Makes "attributable" a *feature*, not just a backend property — few competing teams will have an inspectable decision trace |
| CA-3 | Evidence-pack export (zip of audit log + raw tool outputs + report) | Independently verifiable without re-running the demo; strong for a judge reviewing after the fact |
| CA-4 | Confidence-aware executive summary hedging | Small, cheap, and directly shows "transparent uncertainty" (a named "near-perfect solution" characteristic in the PS) in the one section non-technical judges actually read closely |

### Tier 4 — Polish

| ID | Task |
|---|---|
| PL-1 | ARIA live region on activity log |
| PL-2 | WCAG AA contrast pass on the orange/amber palette |
| PL-3 | `localStorage` persistence of last-used scope inputs |
| PL-4 | "Copy assessment ID" affordance |
| PL-5 | Inline client-side form validation before submit |
| PL-6 | `/healthz` endpoint |
| PL-7 | Structured `logging` instead of bare prints |
| PL-8 | Committed, automated regression test for the XSS-escaping fix (port the jsdom check into the test suite) |

### Tier 5 — Future Scope (explicitly not for this hackathon submission)

| ID | Task |
|---|---|
| FS-1 | Persistent storage (SQLite/Postgres) for `Assessment` objects across restarts |
| FS-2 | Multi-user RBAC (analyst / lead / viewer roles) beyond simple shared-token auth |
| FS-3 | JSON/CSV export alongside PDF |
| FS-4 | Multi-target batch assessment grouping |
| FS-5 | Deployment story (Docker/systemd) with a backup plan for `audit.log` |
| FS-6 | Confidence calibration against historical validation outcomes |
| FS-7 | DNS/SNMP/cloud-metadata finding-driven planning triggers |

---

## 9. Features That Give a Genuine Competitive Advantage

Separating what *every* competing team building against this PS will plausibly have, from what
distinguishes this one:

**Likely common across teams** (don't over-invest marginal effort here beyond "solid"):
correlation/dedup, a CVSS-based risk score, a PDF report, basic scope checking.

**Actually differentiating, specific to this build:**
1. The **closed-candidate-id LLM arbitration** with a *tested* prompt-injection defense — most
   teams integrating an LLM into a security tool will not have thought about "what if the scan
   output itself tries to instruct the model," and even fewer will have a passing adversarial test
   proving it's closed.
2. **Finding-driven (not just service-driven) replanning** that reacts to severity *and* picks a
   topically-correct corroboration action (an infra CVE gets an nmap re-check; a web finding gets a
   second web tool — never a mismatched suggestion).
3. **Hash-chained audit log with a verify endpoint** — genuinely tamper-evident, not just "we log
   things."
4. **Honest integration-transparency matrix computed from code**, not asserted in a slide — most
   teams will overclaim "we integrate with Metasploit" without the judges ever seeing the actual
   gating logic that makes it safe.
5. **Per-finding business+technical impact grounded in CVSS-vector C/I/A components** — most
   reports in this space will either skip business impact or hand-wave it; this one derives it from
   data the tool actually has.
6. Once CR-3/CA-1 land: **live, watchable scan execution** — turns the single weakest-demonstrated
   PS requirement today into the most impressive live moment.

---

## 10. Definition of "Hackathon-Ready, Complete"

The solution is ready when, without any script or hidden setup:

1. A judge can type a natural-language request + the organizer's actual lab target into the UI,
   watch a plan get proposed with real rationale, approve steps one at a time, and see at least one
   step's status visibly change from proposed → running → done **in real time** (CR-3/CA-1).
2. At least one critical/high finding exists that was corroborated across two tools, and the judge
   can trace it back to both raw evidence files via the SHA-256 shown in the report.
3. The judge can trigger a scope violation (e.g. type an out-of-scope IP) and see it rejected with a
   clear reason — proving §13 isn't just a design doc claim.
4. A human-approval gate is demonstrated for active validation, including a **denial**, both visible
   in the audit log.
5. The judge can download the PDF report and find every one of the 6 mandatory PS §7 sections,
   including the integration transparency matrix and the limitations section.
6. If asked "who approved that?", the answer is a real authenticated identity, not a string anyone
   could have typed (CR-1).
7. The repository contains a committed sample report (CR-4), a green `pytest` run that includes
   actual HTTP-level API tests (CR-5), and this roadmap documenting what's shipped vs. what's
   deliberately deferred — because honestly scoping the submission is itself a PS-rewarded trait.

Everything in Tier 5 (Future Scope) is explicitly *not* part of this definition — claiming it would
be the overclaiming the PS and the hackathon rules both explicitly warn against.
