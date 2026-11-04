# Demo Walkthrough Script

A sequenced walkthrough for recording the judges-facing demo (PS-1 deliverable 9.5, judges' live
demonstration checklist §10). Each step is tagged with the checklist item it satisfies. Follow it
against the live deployment (https://vapt-agent-oyvp.onrender.com/ui/) or a local run
(`uvicorn vapt_agent.api:app --reload`, then `/ui/`) — both exercise the same code.

Every numbered step below has already been rehearsed against the live deployment and confirmed to
behave exactly as described (see the session notes) — this script isn't a guess at what should
happen, it's a record of what does happen.

## Setup (before recording)

1. Sign in as `admin` (or a dedicated `analyst`-role account created ahead of time via the admin
   panel — recommended, so the recording shows a realistic non-admin analyst workflow rather than
   an all-powerful account).
2. Have `tests/fixtures/nessus_sample.nessus` and one other fixture (e.g.
   `tests/fixtures/nikto_sample.json`) ready to upload from the walkthrough machine.
3. Decide in advance which of the two tool-failure moments below you'll show live — don't
   improvise a new one on camera; both are already proven to fail cleanly.

## 1. Conversational request + scope validation — checklist item 1

- Fill in the "Analyst request" box with a real sentence (not just a target), e.g. *"Assess the lab
  web application and its host for common network and web vulnerabilities before our client demo."*
- Enter the authorized target(s), check the lab-attestation box, click **Start assessment**.
- **Narrate**: this isn't free text accepted at face value — `scope.py` validates it server-side on
  every single scan/finding/validation afterward, not just at creation.

## 2. Scope rejection — rehearsed, judges' checklist §10 footnote

Before approving any plan step, demonstrate a rejection live:

- Open a second browser tab (or use the same session) and attempt to create a *second* assessment
  with a public IP (e.g. `8.8.8.8`) and the attestation box **unchecked**.
- **Expected, confirmed live**: `400 — "lab attestation missing"`.
- Re-try with attestation checked but still a public target and `allow_public` not set.
- **Expected, confirmed live**: `400 — "target 8.8.8.8 is public; set allow_public only for
  organizer-provided lab hosts"`.
- **Narrate**: this is the same `scope.py` enforcement from step 1, not a separate "demo mode"
  check — rejecting out-of-scope targets is intrinsic to every mutating call, including this one.
- Switch back to the first (valid) assessment and continue.

## 3. Plan generation + reasoning — checklist item 2

- Point out the first plan step: `nmap -> <target> (discovery)`, and read its rationale aloud —
  it's a real sentence tied to `depends_on_evidence`, not a canned label.
- Click **Approve & run**. While it's `running`, show the **Cancel scan** button that appears (A2) —
  optionally click it once to demonstrate a live scan can actually be interrupted, then start a
  fresh approved step to let discovery finish for the rest of the walkthrough.

## 4. Multi-tool import + genuine status — checklist item 3

- Import `nessus_sample.nessus` via the "Import a tool result" panel (select `Nessus`, choose the
  file, **Import**). Watch the finding count/plan grow.
- Import a second fixture (`nikto_sample.json` as `Nikto`) to show multiple tools feeding one
  assessment.

## 5. Tool failure — rehearsed, judges' checklist item 7

Pick ONE of these two (both confirmed live):

- **Wrong file content**: re-select `Nessus`, upload a plain-text file saved with a `.nessus`
  extension. **Expected**: `400 — "could not parse this as a nessus import: syntax error..."` — a
  clean, specific error, not a raw exception.
- **Wrong extension entirely**: select `Nessus`, upload a `.json` file. **Expected**:
  `400 — "'nessus' import expects a file extension of ['nessus', 'xml'], got 'json'"` (B3's
  allow-list, checked before the file is ever parsed).
- **Narrate**: nothing silently fails or 500s — every failure mode is recorded as a limitation and
  shown to the analyst, same honesty the integration matrix extends to live-vs-import-only status.

## 6. Correlation, dedup, false positives, uncertainty — checklist item 4

- Click **Correlate & prioritize findings**.
- Point at a finding card showing the "⇄ N tools merged" badge (a genuine cross-tool duplicate),
  and one showing "possible false positive" (the system's own low-confidence inference).
- Click **Mark FP** or **Not FP** on one finding to show the analyst's explicit override (A9) — note
  the badge text changes to "false positive (confirmed)" and records who set it.

## 7. Risk prioritization + approval checkpoint — checklist item 5

- Point out the P1/P2/P3/P4 + severity badges and the transparent risk formula (mention
  `risk_breakdown` is in the PDF, not just a number).
- On a critical/high finding, click **Request active-validation approval**. Switch to a `lead`
  (or `admin`) account and show **Approve & execute** / **Deny** — narrate that *requesting*
  approval and *deciding* it are different roles, a real separation of duties, not the same person
  rubber-stamping their own request.

## 8. Evidence traceability + report — checklist item 6

- Click **Generate VAPT PDF report**; open it and show the per-finding evidence snippet with its
  SHA-256, and the "assets actually tested" table distinct from the authorized scope.
- Click **Download evidence pack (.zip)** and show it bundles the report, the scoped audit log
  slice, and the raw tool-output files together — independently verifiable provenance.

## 9. Audit trail — ties it together

- Click **Load audit trail for this assessment**; scroll through a few entries, point out the
  `chain intact` badge, and mention (don't need to demonstrate) that tampering with any past entry
  breaks the chain detectably.

## Closing notes to say on camera

- Scope boundary: only organizer-provided/attested lab targets, enforced server-side on every call
  (not just the UI).
- No autonomous exploitation: Metasploit only ever runs in `check` mode, only after a recorded
  `lead`/`admin` approval.
- Nothing here is fabricated: every finding traces to a real parsed tool output or is explicitly
  flagged `[inference]`.
