"""Orchestrator: owns one Assessment's lifecycle and is the only place that calls adapters, scope
enforcement, the correlator, and the risk engine. Every state transition is written to the audit log.
"""
from __future__ import annotations

import subprocess
import threading
from pathlib import Path

from . import calibration, correlate, frameworks, planner, risk
from .adapters import registry
from .adapters.infra import Metasploit
from .audit import AuditLog
from .models import Approval, Assessment, Batch, Event, Finding, PlanStep, ScopeModel, ToolRun
from .scope import check as scope_check
from .scope import validate_scope


class ScopeError(Exception):
    pass


class Orchestrator:
    def __init__(self, data_dir: Path, audit: AuditLog):
        self.data_dir = Path(data_dir)
        self.audit = audit
        self.adapters = registry()
        self._locks: dict[str, threading.Lock] = {}
        # A2: live subprocess handles for currently-running scans, keyed by ToolRun.id, plus the
        # set of run ids a cancel was requested for -- both process-wide (not per-assessment),
        # guarded by their own lock since they're touched from the request thread (cancel_run)
        # while a DIFFERENT thread is blocked inside Adapter.run()'s subprocess.communicate().
        self._procs: dict[str, subprocess.Popen] = {}
        self._cancel_requested: set[str] = set()
        self._proc_lock = threading.Lock()

    def _lock(self, a: Assessment) -> threading.Lock:
        """One lock per assessment, guarding mutation of its runs/plan/findings against a
        background scan finishing while a request for the same assessment is in flight."""
        return self._locks.setdefault(a.id, threading.Lock())

    # ---- lifecycle -----------------------------------------------------
    def create(self, request: str, scope: ScopeModel, actor: str = "analyst") -> Assessment:
        """`actor` is the verified analyst identity. The API layer always supplies it from the
        authenticated session (accounts.py); the default only exists for in-process use (demo scripts)."""
        problems = validate_scope(scope)
        if problems:
            raise ScopeError("; ".join(problems))
        a = Assessment(request=request, scope=scope, created_by=actor)
        a.events.append(Event(level="decision", message=f"Assessment created by {actor} for "
                                                         f"{len(scope.targets)} target(s)."))
        self.audit.append(actor, "assessment.create", assessment=a.id, targets=scope.targets)
        a.plan = planner.build_initial_plan(a)
        a.state = "planned"
        for step in a.plan:
            self.audit.append("agent", "plan.step_proposed", assessment=a.id, step=step.id,
                              tool=step.tool, target=step.target, rationale=step.rationale)
        return a

    def create_batch(self, name: str, request: str, targets: list[str], scope_template: ScopeModel,
                     actor: str = "analyst") -> tuple[Batch, list[Assessment]]:
        """FS-4: one `Assessment` per target, each independently scope-checked and planned exactly
        as `create()` already does for a single-target request -- a Batch never merges targets
        into one assessment's scope, because that would also merge their state (one target's scan
        failing would look like the whole batch failing) and their audit trail. `scope_template`
        supplies every scope field EXCEPT targets, which is overridden per member to that one
        target; this also means a scope problem specific to one target (out-of-scope exclusion,
        say) only rejects that target, not the whole batch -- collected as one combined error if
        every single target in the batch gets rejected, but a partial batch is allowed to proceed
        with whichever targets did validate, since analysts commonly paste a mixed list."""
        members: list[Assessment] = []
        problems: list[str] = []
        for target in targets:
            member_scope = scope_template.model_copy(update={"targets": [target]})
            try:
                members.append(self.create(request, member_scope, actor=actor))
            except ScopeError as e:
                problems.append(f"{target}: {e}")
        if not members:
            raise ScopeError("; ".join(problems) or "no targets supplied")
        batch = Batch(name=name, created_by=actor, assessment_ids=[a.id for a in members])
        self.audit.append(actor, "batch.create", batch=batch.id, name=name,
                          assessments=batch.assessment_ids, rejected_targets=problems)
        return batch, members

    def _workdir(self, a: Assessment) -> Path:
        return self.data_dir / a.id / "raw"

    # ---- plan approval / execution -------------------------------------
    def approve_step(self, a: Assessment, step_id: str, approved: bool, by: str = "analyst") -> PlanStep:
        step = next(s for s in a.plan if s.id == step_id)
        d = scope_check(a.scope, step.target, tool=step.tool)
        if not d.allowed:
            step.status, step.skip_reason = "rejected", d.reason
            self.audit.append(by, "plan.step_rejected", assessment=a.id, step=step.id, reason=d.reason)
            a.events.append(Event(level="warn", message=f"Step {step.id} ({step.tool} -> {step.target}) "
                                                         f"rejected by scope enforcement: {d.reason}"))
            return step
        step.status = "approved" if approved else "rejected"
        self.audit.append(by, f"plan.step_{step.status}", assessment=a.id, step=step.id)
        return step

    def start_step(self, a: Assessment, step_id: str, actor: str = "analyst") -> ToolRun:
        """Validate and mark a step 'running', returning a placeholder ToolRun immediately.
        The actual (blocking) scan is performed by finish_step -- callers that want the
        request to return right away schedule that as a background task; run_step below
        calls both back-to-back for callers that want the old synchronous behaviour.

        F4: the 'is this step actually still approved' check and the mutation that flips it to
        'running' must happen under the SAME lock acquisition, not one before it and one inside
        it -- otherwise two concurrent calls for the same step_id (e.g. a doubled click, or a
        retried request racing the original) can both pass the check before either has flipped
        the status, and both end up appending a ToolRun and launching the same scan twice."""
        step = next(s for s in a.plan if s.id == step_id)
        if self.adapters.get(step.tool) is None:
            raise ScopeError(f"no adapter registered for tool '{step.tool}'")
        with self._lock(a):
            if step.status not in ("approved",):
                raise ScopeError(f"step {step_id} is '{step.status}', not approved")
            run = ToolRun(tool=step.tool, mode=step.mode, target=step.target, preset=step.preset,
                          status="running")
            a.runs.append(run)
            step.run_id, step.status = run.id, "running"
        self.audit.append("agent", "tool.start", assessment=a.id, run=run.id, tool=run.tool,
                          target=run.target, triggered_by=actor)
        return run

    def finish_step(self, a: Assessment, step_id: str, run_id: str, actor: str = "analyst") -> None:
        """Runs the actual scan and folds the result back into the placeholder ToolRun created
        by start_step, in place, so a client polling by run_id sees one record transition
        running -> done/failed rather than two unrelated run ids.

        A2: registers the adapter's live subprocess handle (if any -- see Adapter.run()'s
        `on_start`) under `run_id` for the duration of the call, so `cancel_run()` on a different
        thread can terminate it while this thread is blocked waiting on it."""
        step = next(s for s in a.plan if s.id == step_id)
        adapter = self.adapters[step.tool]

        def _on_start(proc: subprocess.Popen) -> None:
            with self._proc_lock:
                self._procs[run_id] = proc

        try:
            result = adapter.run(step.target, step.preset, self._workdir(a), on_start=_on_start)
        finally:
            with self._proc_lock:
                self._procs.pop(run_id, None)
                was_cancelled = run_id in self._cancel_requested
                self._cancel_requested.discard(run_id)
        with self._lock(a):
            run = next(r for r in a.runs if r.id == run_id)
            for field in type(result).model_fields:
                if field != "id":
                    setattr(run, field, getattr(result, field))
            if was_cancelled:
                run.status, run.error = "cancelled", run.error or "cancelled by analyst request"
            step.status = {"ok": "done", "cancelled": "cancelled"}.get(run.status, "failed")
        # The *execution* is the agent's act, but a human triggered it -- keep both on the record.
        self.audit.append("agent", "tool.run", assessment=a.id, run=run.id, tool=run.tool,
                          target=run.target, status=run.status, raw_sha256=run.raw_sha256, error=run.error,
                          triggered_by=actor)
        if run.status == "ok" and run.raw_path:
            self._ingest(a, adapter, Path(run.raw_path), run)
        elif run.status != "ok":
            a.limitations.append(f"{run.tool} against {run.target} ({run.preset}): {run.status} -- {run.error}")
            a.events.append(Event(level="error", message=f"{run.tool} failed on {run.target}: {run.error}"))

    def cancel_run(self, a: Assessment, run_id: str, by: str = "analyst") -> ToolRun:
        """A2: terminates the live subprocess for a currently-running ToolRun. finish_step (on
        its own thread) sees the process exit, notices `run_id` is in `_cancel_requested`, and
        labels the ToolRun/PlanStep 'cancelled' itself -- this method only requests it and records
        the request; it never mutates the ToolRun directly, since that thread is the one actually
        racing to write it and this avoids a second writer."""
        run = next((r for r in a.runs if r.id == run_id), None)
        if run is None:
            raise ScopeError(f"run {run_id} not found")
        if run.status != "running":
            raise ScopeError(f"run {run_id} is '{run.status}', not running")
        with self._proc_lock:
            proc = self._procs.get(run_id)
            if proc is None:
                raise ScopeError(f"run {run_id} has no live process to cancel "
                                 "(it may be an adapter with no cancellable subprocess, e.g. ZAP's REST API)")
            self._cancel_requested.add(run_id)
            proc.terminate()
        self.audit.append(by, "tool.cancel_requested", assessment=a.id, run=run_id, tool=run.tool)
        return run

    def run_step(self, a: Assessment, step_id: str, actor: str = "analyst") -> ToolRun:
        """Synchronous convenience wrapper (demo scripts, direct orchestrator use) over the same
        two phases the API schedules separately via BackgroundTasks."""
        run = self.start_step(a, step_id, actor)
        self.finish_step(a, step_id, run.id, actor)
        return run

    def import_result(self, a: Assessment, tool: str, raw_path: Path, target: str = "",
                      actor: str = "analyst") -> ToolRun:
        """Ingest a recorded/exported output file (Nessus/.nessus, OpenVAS XML, ZAP/Nikto JSON, Burp XML)."""
        adapter = self.adapters.get(tool)
        if adapter is None:
            raise ScopeError(f"no adapter registered for tool '{tool}'")
        run = ToolRun(tool=tool, mode="import", target=target or str(raw_path), status="ok",
                      raw_path=str(raw_path))
        from .adapters.base import sha256_file
        run.raw_sha256 = sha256_file(raw_path)
        a.runs.append(run)
        self.audit.append(actor, "tool.import", assessment=a.id, run=run.id, tool=tool,
                          raw_sha256=run.raw_sha256, source=str(raw_path))
        self._ingest(a, adapter, Path(raw_path), run)
        return run

    def _ingest(self, a: Assessment, adapter, raw_path: Path, run: ToolRun) -> None:
        parsed = adapter.parse(raw_path)
        kept_services, kept_findings = [], []
        for svc in parsed.services:
            d = scope_check(a.scope, svc.host, resolve=False)
            if d.allowed:
                kept_services.append(svc)
        for f in parsed.findings:
            d = scope_check(a.scope, f.asset, resolve=False)
            if not d.allowed:
                self.audit.append("agent", "finding.dropped_out_of_scope", assessment=a.id,
                                  asset=f.asset, title=f.title, reason=d.reason)
                continue
            f.source_tools = f.source_tools or [adapter.name]
            kept_findings.append(f)
        a.services.extend(kept_services)
        a.raw_findings.extend(kept_findings)
        run.services, run.findings = len(kept_services), len(kept_findings)
        if run.mode == "import":
            # An import's `target` defaulted to the raw file path (we don't know the asset until
            # it's parsed). Replace it with the actual in-scope asset(s) found inside the file --
            # both for a readable report tool-execution-summary table, and because later planning
            # logic checks "has tool X already covered asset Y" by looking at ToolRun.target.
            assets = sorted({s.host for s in kept_services} | {f.asset for f in kept_findings})
            if assets:
                run.target = ", ".join(assets)
        self.audit.append("agent", "tool.ingested", assessment=a.id, run=run.id,
                          services=len(kept_services), findings=len(kept_findings))
        new_steps = planner.plan_from_services(a, kept_services)
        self._absorb_new_steps(a, new_steps, f"evidence in {run.tool} output")

    def _absorb_new_steps(self, a: Assessment, new_steps: list[PlanStep], trigger_desc: str) -> None:
        """Append a freshly-ranked batch of steps to the plan and audit each one, including the
        ones the ranking decided to defer (status='skipped') -- those are logged too, so "why
        didn't the agent run X" has a real, inspectable answer rather than silence."""
        proposed = [s for s in new_steps if s.status == "proposed"]
        skipped = [s for s in new_steps if s.status == "skipped"]
        for s in new_steps:
            a.plan.append(s)
            self.audit.append("agent", f"plan.step_{s.status}", assessment=a.id, step=s.id,
                              tool=s.tool, target=s.target, kind=s.kind, origin=s.origin,
                              depends_on=s.depends_on_evidence, trigger_finding=s.trigger_finding_id,
                              rationale=s.rationale, priority=s.priority_score)
        if proposed:
            a.events.append(Event(level="decision",
                                  message=f"{len(proposed)} new step(s) proposed from {trigger_desc}"
                                          f"{' (' + a.llm_mode + ')' if proposed[0].origin == 'llm' else ''}."))
        for s in skipped:
            a.events.append(Event(level="info",
                                  message=f"Considered {s.tool} -> {s.target} ({s.preset}) from {trigger_desc} "
                                          f"but deferred: {s.skip_reason}"))

    # ---- analysis --------------------------------------------------------
    def analyse(self, a: Assessment, history: list[Assessment] | None = None) -> Assessment:
        """`history` is an optional list of OTHER assessments (never including `a` itself) whose
        already-validated findings may calibrate this one's confidence (FS-6). Callers that don't
        have a history available (direct Orchestrator use, e.g. demo.py) simply omit it -- no
        calibration happens, same behaviour as before FS-6."""
        a.findings = correlate.correlate(a.raw_findings)
        frameworks.apply(a.findings)
        if history:
            hist = calibration.build_history([h for h in history if h.id != a.id])
            calibrated = [f for f in a.findings if calibration.calibrate(f, hist)]
            if calibrated:
                self.audit.append("agent", "analysis.confidence_calibrated", assessment=a.id,
                                  count=len(calibrated), findings=[f.id for f in calibrated])
                a.events.append(Event(level="decision",
                                      message=f"Calibrated confidence for {len(calibrated)} finding(s) "
                                              "against historical active-validation outcomes from "
                                              "other assessments."))
        for f in a.findings:
            risk.score(f, a.scope)
        a.findings = risk.rank(a.findings)
        a.state = "analysed"
        dup = len(a.raw_findings) - len(a.findings)
        self.audit.append("agent", "analysis.correlated", assessment=a.id,
                          raw=len(a.raw_findings), merged=len(a.findings), duplicates_folded=dup)
        a.events.append(Event(level="decision",
                              message=f"Correlated {len(a.raw_findings)} raw findings into "
                                      f"{len(a.findings)} ({dup} duplicate(s) folded)."))

        # Finding-driven replanning: react to severity/confidence, not just to an open port.
        new_steps = planner.plan_from_findings(a)
        self._absorb_new_steps(a, new_steps, "a correlated finding's severity/confidence")

        # Surface (never auto-create) active-validation approval suggestions for the analyst.
        for prop in planner.propose_validation_steps(a, a.findings):
            self.audit.append("agent", "approval.suggested", assessment=a.id,
                              finding=prop["finding_id"], suggested_action=prop["action"], rationale=prop["rationale"])
            a.events.append(Event(level="decision",
                                  message=f"Suggests requesting human-approved active validation for "
                                          f"finding {prop['finding_id']}: {prop['rationale']}"))
        return a

    # ---- remediation lifecycle (analyst-set only, never inferred) --------
    def set_remediation_status(self, a: Assessment, finding_id: str, status: str, by: str) -> Finding:
        f = next(x for x in a.findings if x.id == finding_id)
        from .models import now
        f.remediation_status, f.remediation_updated_by, f.remediation_updated_at = status, by, now()
        self.audit.append(by, "finding.remediation_updated", assessment=a.id, finding=finding_id, status=status)
        return f

    # ---- false-positive marking (A9: analyst-set only, never inferred) ---
    def set_false_positive(self, a: Assessment, finding_id: str, marked: bool, by: str,
                           reason: str = "") -> Finding:
        """An explicit human verdict, distinct from `status`'s own "false_positive_candidate"
        inference (correlate.py). Always re-scores the finding afterward, since risk.score()'s
        discount now reads `is_false_positive()` (status OR this override), not status alone."""
        f = next(x for x in a.findings if x.id == finding_id)
        from .models import now
        f.analyst_marked_false_positive = marked
        f.analyst_fp_reason, f.analyst_fp_set_by, f.analyst_fp_set_at = reason, by, now()
        risk.score(f, a.scope)
        self.audit.append(by, "finding.false_positive_marked", assessment=a.id, finding=finding_id,
                          marked=marked, reason=reason)
        return f

    # ---- human-in-the-loop approval for active validation ---------------
    def request_approval(self, a: Assessment, finding_id: str, action: str, module: str = "",
                         requested_by: str = "analyst") -> Approval:
        f = next(x for x in a.findings if x.id == finding_id)
        appr = Approval(finding_id=finding_id, asset=f.asset, action=action, module=module,
                        requested_by=requested_by)
        a.approvals.append(appr)
        f.validation_status = "approval_pending"
        self.audit.append(requested_by, "approval.requested", assessment=a.id, approval=appr.id,
                          finding=finding_id, requested_action=action)
        return appr

    def decide_approval(self, a: Assessment, approval_id: str, approved: bool, by: str, reason: str = "") -> Approval:
        appr = next(x for x in a.approvals if x.id == approval_id)
        appr.state, appr.decided_by, appr.reason = ("approved" if approved else "denied"), by, reason
        from .models import now
        appr.decided_at = now()
        f = next(x for x in a.findings if x.id == appr.finding_id)
        f.validation_status = "not_validated" if not approved else f.validation_status
        self.audit.append(by, "approval.decided", assessment=a.id, approval=appr.id, state=appr.state, reason=reason)
        if not approved:
            f.validation_status = "denied"
        return appr

    def execute_approval(self, a: Assessment, approval_id: str, executed_by: str = "") -> ToolRun:
        appr = next(x for x in a.approvals if x.id == approval_id)
        if appr.state != "approved":
            raise ScopeError(f"approval {approval_id} is '{appr.state}', cannot execute")
        # Whoever triggers execution is recorded -- they may differ from whoever approved it.
        executor = executed_by or appr.decided_by or "analyst"
        appr.executed_by = executor
        f = next(x for x in a.findings if x.id == appr.finding_id)
        d = scope_check(a.scope, f.asset, tool="metasploit")
        if not d.allowed:
            appr.state, appr.outcome = "failed", f"scope rejected: {d.reason}"
            self.audit.append("agent", "approval.scope_rejected", assessment=a.id, approval=appr.id,
                              reason=d.reason, triggered_by=executor)
            return ToolRun(tool="metasploit", mode="live", target=f.asset, status="failed", error=d.reason)
        ms: Metasploit = self.adapters["metasploit"]  # type: ignore[assignment]
        run = ms.validate(appr, d.host, f.port, self._workdir(a))
        a.runs.append(run)
        appr.state = "executed" if run.status == "ok" else "failed"
        if run.status == "ok" and run.raw_path:
            outcome = ms.interpret(Path(run.raw_path).read_text())
            appr.outcome, appr.outcome_ref = outcome, run.raw_path
            f.validation_status = outcome if outcome in ("validated", "not_reproducible") else "failed"
            if outcome == "validated":
                f.status, f.confidence = "confirmed", max(f.confidence, 0.95)
                f.inference.append("[inference] Approved check-mode validation reported the target as vulnerable.")
            elif outcome == "not_reproducible":
                f.inference.append("[inference] Approved check-mode validation could not reproduce the issue.")
            risk.score(f, a.scope)
        self.audit.append(executor, "approval.executed", assessment=a.id,
                          approval=appr.id, run=run.id, status=run.status, outcome=appr.outcome)
        return run
