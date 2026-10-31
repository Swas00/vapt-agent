"""Orchestrator: owns one Assessment's lifecycle and is the only place that calls adapters, scope
enforcement, the correlator, and the risk engine. Every state transition is written to the audit log.
"""
from __future__ import annotations

from pathlib import Path

from . import correlate, planner, risk
from .adapters import registry
from .adapters.infra import Metasploit
from .audit import AuditLog
from .models import Approval, Assessment, Event, PlanStep, ScopeModel, ToolRun
from .scope import check as scope_check
from .scope import validate_scope


class ScopeError(Exception):
    pass


class Orchestrator:
    def __init__(self, data_dir: Path, audit: AuditLog):
        self.data_dir = Path(data_dir)
        self.audit = audit
        self.adapters = registry()

    # ---- lifecycle -----------------------------------------------------
    def create(self, request: str, scope: ScopeModel) -> Assessment:
        problems = validate_scope(scope)
        if problems:
            raise ScopeError("; ".join(problems))
        a = Assessment(request=request, scope=scope)
        a.events.append(Event(level="decision", message=f"Assessment created for {len(scope.targets)} target(s)."))
        self.audit.append("analyst", "assessment.create", assessment=a.id, targets=scope.targets)
        a.plan = planner.build_initial_plan(a)
        a.state = "planned"
        for step in a.plan:
            self.audit.append("agent", "plan.step_proposed", assessment=a.id, step=step.id,
                              tool=step.tool, target=step.target, rationale=step.rationale)
        return a

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

    def run_step(self, a: Assessment, step_id: str) -> ToolRun:
        step = next(s for s in a.plan if s.id == step_id)
        if step.status not in ("approved",):
            raise ScopeError(f"step {step_id} is '{step.status}', not approved")
        adapter = self.adapters.get(step.tool)
        if adapter is None:
            raise ScopeError(f"no adapter registered for tool '{step.tool}'")
        step.status = "running"
        run = adapter.run(step.target, step.preset, self._workdir(a))
        a.runs.append(run)
        step.run_id, step.status = run.id, ("done" if run.status == "ok" else "failed")
        self.audit.append("agent", "tool.run", assessment=a.id, run=run.id, tool=run.tool,
                          target=run.target, status=run.status, raw_sha256=run.raw_sha256, error=run.error)
        if run.status == "ok" and run.raw_path:
            self._ingest(a, adapter, Path(run.raw_path), run)
        elif run.status != "ok":
            a.limitations.append(f"{run.tool} against {run.target} ({run.preset}): {run.status} -- {run.error}")
            a.events.append(Event(level="error", message=f"{run.tool} failed on {run.target}: {run.error}"))
        return run

    def import_result(self, a: Assessment, tool: str, raw_path: Path, target: str = "") -> ToolRun:
        """Ingest a recorded/exported output file (Nessus/.nessus, OpenVAS XML, ZAP/Nikto JSON, Burp XML)."""
        adapter = self.adapters.get(tool)
        if adapter is None:
            raise ScopeError(f"no adapter registered for tool '{tool}'")
        run = ToolRun(tool=tool, mode="import", target=target or str(raw_path), status="ok",
                      raw_path=str(raw_path))
        from .adapters.base import sha256_file
        run.raw_sha256 = sha256_file(raw_path)
        a.runs.append(run)
        self.audit.append("analyst", "tool.import", assessment=a.id, run=run.id, tool=tool,
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
    def analyse(self, a: Assessment) -> Assessment:
        a.findings = correlate.correlate(a.raw_findings)
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

    # ---- human-in-the-loop approval for active validation ---------------
    def request_approval(self, a: Assessment, finding_id: str, action: str, module: str = "") -> Approval:
        f = next(x for x in a.findings if x.id == finding_id)
        appr = Approval(finding_id=finding_id, asset=f.asset, action=action, module=module)
        a.approvals.append(appr)
        f.validation_status = "approval_pending"
        self.audit.append("agent", "approval.requested", assessment=a.id, approval=appr.id,
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

    def execute_approval(self, a: Assessment, approval_id: str) -> ToolRun:
        appr = next(x for x in a.approvals if x.id == approval_id)
        if appr.state != "approved":
            raise ScopeError(f"approval {approval_id} is '{appr.state}', cannot execute")
        f = next(x for x in a.findings if x.id == appr.finding_id)
        d = scope_check(a.scope, f.asset, tool="metasploit")
        if not d.allowed:
            appr.state, appr.outcome = "failed", f"scope rejected: {d.reason}"
            self.audit.append("agent", "approval.scope_rejected", assessment=a.id, approval=appr.id, reason=d.reason)
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
        self.audit.append(appr.decided_by or "analyst", "approval.executed", assessment=a.id,
                          approval=appr.id, run=run.id, status=run.status, outcome=appr.outcome)
        return run
