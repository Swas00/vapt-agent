"""Common data model shared by every adapter, the correlator, the risk engine and the report."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def uid(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex[:10]


class Evidence(BaseModel):
    """An observation made by a tool. Never written by the LLM."""
    tool: str
    raw_ref: str                 # e.g. "nmap:scan1.xml#host=10.0.0.5/port=80"
    snippet: str                 # verbatim excerpt from the tool output
    timestamp: str = Field(default_factory=now)
    artifact_sha256: Optional[str] = None


class Service(BaseModel):
    host: str
    port: int
    proto: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""             # "ssl" when TLS-wrapped
    source_tool: str = ""

    @property
    def is_web(self) -> bool:
        n = self.name.lower()
        return "http" in n or self.port in (80, 443, 8000, 8008, 8080, 8443, 8888)

    @property
    def scheme(self) -> str:
        return "https" if (self.tunnel == "ssl" or self.port in (443, 8443) or "https" in self.name.lower()) else "http"

    def url(self) -> str:
        return f"{self.scheme}://{self.host}:{self.port}"


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uid("raw-"))
    title: str
    asset: str                                   # host (IP / hostname)
    port: Optional[int] = None
    proto: str = "tcp"
    service: str = ""
    source_tools: list[str] = Field(default_factory=list)
    severity: Severity = "info"
    cvss: Optional[float] = None                 # only ever copied from tool output
    cvss_vector: Optional[str] = None
    cvss_estimated: bool = False                 # True if cvss was derived from tool severity band
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)   # e.g. ["T1210 — Exploitation of Remote Services"];
                                                              # indicative mapping only, see frameworks.py
    description: str = ""
    solution: str = ""
    references: list[str] = Field(default_factory=list)
    exploit_available: Optional[bool] = None     # None = unknown (never guessed)
    evidence: list[Evidence] = Field(default_factory=list)   # observed
    inference: list[str] = Field(default_factory=list)       # AI / rule-derived reasoning, labelled as such
    confidence: float = 0.5                      # 0..1
    status: Literal["confirmed", "suspected", "false_positive_candidate"] = "suspected"
    validation_status: Literal["not_validated", "approval_pending", "validated", "not_reproducible", "denied", "failed"] = "not_validated"
    merged_from: list[str] = Field(default_factory=list)     # raw finding ids merged into this
    location: str = ""                           # URL / path for web findings
    # risk (filled by risk.py)
    risk_score: Optional[float] = None
    priority: Optional[str] = None
    risk_breakdown: dict = Field(default_factory=dict)
    # remediation lifecycle -- analyst-set only, never inferred; tracked separately from
    # validation_status (which is about whether the finding itself is real, not whether it's fixed)
    remediation_status: Literal["open", "in_progress", "fixed", "retested"] = "open"
    remediation_updated_by: str = ""
    remediation_updated_at: str = ""
    # A9: an explicit analyst verdict on whether this finding is a false positive -- distinct from
    # `status`'s "false_positive_candidate", which is only ever the system's OWN inference
    # (correlate.py: single tool, low confidence, generic info-level). None = analyst hasn't
    # reviewed it; True/False is a human call that always wins over the inference either way (see
    # `is_false_positive()` below) -- an analyst can confirm a flagged candidate is indeed a false
    # positive, or just as importantly, overturn one that was flagged wrongly.
    analyst_marked_false_positive: Optional[bool] = None
    analyst_fp_reason: str = ""
    analyst_fp_set_by: str = ""
    analyst_fp_set_at: str = ""


def is_false_positive(f: Finding) -> bool:
    """The single place every consumer (risk.py's scoring discount, planner.py's corroboration
    triggers, report.py's counts/labelling) should check, so the analyst's explicit A9 verdict
    and the system's own inference never drift into two different answers to "is this a false
    positive" in different parts of the codebase."""
    if f.analyst_marked_false_positive is not None:
        return f.analyst_marked_false_positive
    return f.status == "false_positive_candidate"


class ToolRun(BaseModel):
    id: str = Field(default_factory=lambda: uid("run-"))
    tool: str
    mode: Literal["live", "import"]
    target: str
    preset: str = ""
    command: list[str] = Field(default_factory=list)
    status: Literal["pending", "running", "ok", "failed", "timeout", "unavailable", "skipped", "cancelled"] = "pending"
    started: Optional[str] = None
    finished: Optional[str] = None
    error: str = ""
    raw_path: str = ""
    raw_sha256: str = ""
    findings: int = 0
    services: int = 0


class PlanStep(BaseModel):
    id: str = Field(default_factory=lambda: uid("step-"))
    tool: str
    target: str
    preset: str = "default"
    rationale: str
    depends_on_evidence: list[str] = Field(default_factory=list)   # raw refs that triggered this step
    trigger_finding_id: Optional[str] = None   # set when this step was proposed in reaction to a Finding
    intrusive: bool = False
    mode: Literal["live", "import"] = "live"
    status: Literal["proposed", "approved", "running", "done", "failed", "skipped", "rejected", "cancelled"] = "proposed"
    origin: Literal["rules", "llm"] = "rules"
    run_id: Optional[str] = None
    skip_reason: str = ""
    kind: Literal["discovery", "service", "finding"] = "service"
    priority_score: Optional[float] = None     # 0..1, higher = more urgent; rule- or LLM-derived
    llm_explanation: str = ""                  # set only when `origin == "llm"` actually ranked this step
    alternatives_considered: list[dict] = Field(default_factory=list)   # other candidates weighed in the same batch


class Approval(BaseModel):
    id: str = Field(default_factory=lambda: uid("appr-"))
    finding_id: str
    asset: str
    action: str                       # human-readable description of what will run
    tool: str = "metasploit"
    module: str = ""                  # supplied by the analyst, never invented by the agent
    requested_at: str = Field(default_factory=now)
    requested_by: str = ""            # verified analyst identity (auth.py), never client-supplied
    state: Literal["pending", "approved", "denied", "executed", "failed"] = "pending"
    decided_by: str = ""
    executed_by: str = ""
    decided_at: str = ""
    reason: str = ""
    outcome: str = ""
    outcome_ref: str = ""


class Event(BaseModel):
    ts: str = Field(default_factory=now)
    level: Literal["info", "decision", "warn", "error"] = "info"
    message: str


class Batch(BaseModel):
    """FS-4: a named grouping of several single-target Assessments created together from one
    multi-target request. Deliberately NOT a container the targets' findings get merged into --
    each target keeps its own independent Assessment (its own plan, scope check, audit trail), so
    per-target state (one target's scan failing, one target getting a denied approval) stays
    exactly as inspectable as it already is for a single-target assessment. A Batch is only an
    index over assessment ids plus the aggregation the API computes on top of them."""
    id: str = Field(default_factory=lambda: uid("batch-"))
    created: str = Field(default_factory=now)
    created_by: str = ""
    name: str
    assessment_ids: list[str] = Field(default_factory=list)


class Assessment(BaseModel):
    id: str = Field(default_factory=lambda: uid("asm-"))
    created: str = Field(default_factory=now)
    created_by: str = ""              # verified analyst identity that opened this assessment
    request: str
    scope: "ScopeModel"
    state: Literal["created", "planned", "scanning", "analysed", "reviewed", "reported", "rejected"] = "created"
    plan: list[PlanStep] = Field(default_factory=list)
    runs: list[ToolRun] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    raw_findings: list[Finding] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    approvals: list[Approval] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    llm_mode: str = "rules-engine"
    llm_notes: list[str] = Field(default_factory=list)


class ScopeModel(BaseModel):
    targets: list[str]
    exclusions: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=lambda: [
        "nmap", "nikto", "zap", "nessus", "openvas", "burp", "metasploit"])
    allowed_ports: Optional[list[int]] = None
    max_rate_pps: int = 100
    allow_active_validation: bool = False
    lab_attestation: bool = False       # operator attests targets are organizer-provided lab systems
    allow_public: bool = False          # organizer lab on a public IP: must be explicit and is audited
    asset_criticality: dict[str, Literal["low", "medium", "high", "critical"]] = Field(default_factory=dict)
    permissions_note: str = ""          # free text: who authorised, ticket / organizer reference


Assessment.model_rebuild()
