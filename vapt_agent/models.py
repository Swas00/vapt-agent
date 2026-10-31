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


class ToolRun(BaseModel):
    id: str = Field(default_factory=lambda: uid("run-"))
    tool: str
    mode: Literal["live", "import"]
    target: str
    preset: str = ""
    command: list[str] = Field(default_factory=list)
    status: Literal["pending", "running", "ok", "failed", "timeout", "unavailable", "skipped"] = "pending"
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
    status: Literal["proposed", "approved", "running", "done", "failed", "skipped", "rejected"] = "proposed"
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
    state: Literal["pending", "approved", "denied", "executed", "failed"] = "pending"
    decided_by: str = ""
    decided_at: str = ""
    reason: str = ""
    outcome: str = ""
    outcome_ref: str = ""


class Event(BaseModel):
    ts: str = Field(default_factory=now)
    level: Literal["info", "decision", "warn", "error"] = "info"
    message: str


class Assessment(BaseModel):
    id: str = Field(default_factory=lambda: uid("asm-"))
    created: str = Field(default_factory=now)
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
