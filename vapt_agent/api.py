"""FastAPI backend: conversational request -> scope validation -> plan -> approve/run -> analyse ->
human approval for active validation -> report. State lives in-memory per Assessment, persisted to
./data/<id>/ and the audit log under ./data/audit.log.

Authentication: every state-changing (POST) route depends on `require_analyst`, which resolves a
bearer token to a verified analyst identity (see auth.py). That identity -- never anything the
client puts in a query string or body -- is what gets written to the audit log and to approval
records. Read-only GET routes stay open so the audit trail and integration matrix remain inspectable.
"""
from __future__ import annotations

import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import auth
from .audit import AuditLog
from .models import Assessment, ScopeModel
from .orchestrator import Orchestrator, ScopeError
from .report import generate as generate_report

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
DEV_TOKEN_PATH = DATA_DIR / ".dev_token"

audit = AuditLog(DATA_DIR / "audit.log")
orch = Orchestrator(DATA_DIR, audit)
ASSESSMENTS: dict[str, Assessment] = {}

# Built at startup (lifespan) rather than at import, so merely importing this module -- e.g. from a
# test -- never writes a dev token to disk. Tests assign their own registry directly.
auth_registry: auth.AuthRegistry | None = None


def get_registry() -> auth.AuthRegistry:
    global auth_registry
    if auth_registry is None:
        auth_registry = auth.AuthRegistry.from_env(dev_token_path=DEV_TOKEN_PATH)
        print(auth.startup_banner(auth_registry, DEV_TOKEN_PATH), file=sys.stderr)
    return auth_registry


@asynccontextmanager
async def lifespan(_app: FastAPI):
    get_registry()          # fail fast on a malformed VAPT_ANALYST_TOKENS, and show the dev token
    yield


app = FastAPI(title="VAPT Agent", version="0.1.0", lifespan=lifespan)

static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

_bearer = HTTPBearer(auto_error=False, description="Analyst token (see VAPT_ANALYST_TOKENS)")


def require_analyst(request: Request,
                    creds: HTTPAuthorizationCredentials | None = Depends(_bearer)) -> str:
    """Resolve the bearer token to a verified analyst identity, or reject with 401.

    Failed attempts are audited (throttled per client so they can't flood the append-only log)
    with the reason and path only -- the presented token is never recorded.
    """
    registry = get_registry()
    identity = registry.authenticate(creds.credentials) if creds is not None else None
    if identity is None:
        client = request.client.host if request.client else "unknown"
        if registry.should_log_failure(client):
            audit.append("system", "auth.rejected", method=request.method,
                         path=request.url.path[:200], client=client,
                         reason="missing credentials" if creds is None else "invalid token")
        raise HTTPException(401, "authentication required: send 'Authorization: Bearer <analyst token>'",
                            headers={"WWW-Authenticate": "Bearer"})
    return identity


def _get(assessment_id: str) -> Assessment:
    a = ASSESSMENTS.get(assessment_id)
    if not a:
        raise HTTPException(404, "assessment not found")
    return a


@app.get("/whoami")
def whoami(actor: str = Depends(require_analyst)):
    """Validate a token and report which identity it maps to (the UI's sign-in check)."""
    return {"identity": actor}


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

class CreateReq(BaseModel):
    request: str
    scope: ScopeModel


@app.post("/assessments")
def create_assessment(body: CreateReq, actor: str = Depends(require_analyst)):
    try:
        a = orch.create(body.request, body.scope, actor=actor)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    ASSESSMENTS[a.id] = a
    return a


@app.get("/assessments")
def list_assessments():
    return [{"id": a.id, "state": a.state, "created": a.created, "created_by": a.created_by,
             "request": a.request} for a in ASSESSMENTS.values()]


@app.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str):
    return _get(assessment_id)


@app.post("/assessments/{assessment_id}/plan/{step_id}/decision")
def decide_step(assessment_id: str, step_id: str, approved: bool, actor: str = Depends(require_analyst)):
    a = _get(assessment_id)
    return orch.approve_step(a, step_id, approved, actor)


@app.post("/assessments/{assessment_id}/plan/{step_id}/run")
def run_step(assessment_id: str, step_id: str, actor: str = Depends(require_analyst)):
    a = _get(assessment_id)
    try:
        return orch.run_step(a, step_id, actor=actor)
    except ScopeError as e:
        raise HTTPException(400, str(e))


@app.post("/assessments/{assessment_id}/import/{tool}")
async def import_result(assessment_id: str, tool: str, file: UploadFile = File(...),
                        actor: str = Depends(require_analyst)):
    a = _get(assessment_id)
    dest = DATA_DIR / assessment_id / "raw" / file.filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(await file.read())
    try:
        return orch.import_result(a, tool, dest, actor=actor)
    except ScopeError as e:
        raise HTTPException(400, str(e))


@app.post("/assessments/{assessment_id}/analyse")
def analyse(assessment_id: str, actor: str = Depends(require_analyst)):
    a = _get(assessment_id)
    return orch.analyse(a)


class ApprovalReq(BaseModel):
    finding_id: str
    action: str
    module: str = ""


@app.post("/assessments/{assessment_id}/approvals")
def request_approval(assessment_id: str, body: ApprovalReq, actor: str = Depends(require_analyst)):
    a = _get(assessment_id)
    return orch.request_approval(a, body.finding_id, body.action, body.module, requested_by=actor)


@app.post("/assessments/{assessment_id}/approvals/{approval_id}/decision")
def decide_approval(assessment_id: str, approval_id: str, approved: bool, reason: str = "",
                    actor: str = Depends(require_analyst)):
    a = _get(assessment_id)
    return orch.decide_approval(a, approval_id, approved, actor, reason)


@app.post("/assessments/{assessment_id}/approvals/{approval_id}/execute")
def execute_approval(assessment_id: str, approval_id: str, actor: str = Depends(require_analyst)):
    a = _get(assessment_id)
    try:
        return orch.execute_approval(a, approval_id, executed_by=actor)
    except ScopeError as e:
        raise HTTPException(400, str(e))


@app.post("/assessments/{assessment_id}/report")
def report(assessment_id: str, actor: str = Depends(require_analyst)):
    a = _get(assessment_id)
    out = DATA_DIR / assessment_id / "report.pdf"
    generate_report(a, out)
    a.state = "reported"
    audit.append(actor, "report.generated", assessment=a.id, path=str(out))
    return FileResponse(str(out), media_type="application/pdf", filename=f"VAPT-{a.id}.pdf")


@app.get("/audit")
def get_audit():
    ok, msg = audit.verify()
    return {"ok": ok, "message": msg, "entries": audit.entries()}


@app.get("/integration-matrix")
def matrix():
    from .adapters import integration_matrix
    return integration_matrix()
