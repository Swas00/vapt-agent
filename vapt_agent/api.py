"""FastAPI backend: conversational request -> scope validation -> plan -> approve/run -> analyse ->
human approval for active validation -> report. State lives in-memory per Assessment, persisted to
./data/<id>/ and the audit log under ./data/audit.log.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .audit import AuditLog
from .models import Assessment, ScopeModel
from .orchestrator import Orchestrator, ScopeError
from .report import generate as generate_report

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)

app = FastAPI(title="VAPT Agent", version="0.1.0")
audit = AuditLog(DATA_DIR / "audit.log")
orch = Orchestrator(DATA_DIR, audit)
ASSESSMENTS: dict[str, Assessment] = {}

static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")


def _get(assessment_id: str) -> Assessment:
    a = ASSESSMENTS.get(assessment_id)
    if not a:
        raise HTTPException(404, "assessment not found")
    return a


class CreateReq(BaseModel):
    request: str
    scope: ScopeModel


@app.post("/assessments")
def create_assessment(body: CreateReq):
    try:
        a = orch.create(body.request, body.scope)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    ASSESSMENTS[a.id] = a
    return a


@app.get("/assessments")
def list_assessments():
    return [{"id": a.id, "state": a.state, "created": a.created, "request": a.request} for a in ASSESSMENTS.values()]


@app.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str):
    return _get(assessment_id)


@app.post("/assessments/{assessment_id}/plan/{step_id}/decision")
def decide_step(assessment_id: str, step_id: str, approved: bool, by: str = "analyst"):
    a = _get(assessment_id)
    return orch.approve_step(a, step_id, approved, by)


@app.post("/assessments/{assessment_id}/plan/{step_id}/run")
def run_step(assessment_id: str, step_id: str):
    a = _get(assessment_id)
    try:
        return orch.run_step(a, step_id)
    except ScopeError as e:
        raise HTTPException(400, str(e))


@app.post("/assessments/{assessment_id}/import/{tool}")
async def import_result(assessment_id: str, tool: str, file: UploadFile = File(...)):
    a = _get(assessment_id)
    dest = DATA_DIR / assessment_id / "raw" / file.filename
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(await file.read())
    try:
        return orch.import_result(a, tool, dest)
    except ScopeError as e:
        raise HTTPException(400, str(e))


@app.post("/assessments/{assessment_id}/analyse")
def analyse(assessment_id: str):
    a = _get(assessment_id)
    return orch.analyse(a)


class ApprovalReq(BaseModel):
    finding_id: str
    action: str
    module: str = ""


@app.post("/assessments/{assessment_id}/approvals")
def request_approval(assessment_id: str, body: ApprovalReq):
    a = _get(assessment_id)
    return orch.request_approval(a, body.finding_id, body.action, body.module)


@app.post("/assessments/{assessment_id}/approvals/{approval_id}/decision")
def decide_approval(assessment_id: str, approval_id: str, approved: bool, by: str, reason: str = ""):
    a = _get(assessment_id)
    return orch.decide_approval(a, approval_id, approved, by, reason)


@app.post("/assessments/{assessment_id}/approvals/{approval_id}/execute")
def execute_approval(assessment_id: str, approval_id: str):
    a = _get(assessment_id)
    try:
        return orch.execute_approval(a, approval_id)
    except ScopeError as e:
        raise HTTPException(400, str(e))


@app.post("/assessments/{assessment_id}/report")
def report(assessment_id: str):
    a = _get(assessment_id)
    out = DATA_DIR / assessment_id / "report.pdf"
    generate_report(a, out)
    a.state = "reported"
    audit.append("analyst", "report.generated", assessment=a.id, path=str(out))
    return FileResponse(str(out), media_type="application/pdf", filename=f"VAPT-{a.id}.pdf")


@app.get("/audit")
def get_audit():
    ok, msg = audit.verify()
    return {"ok": ok, "message": msg, "entries": audit.entries()}


@app.get("/integration-matrix")
def matrix():
    from .adapters import integration_matrix
    return integration_matrix()
