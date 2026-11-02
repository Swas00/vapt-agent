"""FastAPI backend: conversational request -> scope validation -> plan -> approve/run -> analyse ->
human approval for active validation -> report. State lives in-memory per Assessment, persisted to
./data/<id>/ and the audit log under ./data/audit.log.

Authentication: real accounts (vapt_agent/accounts.py) -- username/password, scrypt-hashed,
server-side sessions. A session is presented either as an HttpOnly cookie (the web UI) or an
explicit `Authorization: Bearer <session id>` header (scripts). Every route but the handful of
public ones (static UI, the integration matrix, OpenAPI docs, login) depends on `require_role`,
which resolves the session to a verified (username, role) -- never anything the client claims --
and checks CSRF + same-origin for the cookie path, since a bearer header can't be forged by a
cross-site page the way a cookie can. Roles are ordered viewer < analyst < lead < admin: requesting
active validation needs `analyst`, but *approving or executing* it needs `lead` -- a real
separation of duties, not just "any logged-in person."
"""
from __future__ import annotations

import hmac as _hmac
import json as _json
import re
import sys
import threading
import time
import xml.etree.ElementTree as _ET
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import accounts
from .audit import AuditLog
from .models import Assessment, ScopeModel
from .orchestrator import Orchestrator, ScopeError
from .report import generate as generate_report

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
BOOTSTRAP_MARKER = DATA_DIR / "bootstrap_admin"
SESSION_COOKIE = "vapt_session"

audit = AuditLog(DATA_DIR / "audit.log")
orch = Orchestrator(DATA_DIR, audit)
ASSESSMENTS: dict[str, Assessment] = {}

# Built in the app lifespan, not at import -- so merely importing this module (e.g. a test) never
# creates data/auth.db or a bootstrap admin on disk. Tests construct their own AccountStore.
account_store: accounts.AccountStore | None = None


def get_store() -> accounts.AccountStore:
    global account_store
    if account_store is None:
        account_store = accounts.AccountStore(DATA_DIR / "auth.db")
        banner = accounts.ensure_bootstrap_admin(account_store, BOOTSTRAP_MARKER)
        if banner:
            print(banner, file=sys.stderr)
    return account_store


@asynccontextmanager
async def lifespan(_app: FastAPI):
    get_store()
    yield


app = FastAPI(title="VAPT Agent", version="0.2.0", lifespan=lifespan)

static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")


# ---------------------------------------------------------------------------
# Rate limiting / noise control around authentication (transport-level concerns, not account
# storage, so these live here rather than in accounts.py)
# ---------------------------------------------------------------------------

class _SlidingWindowLimiter:
    """At most `max_events` within `window` seconds, per key. Used to throttle login attempts
    per client IP -- per-account lockout alone doesn't stop one guess each against many usernames."""

    def __init__(self, max_events: int, window_seconds: float):
        self.max_events, self.window = max_events, window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if now - t < self.window]
            if len(hits) >= self.max_events:
                self._hits[key] = hits
                return False
            hits.append(now)
            self._hits[key] = hits
            return True


class _FailureLogThrottle:
    """At most one audit entry per client per `window` seconds, with a bounded tracking table, so
    unauthenticated traffic can't grow the append-only audit log without bound."""

    def __init__(self, window_seconds: float = 60.0, max_clients: int = 1024):
        self.window, self.max_clients = window_seconds, max_clients
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def should_log(self, key: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            last = self._seen.get(key)
            if last is not None and now - last < self.window:
                return False
            if len(self._seen) >= self.max_clients:
                oldest = min(self._seen, key=self._seen.get)
                del self._seen[oldest]
            self._seen[key] = now
            return True


login_limiter = _SlidingWindowLimiter(max_events=15, window_seconds=300.0)
_auth_failure_throttle = _FailureLogThrottle()


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _same_origin(origin: str, request: Request) -> bool:
    o = urlsplit(origin)
    return (o.scheme, o.hostname, o.port) == (request.url.scheme, request.url.hostname, request.url.port)


# ---------------------------------------------------------------------------
# Session resolution / RBAC
# ---------------------------------------------------------------------------

@dataclass
class Principal:
    username: str
    role: str
    session_id: str
    via_cookie: bool


def require_role(min_role: str, allow_pending_password_change: bool = False, require_csrf: bool = True):
    """Dependency factory. `min_role` is checked with accounts.role_at_least(). A session presented
    as a bearer header skips CSRF/origin checks (a cross-site page cannot set a custom header the
    way it can attach a cookie); a session presented as the cookie must also pass the CSRF-header
    and same-origin checks, unless `require_csrf=False` (used only by /whoami, so a page reload can
    recover its CSRF token from the cookie alone before it has one to send)."""

    def dependency(request: Request) -> Principal:
        store = get_store()
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            session_id, via_cookie = auth_header[7:].strip(), False
        else:
            session_id, via_cookie = request.cookies.get(SESSION_COOKIE), True

        info = store.validate_session(session_id) if session_id else None
        if info is None:
            client = _client_ip(request)
            if _auth_failure_throttle.should_log(client):
                audit.append("system", "auth.rejected", method=request.method,
                             path=request.url.path[:200], client=client,
                             reason="missing or invalid session")
            raise HTTPException(401, "authentication required: sign in, or send "
                                "'Authorization: Bearer <session id>'",
                                headers={"WWW-Authenticate": "Bearer"})

        if via_cookie:
            if require_csrf:
                presented = request.headers.get("x-csrf-token", "")
                if not _hmac.compare_digest(presented, info.csrf_token):
                    raise HTTPException(403, "missing or invalid CSRF token")
            origin = request.headers.get("origin")
            if origin and not _same_origin(origin, request):
                raise HTTPException(403, "cross-origin request rejected")

        if info.user.must_change_password and not allow_pending_password_change:
            raise HTTPException(403, "password change required",
                                headers={"X-Password-Change-Required": "true"})
        if not accounts.role_at_least(info.user.role, min_role):
            raise HTTPException(403, f"requires role '{min_role}' or higher (you have '{info.user.role}')")

        return Principal(username=info.user.username, role=info.user.role,
                         session_id=session_id, via_cookie=via_cookie)

    return dependency


def _get(assessment_id: str) -> Assessment:
    a = ASSESSMENTS.get(assessment_id)
    if not a:
        raise HTTPException(404, "assessment not found")
    return a


def _safe_filename(name: str | None) -> str:
    """Reduce a client-supplied upload name to a plain basename of safe characters, so it can
    never steer the write outside the assessment's raw/ directory ('../../x', absolute paths)."""
    base = Path((name or "").replace("\\", "/")).name
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    return cleaned[:120] or "upload"


MAX_UPLOAD_BYTES = 25 * 1024 * 1024
_UPLOAD_CHUNK_SIZE = 1024 * 1024


async def _read_upload_capped(file: UploadFile, max_bytes: int = MAX_UPLOAD_BYTES) -> bytes:
    """Read an upload in chunks, rejecting with 413 the moment the cap is crossed -- rather
    than buffering the whole body first and checking after, which defeats the point of a cap."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(_UPLOAD_CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(413, f"upload exceeds the {max_bytes // (1024 * 1024)}MB limit")
        chunks.append(chunk)
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------

class LoginReq(BaseModel):
    username: str
    password: str


class LoginResp(BaseModel):
    username: str
    role: str
    must_change_password: bool
    csrf_token: str


@app.post("/login", response_model=LoginResp)
def login(body: LoginReq, request: Request, response: Response):
    store = get_store()
    client = _client_ip(request)
    if not login_limiter.allow(client):
        raise HTTPException(429, "too many login attempts from this address; try again shortly")
    try:
        user = store.authenticate(body.username, body.password)
    except accounts.LockedOutError as e:
        audit.append("system", "auth.login_locked", attempted_username=body.username, client=client)
        raise HTTPException(423, str(e))
    except accounts.LoginError as e:
        audit.append("system", "auth.login_failed", attempted_username=body.username, client=client)
        raise HTTPException(401, str(e))

    session_id, info = store.create_session(user.id)
    response.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict",
                        secure=(request.url.scheme == "https"),
                        max_age=int(accounts.SESSION_ABSOLUTE_TIMEOUT.total_seconds()), path="/")
    audit.append(user.username, "auth.login", client=client)
    return LoginResp(username=user.username, role=user.role,
                     must_change_password=user.must_change_password, csrf_token=info.csrf_token)


@app.get("/whoami", response_model=LoginResp)
def whoami(response: Response, principal: Principal = Depends(
    require_role("viewer", allow_pending_password_change=True, require_csrf=False))):
    """Validates the current session (cookie or bearer) and returns the identity + a CSRF token --
    the one endpoint a page reload can call with the cookie alone, before it has a CSRF token to
    send anywhere else."""
    store = get_store()
    info = store.validate_session(principal.session_id)
    if info is None:
        raise HTTPException(401, "session no longer valid")
    return LoginResp(username=info.user.username, role=info.user.role,
                     must_change_password=info.user.must_change_password, csrf_token=info.csrf_token)


@app.post("/logout")
def logout(response: Response, principal: Principal = Depends(
    require_role("viewer", allow_pending_password_change=True))):
    store = get_store()
    store.revoke_session(principal.session_id)
    response.delete_cookie(SESSION_COOKIE, path="/")
    audit.append(principal.username, "auth.logout")
    return {"ok": True}


@app.post("/logout-all")
def logout_all(principal: Principal = Depends(require_role("viewer", allow_pending_password_change=True))):
    store = get_store()
    store.revoke_all_sessions(principal.username, except_session_id=principal.session_id)
    audit.append(principal.username, "auth.logout_all")
    return {"ok": True}


class ChangePasswordReq(BaseModel):
    current_password: str
    new_password: str


@app.post("/change-password")
def change_password(body: ChangePasswordReq,
                    principal: Principal = Depends(require_role("viewer", allow_pending_password_change=True))):
    store = get_store()
    user = store.get_user(principal.username)
    try:
        store.change_own_password(user.id, body.current_password, body.new_password)
    except accounts.LoginError as e:
        raise HTTPException(401, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    store.revoke_all_sessions(principal.username, except_session_id=principal.session_id)
    audit.append(principal.username, "auth.password_changed")
    return {"ok": True}


# ---------------------------------------------------------------------------
# Admin: account management
# ---------------------------------------------------------------------------

class CreateUserReq(BaseModel):
    username: str
    password: str
    role: str


@app.post("/admin/users")
def admin_create_user(body: CreateUserReq, principal: Principal = Depends(require_role("admin"))):
    store = get_store()
    try:
        u = store.create_user(body.username, body.password, body.role, must_change_password=True)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit.append(principal.username, "admin.user_created", target_user=u.username, role=u.role)
    return {"username": u.username, "role": u.role, "must_change_password": u.must_change_password}


@app.get("/admin/users")
def admin_list_users(principal: Principal = Depends(require_role("admin"))):
    store = get_store()
    return [{"username": u.username, "role": u.role, "disabled": u.disabled,
             "must_change_password": u.must_change_password} for u in store.list_users()]


@app.post("/admin/users/{username}/role")
def admin_set_role(username: str, role: str, principal: Principal = Depends(require_role("admin"))):
    store = get_store()
    try:
        store.set_role(username, role)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit.append(principal.username, "admin.role_changed", target_user=username, role=role)
    return {"ok": True}


@app.post("/admin/users/{username}/disable")
def admin_disable(username: str, disabled: bool = True, principal: Principal = Depends(require_role("admin"))):
    if username == principal.username and disabled:
        raise HTTPException(400, "cannot disable your own account")
    store = get_store()
    try:
        store.set_disabled(username, disabled)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit.append(principal.username, "admin.user_disabled" if disabled else "admin.user_enabled",
                target_user=username)
    return {"ok": True}


@app.post("/admin/users/{username}/unlock")
def admin_unlock(username: str, principal: Principal = Depends(require_role("admin"))):
    store = get_store()
    try:
        store.unlock(username)
    except ValueError as e:
        raise HTTPException(400, str(e))
    audit.append(principal.username, "admin.unlocked", target_user=username)
    return {"ok": True}


@app.post("/admin/users/{username}/reset-password")
def admin_reset_password(username: str, principal: Principal = Depends(require_role("admin"))):
    """Issues a new temporary password (forcing a change at next login) and returns it once --
    the admin relays it to the user out-of-band. Also revokes all of that user's sessions."""
    store = get_store()
    try:
        temp = store.admin_reset_password(username)
    except ValueError as e:
        raise HTTPException(400, str(e))
    store.revoke_all_sessions(username)
    audit.append(principal.username, "admin.password_reset", target_user=username)
    return {"temporary_password": temp}


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------

class CreateReq(BaseModel):
    request: str
    scope: ScopeModel


@app.post("/assessments")
def create_assessment(body: CreateReq, principal: Principal = Depends(require_role("analyst"))):
    try:
        a = orch.create(body.request, body.scope, actor=principal.username)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    ASSESSMENTS[a.id] = a
    return a


@app.get("/assessments")
def list_assessments(principal: Principal = Depends(require_role("viewer"))):
    return [{"id": a.id, "state": a.state, "created": a.created, "created_by": a.created_by,
             "request": a.request} for a in ASSESSMENTS.values()]


@app.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str, principal: Principal = Depends(require_role("viewer"))):
    return _get(assessment_id)


@app.post("/assessments/{assessment_id}/plan/{step_id}/decision")
def decide_step(assessment_id: str, step_id: str, approved: bool,
                principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    return orch.approve_step(a, step_id, approved, principal.username)


@app.post("/assessments/{assessment_id}/plan/{step_id}/run")
def run_step(assessment_id: str, step_id: str, background_tasks: BackgroundTasks,
            principal: Principal = Depends(require_role("analyst"))):
    """Marks the step running and returns immediately; the scan itself runs in the background
    so the request doesn't block on the subprocess. Poll GET .../runs/{run_id} for completion."""
    a = _get(assessment_id)
    try:
        run = orch.start_step(a, step_id, actor=principal.username)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    background_tasks.add_task(orch.finish_step, a, step_id, run.id, principal.username)
    return run


@app.get("/assessments/{assessment_id}/runs/{run_id}")
def get_run(assessment_id: str, run_id: str, principal: Principal = Depends(require_role("viewer"))):
    a = _get(assessment_id)
    run = next((r for r in a.runs if r.id == run_id), None)
    if run is None:
        raise HTTPException(404, "run not found")
    return run


@app.post("/assessments/{assessment_id}/import/{tool}")
async def import_result(assessment_id: str, tool: str, file: UploadFile = File(...),
                        principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    content = await _read_upload_capped(file)
    dest = DATA_DIR / assessment_id / "raw" / _safe_filename(file.filename)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    try:
        return orch.import_result(a, tool, dest, actor=principal.username)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    except (_ET.ParseError, _json.JSONDecodeError) as e:
        raise HTTPException(400, f"could not parse this as a {tool} import: {e}")


@app.post("/assessments/{assessment_id}/analyse")
def analyse(assessment_id: str, principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    return orch.analyse(a)


class ApprovalReq(BaseModel):
    finding_id: str
    action: str
    module: str = ""


@app.post("/assessments/{assessment_id}/approvals")
def request_approval(assessment_id: str, body: ApprovalReq,
                     principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    return orch.request_approval(a, body.finding_id, body.action, body.module,
                                 requested_by=principal.username)


@app.post("/assessments/{assessment_id}/approvals/{approval_id}/decision")
def decide_approval(assessment_id: str, approval_id: str, approved: bool, reason: str = "",
                    principal: Principal = Depends(require_role("lead"))):
    a = _get(assessment_id)
    return orch.decide_approval(a, approval_id, approved, principal.username, reason)


@app.post("/assessments/{assessment_id}/approvals/{approval_id}/execute")
def execute_approval(assessment_id: str, approval_id: str,
                     principal: Principal = Depends(require_role("lead"))):
    a = _get(assessment_id)
    try:
        return orch.execute_approval(a, approval_id, executed_by=principal.username)
    except ScopeError as e:
        raise HTTPException(400, str(e))


@app.post("/assessments/{assessment_id}/report")
def report(assessment_id: str, principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    out = DATA_DIR / assessment_id / "report.pdf"
    generate_report(a, out)
    a.state = "reported"
    audit.append(principal.username, "report.generated", assessment=a.id, path=str(out))
    return FileResponse(str(out), media_type="application/pdf", filename=f"VAPT-{a.id}.pdf")


@app.get("/audit")
def get_audit(principal: Principal = Depends(require_role("viewer"))):
    ok, msg = audit.verify()
    return {"ok": ok, "message": msg, "entries": audit.entries()}


@app.get("/integration-matrix")
def matrix():
    from .adapters import integration_matrix
    return integration_matrix()
