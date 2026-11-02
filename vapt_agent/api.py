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

import asyncio
import csv as _csv
import hmac as _hmac
import io as _io
import json as _json
import logging
import re
import threading
import time
import xml.etree.ElementTree as _ET
import zipfile as _zipfile
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import BackgroundTasks, Depends, FastAPI, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import accounts
from . import diff as diffmod
from .audit import AuditLog
from .models import Assessment, Batch, ScopeModel
from .orchestrator import Orchestrator, ScopeError
from .report import generate as generate_report
from .store import AssessmentStore, BatchStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(exist_ok=True)
BOOTSTRAP_MARKER = DATA_DIR / "bootstrap_admin"
SESSION_COOKIE = "vapt_session"

audit = AuditLog(DATA_DIR / "audit.log")
orch = Orchestrator(DATA_DIR, audit)
ASSESSMENTS: dict[str, Assessment] = {}
BATCHES: dict[str, Batch] = {}

# Built in the app lifespan, not at import -- so merely importing this module (e.g. a test) never
# creates data/auth.db or a bootstrap admin on disk. Tests construct their own AccountStore.
account_store: accounts.AccountStore | None = None

# FS-1: same lazy-construction rule as account_store -- importing this module for a test must
# never create data/assessments.db. Tests that want persistence monkeypatch this directly; tests
# that don't care just monkeypatch ASSESSMENTS to a fresh dict and this store is never touched.
assessment_store: AssessmentStore | None = None
batch_store: BatchStore | None = None


def get_store() -> accounts.AccountStore:
    global account_store
    if account_store is None:
        account_store = accounts.AccountStore(DATA_DIR / "auth.db")
        banner = accounts.ensure_bootstrap_admin(account_store, BOOTSTRAP_MARKER)
        if banner:
            logger.warning(banner)
    return account_store


def get_assessment_store() -> AssessmentStore:
    global assessment_store
    if assessment_store is None:
        assessment_store = AssessmentStore(DATA_DIR / "assessments.db")
    return assessment_store


def get_batch_store() -> BatchStore:
    global batch_store
    if batch_store is None:
        batch_store = BatchStore(DATA_DIR / "batches.db")
    return batch_store


def _persist(a: Assessment) -> Assessment:
    """Write-through: called after every mutation to an Assessment already in ASSESSMENTS, so a
    restart can reload it. Persistence failing is never fatal to the request that triggered it --
    the in-memory state (what the response and the rest of this process session see) is already
    correct either way; a persistence failure only risks that one change not surviving a restart,
    which is logged so it isn't silent."""
    try:
        get_assessment_store().save(a)
    except Exception:  # noqa: BLE001 - must never break the request that triggered this save
        logger.warning("failed to persist assessment %s to disk", a.id, exc_info=True)
    return a


@asynccontextmanager
async def lifespan(_app: FastAPI):
    get_store()
    ASSESSMENTS.update(get_assessment_store().load_all())
    BATCHES.update(get_batch_store().load_all())
    yield


app = FastAPI(title="VAPT Agent", version="0.2.0", lifespan=lifespan)

static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/ui", StaticFiles(directory=str(static_dir), html=True), name="ui")


# Defense-in-depth headers, applied to every response. The CSP's 'unsafe-inline' for script/style
# is a deliberate, documented tradeoff -- static/index.html uses inline <script>/<style> blocks and
# onclick="..." attribute handlers (CSP nonces don't cover attribute handlers at all), so blocking
# inline entirely would break the page. The actual XSS defense is that every dynamic value is run
# through esc() before being placed in the DOM (see index.html, tested in tests/frontend/ui.test.js);
# this header is a second layer on top of that, not a replacement for it.
_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
        "form-action 'self'"
    ),
}


@app.middleware("http")
async def _add_security_headers(request: Request, call_next):
    response = await call_next(request)
    for header, value in _SECURITY_HEADERS.items():
        response.headers[header] = value
    return response


# Unauthenticated liveness check for a load balancer / uptime probe -- deliberately reveals nothing
# about assessments, accounts, or scan state, so it carries no auth and no rate limit.
@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


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

# Scoped to the two routes that trigger a real external process (a scan subprocess, or
# Metasploit) -- keyed by the authenticated identity, not the client IP, so it can't be dodged
# by rotating source addresses and doesn't penalize other analysts sharing a NAT'd network.
run_limiter = _SlidingWindowLimiter(max_events=10, window_seconds=60.0)
execute_limiter = _SlidingWindowLimiter(max_events=5, window_seconds=60.0)


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
    return _persist(a)


@app.get("/assessments")
def list_assessments(limit: int = 50, offset: int = 0, state: str | None = None,
                     principal: Principal = Depends(require_role("viewer"))):
    """A3: pagination + basic state filtering, so a deployment with many assessments (meaningful
    now that FS-1 persists them across restarts, not just within one session) doesn't have to
    return its entire history on every call. `limit`/`offset` apply AFTER `state` filtering, newest
    first -- the order a UI actually wants ("show me the most recent N open ones"), not creation
    order sliced blindly."""
    if limit < 1 or limit > 500:
        raise HTTPException(400, "limit must be between 1 and 500")
    if offset < 0:
        raise HTTPException(400, "offset must be >= 0")
    # Newest first by actual creation/insertion order, not a string sort on `created` -- that
    # timestamp only has second precision (models.now()), so several assessments created within
    # the same second (routine in a test, or a batch) would tie, and sorting instead of just
    # reversing insertion order would make `reverse=True`'s documented tie-break ("equal keys
    # keep original relative order") silently put ties oldest-first within the tie, the opposite
    # of what every other row already shows.
    rows = list(reversed(ASSESSMENTS.values()))
    if state is not None:
        if state not in Assessment.model_fields["state"].annotation.__args__:
            raise HTTPException(400, f"state must be one of {Assessment.model_fields['state'].annotation.__args__}")
        rows = [a for a in rows if a.state == state]
    page = rows[offset:offset + limit]
    return {"total": len(rows), "limit": limit, "offset": offset,
           "assessments": [{"id": a.id, "state": a.state, "created": a.created,
                            "created_by": a.created_by, "request": a.request} for a in page]}


@app.get("/assessments/{assessment_id}")
def get_assessment(assessment_id: str, principal: Principal = Depends(require_role("viewer"))):
    return _get(assessment_id)


# ---------------------------------------------------------------------------
# Batches (FS-4): one named group of single-target Assessments created together from one
# multi-target request. See orchestrator.create_batch's docstring for why each target still gets
# its OWN Assessment rather than being merged into a shared one.
# ---------------------------------------------------------------------------

class CreateBatchReq(BaseModel):
    name: str
    request: str
    targets: list[str]
    scope: ScopeModel     # `scope.targets` is ignored -- each member gets exactly one target


def _get_batch(batch_id: str) -> Batch:
    b = BATCHES.get(batch_id)
    if not b:
        raise HTTPException(404, "batch not found")
    return b


def _batch_members(b: Batch) -> list[Assessment]:
    return [ASSESSMENTS[aid] for aid in b.assessment_ids if aid in ASSESSMENTS]


def _batch_summary(members: list[Assessment]) -> dict:
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for a in members:
        for f in a.findings:
            by_severity[f.severity] += 1
    return {"assessments": len(members),
           "assessments_by_state": {s: sum(1 for a in members if a.state == s)
                                     for s in sorted({a.state for a in members})},
           "total_findings": sum(by_severity.values()), "findings_by_severity": by_severity}


@app.post("/batches")
def create_batch(body: CreateBatchReq, principal: Principal = Depends(require_role("analyst"))):
    if not body.targets:
        raise HTTPException(400, "at least one target is required")
    try:
        batch, members = orch.create_batch(body.name, body.request, body.targets, body.scope,
                                           actor=principal.username)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    for a in members:
        ASSESSMENTS[a.id] = a
        _persist(a)
    BATCHES[batch.id] = batch
    try:
        get_batch_store().save(batch)
    except Exception:  # noqa: BLE001 - must never break the request that created the batch
        logger.warning("failed to persist batch %s to disk", batch.id, exc_info=True)
    return {"batch": batch, "assessments": [{"id": a.id, "target": a.scope.targets[0]} for a in members]}


@app.get("/batches")
def list_batches(principal: Principal = Depends(require_role("viewer"))):
    return [{"id": b.id, "name": b.name, "created": b.created, "created_by": b.created_by,
             "assessment_ids": b.assessment_ids, "summary": _batch_summary(_batch_members(b))}
           for b in BATCHES.values()]


@app.get("/batches/{batch_id}")
def get_batch(batch_id: str, principal: Principal = Depends(require_role("viewer"))):
    b = _get_batch(batch_id)
    members = _batch_members(b)
    return {"batch": b,
           "assessments": [{"id": a.id, "target": a.scope.targets[0], "state": a.state,
                            "findings": len(a.findings)} for a in members],
           "summary": _batch_summary(members)}


@app.get("/batches/{batch_id}/export.csv")
def export_batch_csv(batch_id: str, principal: Principal = Depends(require_role("viewer"))):
    """One row per correlated finding across every member assessment, with an extra
    `assessment_id` column -- the FS-3 per-assessment export, concatenated across a batch."""
    b = _get_batch(batch_id)
    members = _batch_members(b)
    buf = _io.StringIO()
    writer = _csv.DictWriter(buf, fieldnames=["assessment_id"] + CSV_FINDING_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for a in members:
        for f in a.findings:
            row = f.model_dump()
            row["assessment_id"] = a.id
            row["cve"] = ";".join(row.get("cve") or [])
            row["source_tools"] = ";".join(row.get("source_tools") or [])
            writer.writerow(row)
    audit.append(principal.username, "export.generated", batch=batch_id, format="csv")
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=VAPT-batch-{batch_id}.csv"})


@app.get("/assessments/{after_id}/diff/{before_id}")
def diff_assessments(after_id: str, before_id: str,
                     principal: Principal = Depends(require_role("viewer"))):
    """New/fixed/persisting findings between two assessments -- a retest workflow, not just a
    one-shot scan. `after_id` should be the later assessment, `before_id` the earlier one."""
    after, before = _get(after_id), _get(before_id)
    return diffmod.compare(before, after)


EVENT_STREAM_POLL_SECONDS = 1.0
_DEFAULT_STREAM_SECONDS = 3600.0   # ~1h; EventSource reconnects on its own once a stream ends


def _sse(event, idx: int) -> str:
    # The id: line lets a client that already rendered the first N events (e.g. from the
    # assessment's own create response) recognize the stream's initial replay of those same
    # events and skip them, rather than rendering every one of them twice.
    return f"id: {idx}\ndata: {_json.dumps(event.model_dump())}\n\n"


@app.get("/assessments/{assessment_id}/stream")
async def stream_events(assessment_id: str, request: Request, max_seconds: float = _DEFAULT_STREAM_SECONDS,
                        # EventSource cannot send custom headers, so a cookie session here can't
                        # carry the usual CSRF header -- safe to skip for this route specifically:
                        # it's read-only (no state change for CSRF to forge), and the session
                        # cookie is SameSite=Strict, so a cross-site page's EventSource wouldn't
                        # even have the cookie attached in the first place. Same exception as
                        # /whoami, for the same underlying reason.
                        principal: Principal = Depends(require_role("viewer", require_csrf=False))):
    """Server-Sent Events for the activity/decision log: replays everything recorded so far, then
    pushes new Events as the orchestrator appends them (notably while a background scan from
    CR-3 is still running), so a judge watching the UI sees the agent's reasoning as it happens
    instead of only after the next full refresh()."""
    a = _get(assessment_id)

    async def gen():
        for i, e in enumerate(a.events):
            yield _sse(e, i)
        sent = len(a.events)
        elapsed = 0.0
        while elapsed < max_seconds:
            if await request.is_disconnected():
                return
            if len(a.events) > sent:
                for i in range(sent, len(a.events)):
                    yield _sse(a.events[i], i)
                sent = len(a.events)
            await asyncio.sleep(EVENT_STREAM_POLL_SECONDS)
            elapsed += EVENT_STREAM_POLL_SECONDS

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/assessments/{assessment_id}/plan/{step_id}/decision")
def decide_step(assessment_id: str, step_id: str, approved: bool,
                principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    step = orch.approve_step(a, step_id, approved, principal.username)
    _persist(a)
    return step


@app.post("/assessments/{assessment_id}/plan/{step_id}/run")
def run_step(assessment_id: str, step_id: str, background_tasks: BackgroundTasks,
            principal: Principal = Depends(require_role("analyst"))):
    """Marks the step running and returns immediately; the scan itself runs in the background
    so the request doesn't block on the subprocess. Poll GET .../runs/{run_id} for completion."""
    if not run_limiter.allow(principal.username):
        raise HTTPException(429, "too many scan requests -- slow down and try again shortly")
    a = _get(assessment_id)
    try:
        run = orch.start_step(a, step_id, actor=principal.username)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    _persist(a)

    def _finish_and_persist():
        orch.finish_step(a, step_id, run.id, principal.username)
        _persist(a)

    background_tasks.add_task(_finish_and_persist)
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
    adapter = orch.adapters.get(tool)
    if adapter is None:
        raise HTTPException(400, f"no adapter registered for tool '{tool}'")
    # B3: reject an obviously wrong-tool file by extension BEFORE reading/writing/parsing it --
    # e.g. a ZAP JSON export posted to the Nmap import route. An empty `import_extensions` means
    # the adapter declared no restriction (checked defensively, but every adapter sets one).
    ext = Path(file.filename or "").suffix.lstrip(".").lower()
    if adapter.import_extensions and ext not in adapter.import_extensions:
        raise HTTPException(400, f"'{tool}' import expects a file extension of "
                                 f"{sorted(adapter.import_extensions)}, got '{ext or '(none)'}'")
    content = await _read_upload_capped(file)
    dest = DATA_DIR / assessment_id / "raw" / _safe_filename(file.filename)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)
    try:
        run = orch.import_result(a, tool, dest, actor=principal.username)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    except (_ET.ParseError, _json.JSONDecodeError) as e:
        raise HTTPException(400, f"could not parse this as a {tool} import: {e}")
    _persist(a)
    return run


@app.post("/assessments/{assessment_id}/analyse")
def analyse(assessment_id: str, principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    # FS-6: every OTHER assessment this process knows about (in-memory, which on a real
    # deployment also means "every assessment persisted to data/assessments.db since FS-1", not
    # just ones created this session) is eligible calibration history.
    history = [other for other in ASSESSMENTS.values() if other.id != a.id]
    result = orch.analyse(a, history=history)
    _persist(a)
    return result


class ApprovalReq(BaseModel):
    finding_id: str
    action: str
    module: str = ""


_REMEDIATION_STATUSES = {"open", "in_progress", "fixed", "retested"}


@app.post("/assessments/{assessment_id}/findings/{finding_id}/remediation")
def set_remediation_status(assessment_id: str, finding_id: str, status: str,
                           principal: Principal = Depends(require_role("analyst"))):
    if status not in _REMEDIATION_STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(_REMEDIATION_STATUSES)}")
    a = _get(assessment_id)
    try:
        f = orch.set_remediation_status(a, finding_id, status, principal.username)
    except StopIteration:
        raise HTTPException(404, "finding not found")
    _persist(a)
    return f


@app.post("/assessments/{assessment_id}/findings/{finding_id}/false-positive")
def set_false_positive(assessment_id: str, finding_id: str, marked: bool, reason: str = "",
                       principal: Principal = Depends(require_role("analyst"))):
    """A9: an explicit analyst verdict, in either direction -- `marked=true` confirms a finding
    as a false positive (whether or not the system's own correlation step already flagged it as
    a candidate), `marked=false` explicitly overturns one that was. Always wins over the
    system's own inference; see `models.is_false_positive()`."""
    a = _get(assessment_id)
    try:
        f = orch.set_false_positive(a, finding_id, marked, principal.username, reason)
    except StopIteration:
        raise HTTPException(404, "finding not found")
    _persist(a)
    return f


@app.post("/assessments/{assessment_id}/approvals")
def request_approval(assessment_id: str, body: ApprovalReq,
                     principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    appr = orch.request_approval(a, body.finding_id, body.action, body.module,
                                 requested_by=principal.username)
    _persist(a)
    return appr


@app.post("/assessments/{assessment_id}/approvals/{approval_id}/decision")
def decide_approval(assessment_id: str, approval_id: str, approved: bool, reason: str = "",
                    principal: Principal = Depends(require_role("lead"))):
    a = _get(assessment_id)
    appr = orch.decide_approval(a, approval_id, approved, principal.username, reason)
    _persist(a)
    return appr


@app.post("/assessments/{assessment_id}/approvals/{approval_id}/execute")
def execute_approval(assessment_id: str, approval_id: str,
                     principal: Principal = Depends(require_role("lead"))):
    if not execute_limiter.allow(principal.username):
        raise HTTPException(429, "too many execution requests -- slow down and try again shortly")
    a = _get(assessment_id)
    try:
        run = orch.execute_approval(a, approval_id, executed_by=principal.username)
    except ScopeError as e:
        raise HTTPException(400, str(e))
    _persist(a)
    return run


@app.post("/assessments/{assessment_id}/report")
def report(assessment_id: str, principal: Principal = Depends(require_role("analyst"))):
    a = _get(assessment_id)
    out = DATA_DIR / assessment_id / "report.pdf"
    generate_report(a, out)
    a.state = "reported"
    _persist(a)
    audit.append(principal.username, "report.generated", assessment=a.id, path=str(out))
    return FileResponse(str(out), media_type="application/pdf", filename=f"VAPT-{a.id}.pdf")


# FS-3: JSON/CSV export alongside the PDF report. The PDF is the mandatory PS-7 deliverable
# (narrative, impact, remediation); these exist for a judge/analyst who wants the finding data in a
# machine-readable form -- to pipe into a ticketing system, a spreadsheet, or another report
# template -- without re-deriving it from the PDF. Read-only, so viewer role is enough, same as
# GET /assessments/{id} which already returns the same underlying data as inline JSON.
CSV_FINDING_COLUMNS = ["id", "title", "asset", "port", "proto", "service", "severity", "cvss",
                      "cve", "confidence", "status", "validation_status", "remediation_status",
                      "risk_score", "priority", "source_tools"]


@app.get("/assessments/{assessment_id}/export.json")
def export_json(assessment_id: str, principal: Principal = Depends(require_role("viewer"))):
    a = _get(assessment_id)
    audit.append(principal.username, "export.generated", assessment=a.id, format="json")
    return Response(a.model_dump_json(indent=2), media_type="application/json",
                    headers={"Content-Disposition": f"attachment; filename=VAPT-{assessment_id}.json"})


@app.get("/assessments/{assessment_id}/export.csv")
def export_csv(assessment_id: str, principal: Principal = Depends(require_role("viewer"))):
    """One row per correlated finding -- the same `findings` list the PDF report renders,
    not the pre-correlation `raw_findings`, so the row count matches what the report shows."""
    a = _get(assessment_id)
    buf = _io.StringIO()
    writer = _csv.DictWriter(buf, fieldnames=CSV_FINDING_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for f in a.findings:
        row = f.model_dump()
        row["cve"] = ";".join(row.get("cve") or [])
        row["source_tools"] = ";".join(row.get("source_tools") or [])
        writer.writerow(row)
    audit.append(principal.username, "export.generated", assessment=a.id, format="csv")
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=VAPT-{assessment_id}.csv"})


def _scoped_audit_entries(assessment_id: str) -> list[dict]:
    return [e for e in audit.entries() if e.get("details", {}).get("assessment") == assessment_id]


@app.post("/assessments/{assessment_id}/evidence-pack")
def evidence_pack(assessment_id: str, principal: Principal = Depends(require_role("analyst"))):
    """A zip of this assessment's audit trail, raw tool outputs, and PDF report -- independently
    verifiable by someone who wasn't in the room for the live demo, without re-running anything."""
    a = _get(assessment_id)
    report_path = DATA_DIR / assessment_id / "report.pdf"
    generate_report(a, report_path)

    buf = _io.BytesIO()
    with _zipfile.ZipFile(buf, "w", _zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("assessment.json", a.model_dump_json(indent=2))
        zf.writestr("audit_log.json", _json.dumps(_scoped_audit_entries(assessment_id), indent=2))
        zf.write(report_path, arcname="report.pdf")
        raw_dir = DATA_DIR / assessment_id / "raw"
        if raw_dir.exists():
            for f in sorted(raw_dir.iterdir()):
                if f.is_file():
                    zf.write(f, arcname=f"raw/{f.name}")
    audit.append(principal.username, "evidence_pack.generated", assessment=a.id)
    return Response(buf.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": f"attachment; filename=evidence-pack-{assessment_id}.zip"})


@app.get("/audit")
def get_audit(assessment_id: str | None = None, principal: Principal = Depends(require_role("viewer"))):
    """`assessment_id` narrows the returned entries to one assessment -- for the audit-trail
    replay view (CA-2): "what did the agent decide, and why" for a single assessment, without
    the rest of the server's traffic in the way. The hash-chain is always verified against the
    *full* log regardless of the filter, since that's what the chain actually protects."""
    ok, msg = audit.verify()
    entries = _scoped_audit_entries(assessment_id) if assessment_id else audit.entries()
    return {"ok": ok, "message": msg, "entries": entries}


@app.get("/integration-matrix")
def matrix():
    from .adapters import integration_matrix
    return integration_matrix()
