"""HTTP-level tests for real login (username/password -> session cookie, CSRF, roles), run through
FastAPI's TestClient -- i.e. real routing, dependency injection, cookie handling, and serialization.

Properties under test:
  * every protected route rejects a missing/invalid session with 401;
  * cookie-authenticated mutating calls need a matching CSRF header, bearer-authenticated ones don't;
  * role is enforced per route, and "lead" is genuinely required to approve/execute active
    validation -- an "analyst" is blocked even with a perfectly valid session;
  * the identity written to the audit log and approval records is the session's owner, never a
    value the client sent;
  * login lockout, rate limiting, must-change-password gating, and logout/logout-all all behave;
  * a future POST route added without the guard fails the meta-test below.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from vapt_agent import accounts, api
from vapt_agent.audit import AuditLog
from vapt_agent.models import ToolRun
from vapt_agent.orchestrator import Orchestrator

FIX = Path(__file__).parent / "fixtures"
GOOD_PW = "correct-horse-battery-1"
CREATE_BODY = {"request": "audit test", "scope": {"targets": ["10.10.10.5"], "lab_attestation": True,
                                                  "allow_active_validation": True}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    """The real app, with state redirected to a temp dir and three known accounts."""
    audit = AuditLog(tmp_path / "audit.log")
    monkeypatch.setattr(api, "DATA_DIR", tmp_path)
    monkeypatch.setattr(api, "audit", audit)
    monkeypatch.setattr(api, "orch", Orchestrator(tmp_path, audit))
    monkeypatch.setattr(api, "ASSESSMENTS", {})
    store = accounts.AccountStore(tmp_path / "auth.db")
    store.create_user("alice", GOOD_PW, "analyst")
    store.create_user("bob", GOOD_PW, "lead")
    store.create_user("carol", GOOD_PW, "admin")
    store.create_user("victor", GOOD_PW, "viewer")
    monkeypatch.setattr(api, "account_store", store)
    monkeypatch.setattr(api, "login_limiter", api._SlidingWindowLimiter(max_events=15, window_seconds=300.0))
    monkeypatch.setattr(api, "_auth_failure_throttle", api._FailureLogThrottle())
    client = TestClient(api.app)

    class Env:
        pass
    e = Env()
    e.client, e.audit, e.tmp, e.store = client, audit, tmp_path, store
    e.entries = lambda action=None: [x for x in audit.entries() if action is None or x["action"] == action]
    return e


def login(env, username, password=GOOD_PW):
    r = env.client.post("/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


def session(env, username, password=GOOD_PW):
    """Returns (headers_with_csrf,) for a logged-in client -- TestClient keeps cookies itself."""
    body = login(env, username, password)
    return {"X-CSRF-Token": body["csrf_token"]}


def create_assessment(env, username="alice") -> dict:
    hdr = session(env, username)
    r = env.client.post("/assessments", json=CREATE_BODY, headers=hdr)
    assert r.status_code == 200, r.text
    return r.json()


def import_nessus(env, assessment_id, hdr, filename="n.nessus"):
    data = (FIX / "nessus_sample.nessus").read_bytes()
    return env.client.post(f"/assessments/{assessment_id}/import/nessus", headers=hdr,
                           files={"file": (filename, data, "application/xml")})


# ---- login -------------------------------------------------------------------------------------

def test_login_success_sets_httponly_samesite_cookie_and_returns_csrf(env):
    r = env.client.post("/login", json={"username": "alice", "password": GOOD_PW})
    assert r.status_code == 200
    body = r.json()
    assert body["username"] == "alice" and body["role"] == "analyst" and body["csrf_token"]
    cookie = next(c for c in r.headers.get_list("set-cookie") if c.startswith(api.SESSION_COOKIE + "="))
    assert "httponly" in cookie.lower()
    assert "samesite=strict" in cookie.lower()
    assert "secure" not in cookie.lower()          # plain http in tests -- must not be marked Secure


def test_login_wrong_password_401_generic_message(env):
    r = env.client.post("/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 401
    assert "invalid username or password" in r.text


def test_login_unknown_username_same_message_as_wrong_password(env):
    r1 = env.client.post("/login", json={"username": "alice", "password": "wrong"})
    r2 = env.client.post("/login", json={"username": "ghost", "password": "wrong"})
    assert r1.json()["detail"] == r2.json()["detail"]


def test_login_failures_are_audited_without_a_verified_actor(env):
    env.client.post("/login", json={"username": "alice", "password": "wrong"})
    entry = env.entries("auth.login_failed")[0]
    assert entry["actor"] == "system" and entry["details"]["attempted_username"] == "alice"


def test_successful_login_is_audited_as_the_real_user(env):
    login(env, "alice")
    assert env.entries("auth.login")[0]["actor"] == "alice"


def test_lockout_returns_423_and_is_audited(env):
    for _ in range(accounts.LOCKOUT_THRESHOLD + 1):
        env.client.post("/login", json={"username": "alice", "password": "wrong"})
    r = env.client.post("/login", json={"username": "alice", "password": "wrong"})
    assert r.status_code == 423
    assert env.entries("auth.login_locked")

    r2 = env.client.post("/login", json={"username": "alice", "password": GOOD_PW})
    assert r2.status_code == 423                    # correct password still rejected while locked


def test_login_rate_limited_per_client_across_usernames(env):
    for i in range(15):
        env.client.post("/login", json={"username": f"user{i}", "password": "x" * 12 + "wrong"})
    r = env.client.post("/login", json={"username": "alice", "password": GOOD_PW})
    assert r.status_code == 429


# ---- session resolution: cookie vs bearer, 401 shapes ---------------------------------------------

def test_protected_route_without_any_session_is_401(env):
    r = env.client.post("/assessments", json=CREATE_BODY)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


def test_bearer_session_works_without_a_csrf_header(env):
    login(env, "alice")
    session_id = env.client.cookies.get(api.SESSION_COOKIE)
    fresh = TestClient(api.app)              # a client with no cookie jar / prior state at all
    r = fresh.get("/whoami", headers={"Authorization": f"Bearer {session_id}"})
    assert r.status_code == 200 and r.json()["username"] == "alice"
    r2 = fresh.post("/assessments", json=CREATE_BODY, headers={"Authorization": f"Bearer {session_id}"})
    assert r2.status_code == 200, r2.text            # no CSRF header needed for the bearer path


def test_cookie_session_without_csrf_header_is_403(env):
    login(env, "alice")
    r = env.client.post("/assessments", json=CREATE_BODY)       # cookie present, no X-CSRF-Token
    assert r.status_code == 403
    assert "csrf" in r.text.lower()


def test_cookie_session_with_wrong_csrf_header_is_403(env):
    login(env, "alice")
    r = env.client.post("/assessments", json=CREATE_BODY, headers={"X-CSRF-Token": "not-the-real-one"})
    assert r.status_code == 403


def test_csrf_tokens_are_not_interchangeable_across_sessions(env):
    c1, c2 = TestClient(api.app), TestClient(api.app)
    body1 = c1.post("/login", json={"username": "alice", "password": GOOD_PW}).json()
    c2.post("/login", json={"username": "bob", "password": GOOD_PW})
    r = c2.post("/assessments", json=CREATE_BODY, headers={"X-CSRF-Token": body1["csrf_token"]})
    assert r.status_code == 403


def test_cross_origin_cookie_request_rejected(env):
    hdr = session(env, "alice")
    hdr["Origin"] = "https://evil.example.com"
    r = env.client.post("/assessments", json=CREATE_BODY, headers=hdr)
    assert r.status_code == 403
    assert "origin" in r.text.lower()


def test_same_origin_cookie_request_with_origin_header_is_fine(env):
    hdr = session(env, "alice")
    hdr["Origin"] = str(env.client.base_url)
    r = env.client.post("/assessments", json=CREATE_BODY, headers=hdr)
    assert r.status_code == 200


def test_invalid_scheme_or_malformed_bearer_rejected(env):
    for header in [{"Authorization": "Basic xxx"}, {"Authorization": "Bearer"}, {"Authorization": "Bearer "}]:
        assert env.client.post("/assessments", json=CREATE_BODY, headers=header).status_code == 401


def test_auth_checked_before_resource_lookup(env):
    assert env.client.post("/assessments/does-not-exist/analyse").status_code == 401
    hdr = session(env, "alice")
    assert env.client.post("/assessments/does-not-exist/analyse", headers=hdr).status_code == 404


def test_unauthenticated_failures_are_audited_and_throttled_without_leaking_anything_secret(env):
    for _ in range(4):
        env.client.post("/assessments", json=CREATE_BODY)
    rejected = env.entries("auth.rejected")
    assert len(rejected) == 1                        # throttled, not one-per-request
    assert rejected[0]["actor"] == "system"
    assert rejected[0]["details"]["path"] == "/assessments"


# ---- logout / logout-all / change-password -------------------------------------------------------

def test_logout_invalidates_the_session_and_clears_the_cookie(env):
    hdr = session(env, "alice")
    r = env.client.post("/logout", headers=hdr)
    assert r.status_code == 200
    assert "vapt_session=" in r.headers.get("set-cookie", "") and "Max-Age=0" in r.headers["set-cookie"]
    assert env.client.post("/assessments", json=CREATE_BODY, headers=hdr).status_code == 401


def test_logout_all_revokes_other_sessions_but_not_the_current_one(env):
    c1, c2 = TestClient(api.app), TestClient(api.app)
    b1 = c1.post("/login", json={"username": "alice", "password": GOOD_PW}).json()
    b2 = c2.post("/login", json={"username": "alice", "password": GOOD_PW}).json()
    c1.post("/logout-all", headers={"X-CSRF-Token": b1["csrf_token"]})
    assert c1.get("/whoami", headers={"X-CSRF-Token": b1["csrf_token"]}).status_code == 200
    assert c2.get("/whoami", headers={"X-CSRF-Token": b2["csrf_token"]}).status_code == 401


def test_change_password_requires_correct_current_password(env):
    hdr = session(env, "alice")
    r = env.client.post("/change-password", json={"current_password": "wrong", "new_password": "a-new-strong-pw-1"},
                        headers=hdr)
    assert r.status_code == 401


def test_change_password_rejects_weak_new_password(env):
    hdr = session(env, "alice")
    r = env.client.post("/change-password", json={"current_password": GOOD_PW, "new_password": "short"}, headers=hdr)
    assert r.status_code == 400


def test_change_password_revokes_other_sessions_but_not_the_current_one(env):
    c1, c2 = TestClient(api.app), TestClient(api.app)
    b1 = c1.post("/login", json={"username": "alice", "password": GOOD_PW}).json()
    b2 = c2.post("/login", json={"username": "alice", "password": GOOD_PW}).json()
    r = c1.post("/change-password", headers={"X-CSRF-Token": b1["csrf_token"]},
               json={"current_password": GOOD_PW, "new_password": "a-new-strong-pw-1"})
    assert r.status_code == 200
    assert c1.get("/whoami", headers={"X-CSRF-Token": b1["csrf_token"]}).status_code == 200
    assert c2.get("/whoami", headers={"X-CSRF-Token": b2["csrf_token"]}).status_code == 401
    # old password no longer works, new one does
    assert c1.post("/login", json={"username": "alice", "password": GOOD_PW}).status_code == 401
    assert c1.post("/login", json={"username": "alice", "password": "a-new-strong-pw-1"}).status_code == 200


def test_must_change_password_blocks_other_routes_until_changed(env):
    env.store.create_user("dave", GOOD_PW, "analyst", must_change_password=True)
    hdr = session(env, "dave")
    r = env.client.post("/assessments", json=CREATE_BODY, headers=hdr)
    assert r.status_code == 403
    assert r.headers.get("x-password-change-required") == "true"
    # but /whoami, /change-password, /logout are reachable to actually complete the flow
    assert env.client.get("/whoami", headers=hdr).status_code == 200
    r2 = env.client.post("/change-password", headers=hdr,
                         json={"current_password": GOOD_PW, "new_password": "a-new-strong-pw-1"})
    assert r2.status_code == 200
    hdr2 = session(env, "dave", "a-new-strong-pw-1")
    assert env.client.post("/assessments", json=CREATE_BODY, headers=hdr2).status_code == 200


# ---- RBAC: the separation of duties on active validation -------------------------------------------

def test_meta_every_mutating_route_requires_a_role(env):
    for r in api.app.routes:
        if isinstance(r, APIRoute) and "POST" in r.methods and r.path != "/login":
            assert any(d.call.__name__ == "dependency" for d in r.dependant.dependencies), r.path


def test_analyst_can_request_but_not_decide_or_execute_approval(env):
    a = create_assessment(env, "alice")
    alice_hdr = session(env, "alice")
    assert import_nessus(env, a["id"], alice_hdr).status_code == 200
    assert env.client.post(f"/assessments/{a['id']}/analyse", headers=alice_hdr).status_code == 200
    finding = next(f for f in env.client.get(f"/assessments/{a['id']}", headers=alice_hdr).json()["findings"]
                   if f["severity"] in ("critical", "high"))

    appr = env.client.post(f"/assessments/{a['id']}/approvals", headers=alice_hdr,
                           json={"finding_id": finding["id"], "action": "validate"}).json()
    assert appr["requested_by"] == "alice"

    # an analyst (not a lead) is blocked from deciding or executing
    r = env.client.post(f"/assessments/{a['id']}/approvals/{appr['id']}/decision?approved=true",
                        headers=alice_hdr)
    assert r.status_code == 403 and "lead" in r.text

    bob_hdr = session(env, "bob")
    decided = env.client.post(f"/assessments/{a['id']}/approvals/{appr['id']}/decision?approved=true",
                              headers=bob_hdr).json()
    assert decided["state"] == "approved" and decided["decided_by"] == "bob"

    r2 = env.client.post(f"/assessments/{a['id']}/approvals/{appr['id']}/execute", headers=alice_hdr)
    assert r2.status_code == 403

    env.client.post(f"/assessments/{a['id']}/approvals/{appr['id']}/execute", headers=bob_hdr)
    final = env.client.get(f"/assessments/{a['id']}", headers=bob_hdr).json()["approvals"][0]
    assert (final["requested_by"], final["decided_by"], final["executed_by"]) == ("alice", "bob", "bob")
    ok, msg = env.audit.verify()
    assert ok, msg


def test_viewer_can_read_but_not_create(env):
    a = create_assessment(env, "alice")
    viewer_hdr = session(env, "victor")
    assert env.client.get(f"/assessments/{a['id']}", headers=viewer_hdr).status_code == 200
    assert env.client.get("/audit", headers=viewer_hdr).status_code == 200
    r = env.client.post("/assessments", json=CREATE_BODY, headers=viewer_hdr)
    assert r.status_code == 403 and "analyst" in r.text


def test_admin_routes_require_admin_role(env):
    alice_hdr = session(env, "alice")
    r = env.client.post("/admin/users", json={"username": "x", "password": GOOD_PW, "role": "viewer"},
                        headers=alice_hdr)
    assert r.status_code == 403

    carol_hdr = session(env, "carol")
    r2 = env.client.post("/admin/users", json={"username": "newbie", "password": "a-strong-pw-123", "role": "analyst"},
                         headers=carol_hdr)
    assert r2.status_code == 200 and r2.json()["must_change_password"] is True

    listed = env.client.get("/admin/users", headers=carol_hdr).json()
    assert any(u["username"] == "newbie" for u in listed)
    assert not any("password" in u for u in listed)      # never exposes hashes

    env.client.post("/admin/users/newbie/role?role=lead", headers=carol_hdr)
    assert env.store.get_user("newbie").role == "lead"

    reset = env.client.post("/admin/users/newbie/reset-password", headers=carol_hdr).json()
    assert env.store.authenticate("newbie", reset["temporary_password"]).must_change_password

    env.client.post("/admin/users/newbie/disable?disabled=true", headers=carol_hdr)
    assert env.store.get_user("newbie").disabled is True


def test_admin_cannot_disable_self(env):
    carol_hdr = session(env, "carol")
    r = env.client.post("/admin/users/carol/disable?disabled=true", headers=carol_hdr)
    assert r.status_code == 400


# ---- identity attribution: never trust client-supplied text ----------------------------------------

def test_create_records_the_verified_identity(env):
    a = create_assessment(env, "alice")
    assert a["created_by"] == "alice"
    assert env.entries("assessment.create")[0]["actor"] == "alice"


def test_import_and_report_are_attributed(env):
    a = create_assessment(env, "bob")
    hdr = session(env, "bob")
    assert import_nessus(env, a["id"], hdr).status_code == 200
    assert env.entries("tool.import")[0]["actor"] == "bob"
    r = env.client.post(f"/assessments/{a['id']}/report", headers=hdr)
    assert r.status_code == 200 and r.content[:5] == b"%PDF-"
    assert env.entries("report.generated")[0]["actor"] == "bob"


def test_oversized_import_rejected_with_413_not_buffered(env):
    a = create_assessment(env, "bob")
    hdr = session(env, "bob")
    oversized = b"x" * (api.MAX_UPLOAD_BYTES + 1)
    r = env.client.post(f"/assessments/{a['id']}/import/nessus", headers=hdr,
                        files={"file": ("huge.nessus", oversized, "application/xml")})
    assert r.status_code == 413
    assert not (env.tmp / a["id"] / "raw" / "huge.nessus").exists()


def test_tool_runs_record_who_triggered_them(env, monkeypatch):
    def fake_run(target, preset, workdir, timeout=900):
        return ToolRun(tool="nmap", mode="live", target=target, preset=preset, status="failed",
                       error="stubbed in test")
    monkeypatch.setattr(api.orch.adapters["nmap"], "run", fake_run)

    a = create_assessment(env, "alice")
    alice_hdr = session(env, "alice")
    step = a["plan"][0]["id"]
    env.client.post(f"/assessments/{a['id']}/plan/{step}/decision?approved=true", headers=alice_hdr)
    bob_hdr = session(env, "bob")                       # a lead happens to click "run" too
    env.client.post(f"/assessments/{a['id']}/plan/{step}/run", headers=bob_hdr)
    run_entry = env.entries("tool.run")[0]
    assert run_entry["actor"] == "agent" and run_entry["details"]["triggered_by"] == "bob"
    assert env.entries("plan.step_approved")[0]["actor"] == "alice"


# ---- upload filename safety (same property as before, now behind real login) ----------------------

@pytest.mark.parametrize("evil", ["../../escape.nessus", "..\\..\\escape.nessus", "/tmp/escape.nessus"])
def test_traversing_upload_names_cannot_escape_the_assessment_directory(env, evil):
    a = create_assessment(env, "alice")
    hdr = session(env, "alice")
    r = import_nessus(env, a["id"], hdr, filename=evil)
    assert r.status_code == 200, r.text
    assert (env.tmp / a["id"] / "raw" / "escape.nessus").exists()
    assert not Path("/tmp/escape.nessus").exists()


# ---- read-only routes stay reachable to anyone signed in -------------------------------------------

def test_integration_matrix_and_static_ui_are_public(env):
    assert env.client.get("/integration-matrix").status_code == 200
    assert env.client.get("/ui/").status_code == 200


# ---- startup behaviour ------------------------------------------------------------------------------

def test_bootstrap_admin_created_on_first_use_and_banner_never_reused(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(api, "DATA_DIR", tmp_path)
    monkeypatch.setattr(api, "BOOTSTRAP_MARKER", tmp_path / "bootstrap_admin")
    monkeypatch.setattr(api, "account_store", None)
    store = api.get_store()
    assert store.get_user("admin").must_change_password is True
    assert "admin" in capsys.readouterr().err

    monkeypatch.setattr(api, "account_store", None)      # simulate a second process starting up
    api.get_store()
    assert "admin" not in capsys.readouterr().err         # no password reprinted
