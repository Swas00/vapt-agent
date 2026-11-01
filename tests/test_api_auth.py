"""HTTP-level tests for API authentication (CR-1), run through FastAPI's TestClient -- i.e. the real
routing, dependency injection, request parsing, and serialization, not the orchestrator in-process.

The properties that matter:
  * every state-changing route rejects a missing/invalid/mis-schemed token with 401;
  * the identity written to the audit log and approval records is the TOKEN'S owner, never a
    value the client sent (e.g. a forged `by=` query parameter);
  * a future POST route added without the auth dependency fails the meta-test below.
"""
from __future__ import annotations

import stat
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from vapt_agent import api, auth
from vapt_agent.audit import AuditLog
from vapt_agent.models import ToolRun
from vapt_agent.orchestrator import Orchestrator

FIX = Path(__file__).parent / "fixtures"
ALICE = "alice-token-0123456789abcdef"
BOB = "bob-token-0123456789abcdefgh"
CREATE_BODY = {"request": "audit test", "scope": {"targets": ["10.10.10.5"], "lab_attestation": True,
                                                  "allow_active_validation": True}}


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def env(tmp_path, monkeypatch):
    """The real app, with state redirected to a temp dir and a known two-analyst registry."""
    audit = AuditLog(tmp_path / "audit.log")
    monkeypatch.setattr(api, "DATA_DIR", tmp_path)
    monkeypatch.setattr(api, "audit", audit)
    monkeypatch.setattr(api, "orch", Orchestrator(tmp_path, audit))
    monkeypatch.setattr(api, "ASSESSMENTS", {})
    monkeypatch.setattr(api, "auth_registry", auth.AuthRegistry({ALICE: "alice", BOB: "bob"}))
    client = TestClient(api.app)

    class Env:
        pass
    e = Env()
    e.client, e.audit, e.tmp = client, audit, tmp_path
    e.entries = lambda action=None: [x for x in audit.entries() if action is None or x["action"] == action]
    return e


def create_assessment(env, token=ALICE) -> dict:
    r = env.client.post("/assessments", json=CREATE_BODY, headers=bearer(token))
    assert r.status_code == 200, r.text
    return r.json()


def import_nessus(env, assessment_id, token=ALICE, filename="n.nessus"):
    data = (FIX / "nessus_sample.nessus").read_bytes()
    return env.client.post(f"/assessments/{assessment_id}/import/nessus", headers=bearer(token),
                           files={"file": (filename, data, "application/xml")})


# ---- every mutating route is protected ---------------------------------------------------------

POST_CASES = [
    ("/assessments", {"json": CREATE_BODY}),
    ("/assessments/x/plan/y/decision?approved=true", {}),
    ("/assessments/x/plan/y/run", {}),
    ("/assessments/x/import/nessus", {"files": {"file": ("a.nessus", b"<x/>", "application/xml")}}),
    ("/assessments/x/analyse", {}),
    ("/assessments/x/approvals", {"json": {"finding_id": "f", "action": "a"}}),
    ("/assessments/x/approvals/y/decision?approved=true", {}),
    ("/assessments/x/approvals/y/execute", {}),
    ("/assessments/x/report", {}),
]


def _post_routes():
    return [r for r in api.app.routes if isinstance(r, APIRoute) and "POST" in r.methods]


def test_meta_every_post_route_depends_on_require_analyst():
    """Fails the day someone adds a POST route and forgets the guard."""
    routes = _post_routes()
    assert routes, "expected POST routes"
    unguarded = [r.path for r in routes
                 if not any(d.call is api.require_analyst for d in r.dependant.dependencies)]
    assert unguarded == []


def test_meta_case_table_covers_every_post_route():
    assert len(POST_CASES) == len(_post_routes())


@pytest.mark.parametrize("path,kwargs", POST_CASES)
def test_post_without_credentials_is_401(env, path, kwargs):
    r = env.client.post(path, **kwargs)
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("path,kwargs", POST_CASES)
def test_post_with_wrong_token_is_401(env, path, kwargs):
    r = env.client.post(path, headers=bearer("not-a-real-token-0123456789"), **kwargs)
    assert r.status_code == 401


@pytest.mark.parametrize("header", [
    {"Authorization": f"Basic {ALICE}"},            # wrong scheme
    {"Authorization": "Bearer"},                    # no credential
    {"Authorization": "Bearer "},                   # empty credential
    {"Authorization": ALICE},                       # missing scheme
    {"Authorization": f"Bearer {ALICE.upper()}"},   # case-altered token
    {"Authorization": f"Bearer {ALICE}x"},          # near-miss
    {"Authorization": f"Bearer {ALICE[:-1]}"},      # truncated
])
def test_malformed_or_near_miss_credentials_rejected(env, header):
    assert env.client.post("/assessments", json=CREATE_BODY, headers=header).status_code == 401


def test_scheme_name_is_case_insensitive_per_rfc(env):
    r = env.client.post("/assessments", json=CREATE_BODY, headers={"Authorization": f"bearer {ALICE}"})
    assert r.status_code == 200


def test_auth_is_checked_before_the_resource_is_looked_up(env):
    # An unauthenticated caller must not learn whether an assessment id exists (401, never 404).
    assert env.client.post("/assessments/does-not-exist/analyse").status_code == 401
    assert env.client.post("/assessments/does-not-exist/analyse", headers=bearer(ALICE)).status_code == 404


# ---- read-only routes stay open ----------------------------------------------------------------

def test_read_only_routes_do_not_require_a_token(env):
    created = create_assessment(env)
    for path in ("/assessments", f"/assessments/{created['id']}", "/audit", "/integration-matrix", "/ui/"):
        assert env.client.get(path).status_code == 200, path


def test_whoami_requires_a_token_and_reports_the_identity(env):
    assert env.client.get("/whoami").status_code == 401
    assert env.client.get("/whoami", headers=bearer("bad-token-0123456789abc")).status_code == 401
    assert env.client.get("/whoami", headers=bearer(BOB)).json() == {"identity": "bob"}


def test_openapi_advertises_the_bearer_scheme_on_mutating_operations(env):
    schema = env.client.get("/openapi.json").json()
    schemes = schema["components"]["securitySchemes"]
    assert any(s.get("type") == "http" and s.get("scheme") == "bearer" for s in schemes.values())
    assert schema["paths"]["/assessments"]["post"].get("security")


# ---- the identity recorded is the token's owner ------------------------------------------------

def test_create_records_the_authenticated_identity(env):
    a = create_assessment(env, ALICE)
    assert a["created_by"] == "alice"
    entry = env.entries("assessment.create")[0]
    assert entry["actor"] == "alice" and entry["details"]["assessment"] == a["id"]
    assert any(e["message"].startswith("Assessment created by alice") for e in a["events"])


def test_client_supplied_by_parameter_is_ignored_on_step_decisions(env):
    a = create_assessment(env, ALICE)
    step = a["plan"][0]["id"]
    r = env.client.post(f"/assessments/{a['id']}/plan/{step}/decision?approved=true&by=mallory",
                        headers=bearer(ALICE))
    assert r.status_code == 200
    entry = env.entries("plan.step_approved")[0]
    assert entry["actor"] == "alice"
    assert not any(e["actor"] == "mallory" for e in env.audit.entries())


def test_full_approval_trail_attributes_each_step_to_the_right_analyst(env):
    a = create_assessment(env, ALICE)
    assert import_nessus(env, a["id"], ALICE).status_code == 200
    assert env.client.post(f"/assessments/{a['id']}/analyse", headers=bearer(ALICE)).status_code == 200
    finding = next(f for f in env.client.get(f"/assessments/{a['id']}").json()["findings"]
                   if f["severity"] in ("critical", "high"))

    # alice requests, bob decides (while claiming to be "mallory" in the query), alice executes
    appr = env.client.post(f"/assessments/{a['id']}/approvals", headers=bearer(ALICE),
                           json={"finding_id": finding["id"], "action": "validate", "module": ""}).json()
    assert appr["requested_by"] == "alice"

    decided = env.client.post(
        f"/assessments/{a['id']}/approvals/{appr['id']}/decision?approved=true&by=mallory&reason=ok",
        headers=bearer(BOB)).json()
    assert decided["decided_by"] == "bob" and decided["state"] == "approved"

    env.client.post(f"/assessments/{a['id']}/approvals/{appr['id']}/execute", headers=bearer(ALICE))
    final = env.client.get(f"/assessments/{a['id']}").json()["approvals"][0]
    assert (final["requested_by"], final["decided_by"], final["executed_by"]) == ("alice", "bob", "alice")

    assert env.entries("approval.requested")[0]["actor"] == "alice"
    assert env.entries("approval.decided")[0]["actor"] == "bob"
    assert env.entries("approval.executed")[0]["actor"] == "alice"
    assert not any(e["actor"] == "mallory" for e in env.audit.entries())
    ok, msg = env.audit.verify()
    assert ok, msg


def test_import_and_report_are_attributed(env):
    a = create_assessment(env, BOB)
    assert import_nessus(env, a["id"], BOB).status_code == 200
    assert env.entries("tool.import")[0]["actor"] == "bob"

    r = env.client.post(f"/assessments/{a['id']}/report", headers=bearer(BOB))
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf" and r.content[:5] == b"%PDF-"
    assert env.entries("report.generated")[0]["actor"] == "bob"


def test_tool_runs_record_who_triggered_them(env, monkeypatch):
    # Stub the adapter: this test is about attribution, and must never launch a real scan (nmap
    # may well be installed on the machine running the suite).
    def fake_run(target, preset, workdir, timeout=900):
        return ToolRun(tool="nmap", mode="live", target=target, preset=preset, status="failed",
                       error="stubbed in test")
    monkeypatch.setattr(api.orch.adapters["nmap"], "run", fake_run)

    a = create_assessment(env, ALICE)
    step = a["plan"][0]["id"]
    env.client.post(f"/assessments/{a['id']}/plan/{step}/decision?approved=true", headers=bearer(ALICE))
    env.client.post(f"/assessments/{a['id']}/plan/{step}/run", headers=bearer(BOB))
    run_entry = env.entries("tool.run")[0]
    assert run_entry["actor"] == "agent" and run_entry["details"]["triggered_by"] == "bob"
    assert env.entries("plan.step_approved")[0]["actor"] == "alice"   # approver and runner differ


# ---- failed attempts: audited, throttled, never leak the token ---------------------------------

def test_rejections_are_audited_once_per_client_window_without_the_token(env):
    secret = "SECRET-TOKEN-VALUE-1234567890"
    bodies = [env.client.post("/assessments", json=CREATE_BODY, headers=bearer(secret)).text
              for _ in range(4)]
    rejected = env.entries("auth.rejected")
    assert len(rejected) == 1                                    # throttled, not one-per-request
    assert rejected[0]["actor"] == "system"
    assert rejected[0]["details"]["reason"] == "invalid token"
    assert rejected[0]["details"]["path"] == "/assessments"
    assert secret not in (env.tmp / "audit.log").read_text()     # never written to the log
    assert all(secret not in b for b in bodies)                   # never echoed back


def test_missing_credentials_reason_is_distinguished(env):
    env.client.post("/assessments", json=CREATE_BODY)
    assert env.entries("auth.rejected")[0]["details"]["reason"] == "missing credentials"


def test_unauthenticated_requests_cannot_grow_the_audit_log_unboundedly(env):
    for _ in range(50):
        env.client.post("/assessments", json=CREATE_BODY)
    assert len(env.entries("auth.rejected")) == 1


# ---- an unauthenticated upload leaves nothing behind -------------------------------------------

def test_unauthenticated_upload_writes_nothing_to_disk(env):
    a = create_assessment(env)
    before = {p for p in env.tmp.rglob("*")}
    r = env.client.post(f"/assessments/{a['id']}/import/nessus",
                        files={"file": ("n.nessus", b"<x/>", "application/xml")})
    assert r.status_code == 401
    new = {p for p in env.tmp.rglob("*")} - before
    assert not [p for p in new if p.name != "audit.log"], new


# ---- upload filename path traversal (found while hardening this endpoint) ----------------------

@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd", "passwd"),
    ("/abs/path/report.xml", "report.xml"),
    ("..\\..\\win\\report.xml", "report.xml"),
    ("scan results (1).xml", "scan_results__1_.xml"),
    (".hidden", "hidden"),
    ("..", "upload"),
    ("", "upload"),
    (None, "upload"),
])
def test_safe_filename(raw, expected):
    assert api._safe_filename(raw) == expected


def test_safe_filename_is_length_bounded():
    assert len(api._safe_filename("a" * 500 + ".xml")) <= 120


@pytest.mark.parametrize("evil", ["../../escape.nessus", "..\\..\\escape.nessus", "/tmp/escape.nessus"])
def test_traversing_upload_names_cannot_escape_the_assessment_directory(env, evil):
    a = create_assessment(env)
    r = import_nessus(env, a["id"], filename=evil)
    assert r.status_code == 200, r.text
    assert (env.tmp / a["id"] / "raw" / "escape.nessus").exists()
    assert not (env.tmp.parent / "escape.nessus").exists()
    assert not Path("/tmp/escape.nessus").exists()


# ---- startup behaviour -------------------------------------------------------------------------

def test_dev_mode_when_unconfigured_prints_a_token_and_persists_it_privately(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv(auth.ENV_VAR, raising=False)
    monkeypatch.setattr(api, "DEV_TOKEN_PATH", tmp_path / ".dev_token")
    monkeypatch.setattr(api, "auth_registry", None)
    registry = api.get_registry()
    assert registry.dev_mode
    token = next(iter(registry.tokens))
    assert token in capsys.readouterr().err
    assert stat.S_IMODE((tmp_path / ".dev_token").stat().st_mode) == 0o600
    assert registry.authenticate(token) == "analyst"


def test_configured_tokens_are_never_printed(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv(auth.ENV_VAR, f"{ALICE}:alice")
    monkeypatch.setattr(api, "auth_registry", None)
    api.get_registry()
    out = capsys.readouterr()
    assert ALICE not in out.out + out.err


def test_malformed_config_fails_fast_at_startup(monkeypatch):
    monkeypatch.setenv(auth.ENV_VAR, "short:agent")
    monkeypatch.setattr(api, "auth_registry", None)
    with pytest.raises(auth.AuthConfigError):
        with TestClient(api.app):      # entering the context runs the lifespan startup
            pass
