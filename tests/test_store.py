"""FS-1: unit tests for the SQLite-backed Assessment persistence layer (vapt_agent/store.py),
independent of the API layer that wires it in."""
from __future__ import annotations

from vapt_agent.models import Assessment, Finding, ScopeModel
from vapt_agent.store import AssessmentStore


def make_assessment(**kw):
    scope = ScopeModel(targets=["10.10.10.5"], lab_attestation=True)
    return Assessment(request="test", scope=scope, **kw)


def test_save_and_load_all_round_trips_full_assessment(tmp_path):
    store = AssessmentStore(tmp_path / "assessments.db")
    a = make_assessment()
    a.findings.append(Finding(title="Exposed service", asset="10.10.10.5", port=80))
    a.state = "analysed"
    store.save(a)

    reloaded = store.load_all()
    assert set(reloaded) == {a.id}
    got = reloaded[a.id]
    assert got.state == "analysed"
    assert len(got.findings) == 1
    assert got.findings[0].title == "Exposed service"
    assert got.scope.targets == ["10.10.10.5"]


def test_save_again_overwrites_rather_than_duplicates(tmp_path):
    store = AssessmentStore(tmp_path / "assessments.db")
    a = make_assessment()
    store.save(a)
    a.state = "reported"
    store.save(a)

    reloaded = store.load_all()
    assert len(reloaded) == 1
    assert reloaded[a.id].state == "reported"


def test_load_all_returns_multiple_assessments_oldest_first(tmp_path):
    store = AssessmentStore(tmp_path / "assessments.db")
    first = make_assessment()
    store.save(first)
    second = make_assessment()
    store.save(second)

    reloaded = store.load_all()
    assert list(reloaded) == [first.id, second.id]


def test_delete_removes_the_row(tmp_path):
    store = AssessmentStore(tmp_path / "assessments.db")
    a = make_assessment()
    store.save(a)
    store.delete(a.id)
    assert store.load_all() == {}


def test_a_second_store_instance_over_the_same_file_sees_prior_saves(tmp_path):
    """The actual property FS-1 exists for: a fresh process (a new AssessmentStore object,
    exactly as api.get_assessment_store() constructs on startup) reading the same file sees
    what an earlier process wrote."""
    path = tmp_path / "assessments.db"
    a = make_assessment()
    AssessmentStore(path).save(a)

    reloaded = AssessmentStore(path).load_all()
    assert reloaded[a.id].id == a.id
    assert reloaded[a.id].request == "test"
