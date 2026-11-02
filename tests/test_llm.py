"""Tests for the executive-summary generator (vapt_agent.llm.summarize_assessment), including the
confidence-aware hedging (CA-4): when most findings are still 'suspected' rather than confirmed or
analyst-validated, the summary must say so explicitly instead of implying more certainty than the
assessment actually has.
"""
from __future__ import annotations

from vapt_agent import llm
from vapt_agent.models import Assessment, Finding, ScopeModel


def _assessment(**kw):
    base = dict(targets=["10.10.10.5"], lab_attestation=True)
    base.update(kw)
    return Assessment(request="r", scope=ScopeModel(**base))


def _f(status, severity="high"):
    return Finding(title="t", asset="10.10.10.5", severity=severity, status=status)


def test_no_api_key_falls_back_to_the_deterministic_template(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    a = _assessment()
    findings = [_f("confirmed"), _f("confirmed", severity="medium")]
    text = llm.summarize_assessment(a, findings)
    assert "1 authorized target" in text
    assert "1 high" in text and "1 medium" in text


def test_template_has_no_hedge_when_most_findings_are_confirmed(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    a = _assessment()
    findings = [_f("confirmed"), _f("confirmed"), _f("suspected")]
    text = llm.summarize_assessment(a, findings)
    assert "suspected" not in text.lower() or "Note:" not in text


def test_template_hedges_when_most_findings_are_still_suspected(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    a = _assessment()
    findings = [_f("suspected"), _f("suspected"), _f("confirmed")]   # 2/3 >= 0.6 threshold
    text = llm.summarize_assessment(a, findings)
    assert "Note: 2 of 3 finding(s)" in text
    assert "upper bound on confirmed risk" in text


def test_uncertainty_note_empty_for_no_findings():
    assert llm._uncertainty_note([]) == ""


def test_uncertainty_note_threshold_is_exclusive_boundary_at_just_under():
    findings = [_f("suspected"), _f("suspected"), _f("confirmed"), _f("confirmed"), _f("confirmed")]
    assert 2 / 5 < llm._HEDGE_THRESHOLD
    assert llm._uncertainty_note(findings) == ""


def test_llm_path_appends_hedge_even_when_model_response_omits_it(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    class FakeBlock:
        type = "text"
        text = "A short summary that never mentions uncertainty."

    class FakeResponse:
        content = [FakeBlock()]

    class FakeMessages:
        def create(self, **kwargs):
            FakeMessages.last_kwargs = kwargs
            return FakeResponse()

    class FakeClient:
        messages = FakeMessages()

    monkeypatch.setattr(llm, "_client", lambda: FakeClient())
    a = _assessment()
    findings = [_f("suspected"), _f("suspected")]   # 2/2 -- hedge required
    text = llm.summarize_assessment(a, findings)
    assert text.startswith("A short summary that never mentions uncertainty.")
    assert "Note: 2 of 2 finding(s)" in text
    assert "hedge accordingly" in FakeMessages.last_kwargs["messages"][0]["content"]


def test_llm_path_falls_back_to_template_on_api_error(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    class FakeMessages:
        def create(self, **kwargs):
            raise RuntimeError("network down")

    class FakeClient:
        messages = FakeMessages()

    monkeypatch.setattr(llm, "_client", lambda: FakeClient())
    a = _assessment()
    findings = [_f("confirmed")]
    text = llm.summarize_assessment(a, findings)
    assert "1 authorized target" in text


def test_llm_path_failure_is_logged_not_silently_swallowed(monkeypatch, caplog):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    class FakeMessages:
        def create(self, **kwargs):
            raise RuntimeError("network down")

    class FakeClient:
        messages = FakeMessages()

    monkeypatch.setattr(llm, "_client", lambda: FakeClient())
    with caplog.at_level("WARNING", logger="vapt_agent.llm"):
        llm.summarize_assessment(_assessment(), [_f("confirmed")])
    assert "falling back" in caplog.text.lower()


# B7: the API key must never reach a log line, even in the hypothetical case where it shows up
# inside an exception's own string representation (SECURITY.md's noted residual risk).

def test_api_key_is_redacted_even_if_the_exception_message_contains_it(monkeypatch, caplog):
    secret = "sk-ant-totally-real-secret-12345"
    monkeypatch.setenv("ANTHROPIC_API_KEY", secret)

    class FakeMessages:
        def create(self, **kwargs):
            raise RuntimeError(f"401 unauthorized for key {secret}")

    class FakeClient:
        messages = FakeMessages()

    monkeypatch.setattr(llm, "_client", lambda: FakeClient())
    with caplog.at_level("WARNING", logger="vapt_agent.llm"):
        llm.summarize_assessment(_assessment(), [_f("confirmed")])
    assert secret not in caplog.text
    assert "[REDACTED]" in caplog.text


def test_scrub_secret_is_a_no_op_when_no_key_is_configured(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert llm._scrub_secret("plain message") == "plain message"
