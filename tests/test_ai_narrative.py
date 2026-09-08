import ai_narrative
from scanner import Finding, ScanResult


def test_generate_narrative_rule_based_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = ScanResult(
        target="https://example.test", scanned_at="t",
        findings=[Finding("no-https", "Site does not use HTTPS", "critical", "detail", "fix")],
        reachable=True, error=None,
    )
    text, source = ai_narrative.generate_narrative(result)
    assert source == "rule-based"
    assert "site does not use https" in text.lower()


def test_generate_narrative_clean_scan_message(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = ScanResult(target="https://clean.test", scanned_at="t", findings=[], reachable=True, error=None)
    text, source = ai_narrative.generate_narrative(result)
    assert source == "rule-based"
    assert "passed every check" in text


def test_generate_outreach_message_rule_based_with_findings(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text, source = ai_narrative.generate_outreach_message(
        "https://example.test", "Missing HSTS header", "detail here", True
    )
    assert source == "rule-based"
    assert "example.test" in text
    assert "missing hsts header" in text.lower()


def test_generate_outreach_message_rule_based_clean_site(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text, source = ai_narrative.generate_outreach_message("https://clean.test", "", "", False)
    assert source == "rule-based"
    assert "came back clean" in text


def test_generate_narrative_falls_back_when_api_call_raises(monkeypatch):
    """Even with a key set, an API hiccup must never break the report --
    mocks the Anthropic client so this never makes a real network call."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake-not-a-real-key")
    import anthropic

    class _BoomMessages:
        @staticmethod
        def create(**kwargs):
            raise RuntimeError("simulated API failure")

    class _BoomClient:
        messages = _BoomMessages()

    monkeypatch.setattr(anthropic, "Anthropic", lambda api_key: _BoomClient())

    result = ScanResult(
        target="https://example.test", scanned_at="t",
        findings=[Finding("no-https", "Site does not use HTTPS", "critical", "detail", "fix")],
        reachable=True, error=None,
    )
    text, source = ai_narrative.generate_narrative(result)
    assert source == "rule-based"
    assert text
