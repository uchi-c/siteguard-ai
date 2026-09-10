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


def test_generate_followup_message_rule_based_with_finding(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text, source = ai_narrative.generate_followup_message(
        "https://example.test", "Missing HSTS header", "detail here", days_since=3,
    )
    assert source == "rule-based"
    assert "example.test" in text
    assert "missing hsts header" in text.lower()


def test_generate_followup_message_rule_based_no_finding(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text, source = ai_narrative.generate_followup_message(
        "https://clean.test", "", "", days_since=10,
    )
    assert source == "rule-based"
    assert "clean.test" in text


def test_generate_followup_message_wording_varies_with_days_since(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    recent, _ = ai_narrative.generate_followup_message("https://x.test", "", "", days_since=2)
    old, _ = ai_narrative.generate_followup_message("https://x.test", "", "", days_since=30)
    assert recent != old


def test_generate_followup_message_falls_back_when_api_call_raises(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake-not-a-real-key")
    import anthropic

    class _BoomMessages:
        @staticmethod
        def create(**kwargs):
            raise RuntimeError("simulated API failure")

    class _BoomClient:
        messages = _BoomMessages()

    monkeypatch.setattr(anthropic, "Anthropic", lambda api_key: _BoomClient())

    text, source = ai_narrative.generate_followup_message(
        "https://example.test", "Missing HSTS header", "detail here", days_since=5,
    )
    assert source == "rule-based"
    assert text


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


# --- generate_monitoring_digest ------------------------------------------------

def test_generate_monitoring_digest_new_findings_only(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    new = [Finding("csp-missing", "Missing CSP header", "medium", "detail", "fix")]
    text, source = ai_narrative.generate_monitoring_digest("https://example.test", new, [])
    assert source == "rule-based"
    assert "example.test" in text
    assert "1 new finding" in text
    assert "missing csp header" in text.lower()


def test_generate_monitoring_digest_resolved_only(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    resolved = [Finding("hsts", "Missing HSTS header", "high", "detail", "fix")]
    text, source = ai_narrative.generate_monitoring_digest("https://example.test", [], resolved)
    assert source == "rule-based"
    assert "1 previous finding" in text
    assert "resolved" in text.lower()


def test_generate_monitoring_digest_no_changes(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    text, source = ai_narrative.generate_monitoring_digest("https://example.test", [], [])
    assert source == "rule-based"
    assert "no changes" in text.lower()


def test_generate_monitoring_digest_falls_back_when_api_call_raises(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake-not-a-real-key")
    import anthropic

    class _BoomMessages:
        @staticmethod
        def create(**kwargs):
            raise RuntimeError("simulated API failure")

    class _BoomClient:
        messages = _BoomMessages()

    monkeypatch.setattr(anthropic, "Anthropic", lambda api_key: _BoomClient())

    new = [Finding("csp-missing", "Missing CSP header", "medium", "detail", "fix")]
    text, source = ai_narrative.generate_monitoring_digest("https://example.test", new, [])
    assert source == "rule-based"
    assert text
