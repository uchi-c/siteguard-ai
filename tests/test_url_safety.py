from unittest.mock import MagicMock, patch

import url_safety


def _fake_response(json_body, status_ok=True):
    resp = MagicMock()
    resp.json.return_value = json_body
    if not status_ok:
        resp.raise_for_status.side_effect = Exception("HTTP error")
    return resp


def test_check_url_malicious_when_safe_browsing_matches(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "fake-key")
    matches = {"matches": [{"threatType": "SOCIAL_ENGINEERING"}, {"threatType": "MALWARE"}]}
    with patch("requests.post", return_value=_fake_response(matches)):
        result = url_safety.check_url("http://evil-phishing-site.test")

    assert result["verdict"] == "malicious"
    assert set(result["threats"]) == {"phishing", "malware"}
    assert result["source"] == "safe-browsing"


def test_check_url_no_known_threats_when_safe_browsing_finds_nothing(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "fake-key")
    with patch("requests.post", return_value=_fake_response({"matches": []})):
        result = url_safety.check_url("https://example.test")

    assert result["verdict"] == "no-known-threats"
    assert result["threats"] == []
    assert result["source"] == "safe-browsing"


def test_check_url_falls_back_when_no_api_key(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "")
    with patch("requests.post") as mock_post:
        result = url_safety.check_url("https://example.test")
    mock_post.assert_not_called()
    assert result["source"] in ("allowlist", "ml", "none")


def test_check_url_falls_back_when_api_call_raises(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "fake-key")
    import requests

    with patch("requests.post", side_effect=requests.RequestException("timeout")):
        result = url_safety.check_url("https://example.test")
    assert result["source"] in ("allowlist", "ml", "none")
    assert result["verdict"] != "malicious"


def test_check_url_falls_back_when_response_is_not_json(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "fake-key")
    bad_resp = MagicMock()
    bad_resp.json.side_effect = ValueError("not json")
    with patch("requests.post", return_value=bad_resp):
        result = url_safety.check_url("https://example.test")
    assert result["source"] in ("allowlist", "ml", "none")


# --- Allowlist short-circuit (real bug found: see known_domains.py) ----------

def test_known_safe_domain_short_circuits_before_ml(monkeypatch):
    """Regression test: the ML fallback's training data skewed such that
    it confidently mis-flagged well-known bare domains (google.com,
    wikipedia.org) as phishing. The allowlist must short-circuit before
    the ML model is even consulted for domains on it."""
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "")
    import url_classifier
    spy = MagicMock(wraps=url_classifier.classify_url)
    monkeypatch.setattr(url_classifier, "classify_url", spy)

    result = url_safety.check_url("https://www.google.com")

    assert result["verdict"] == "no-known-threats"
    assert result["source"] == "allowlist"
    spy.assert_not_called()


def test_non_allowlisted_domain_reaches_ml_fallback(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "")
    import url_classifier
    monkeypatch.setattr(
        url_classifier, "classify_url",
        lambda url: {"label": "benign", "confidence": 0.9, "scores": {"benign": 0.9}},
    )
    monkeypatch.setattr(url_classifier, "is_available", lambda: True)

    result = url_safety.check_url("https://some-random-site-not-on-any-list.test")
    assert result["source"] == "ml"


def test_check_url_normalizes_the_url(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "")
    result = url_safety.check_url("www.google.com")  # no scheme
    assert result["url"] == "https://www.google.com"
    assert result["source"] == "allowlist"


# --- ML fallback verdict mapping ---------------------------------------------

def test_ml_fallback_suspicious_above_confidence_threshold(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "")
    import url_classifier
    monkeypatch.setattr(url_classifier, "is_available", lambda: True)
    monkeypatch.setattr(
        url_classifier, "classify_url",
        lambda url: {"label": "phishing", "confidence": 0.85, "scores": {}},
    )
    result = url_safety.check_url("https://not-on-allowlist-either.test")
    assert result["verdict"] == "suspicious"
    assert result["threats"] == ["phishing"]
    assert result["source"] == "ml"
    assert result["confidence"] == 0.85


def test_ml_fallback_no_known_threats_below_confidence_threshold(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "")
    import url_classifier
    monkeypatch.setattr(url_classifier, "is_available", lambda: True)
    monkeypatch.setattr(
        url_classifier, "classify_url",
        lambda url: {"label": "phishing", "confidence": 0.3, "scores": {}},
    )
    result = url_safety.check_url("https://not-on-allowlist-either.test")
    assert result["verdict"] == "no-known-threats"
    assert result["threats"] == []


def test_ml_fallback_unavailable_when_model_not_loaded(monkeypatch):
    monkeypatch.setattr(url_safety, "SAFE_BROWSING_API_KEY", "")
    import url_classifier
    monkeypatch.setattr(url_classifier, "is_available", lambda: False)
    result = url_safety.check_url("https://not-on-allowlist-either.test")
    assert result["verdict"] == "unavailable"
    assert result["source"] == "none"
