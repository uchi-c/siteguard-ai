import url_classifier as uc


def test_model_is_available():
    """Uses the real committed model (ml/models/url_classifier.joblib) --
    this is the one thing in the suite that isn't a fixture, since the
    whole point is to catch a bad or missing commit of the artifact."""
    assert uc.is_available()


def test_classify_empty_input_returns_error():
    result = uc.classify_url("")
    assert "error" in result


def test_classify_known_phishing_pattern():
    result = uc.classify_url("http://paypal-verify-account-secure.tk/login.php")
    assert result["label"] == "phishing"
    assert result["confidence"] > 0.5


def test_classify_scores_sum_to_roughly_one():
    result = uc.classify_url("https://example.test/some/path")
    assert abs(sum(result["scores"].values()) - 1.0) < 0.01


def test_classify_scores_are_plain_python_types():
    """Regression check: predict_proba/classes_ return numpy scalars: make
    sure they're cast to plain str/float before leaving this module."""
    result = uc.classify_url("https://example.test")
    assert isinstance(result["label"], str)
    assert isinstance(result["confidence"], float)
    for label, score in result["scores"].items():
        assert isinstance(label, str)
        assert isinstance(score, float)


def test_classify_known_safe_domains_from_allowlist():
    """These are exactly the domains oversampled into training specifically
    to fix a real, confirmed bug (see known_domains.py) -- the model itself
    should now get its own training examples right, independent of the
    runtime allowlist short-circuit in url_safety.py that also covers them."""
    result = uc.classify_url("https://www.google.com")
    assert result["label"] == "benign"
