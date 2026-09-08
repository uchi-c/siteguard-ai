import payload_classifier as pc


def test_model_is_available():
    """Uses the real committed model (ml/models/payload_classifier.joblib)
    -- this is the one thing in the suite that isn't a fixture, since the
    whole point is to catch a bad or missing commit of the artifact."""
    assert pc.is_available()


def test_classify_empty_input_returns_error():
    result = pc.classify_payload("")
    assert "error" in result


def test_classify_sql_injection():
    result = pc.classify_payload("' OR 1=1--")
    assert result["label"] == "sql"
    assert result["confidence"] > 0.5


def test_classify_xss():
    result = pc.classify_payload("<script>alert(1)</script>")
    assert result["label"] == "xss"
    assert result["confidence"] > 0.5


def test_classify_path_traversal():
    result = pc.classify_payload("../../etc/passwd")
    assert result["label"] == "traversal"
    assert result["confidence"] > 0.5


def test_classify_benign_text():
    result = pc.classify_payload("hello world, just a normal search query")
    assert result["label"] == "benign"


def test_classify_scores_sum_to_roughly_one():
    result = pc.classify_payload("some input")
    assert abs(sum(result["scores"].values()) - 1.0) < 0.01


def test_classify_scores_are_plain_python_types():
    """Regression check: predict_proba/classes_ return numpy scalars: make
    sure they're cast to plain str/float before leaving this module."""
    result = pc.classify_payload("test")
    assert isinstance(result["label"], str)
    assert isinstance(result["confidence"], float)
    for label, score in result["scores"].items():
        assert isinstance(label, str)
        assert isinstance(score, float)
