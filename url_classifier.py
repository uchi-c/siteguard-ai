"""
Loads the trained URL classifier (see ml/train_url_classifier.py) and
classifies a URL as benign / phishing / malware / defacement with a
confidence score. Purely local inference on the URL string itself --
never fetches the URL. Lazy-loaded so importing this module never fails
even if the model file is missing (e.g. a fresh checkout before running
ml/train_url_classifier.py); classify_url() reports that state instead of
crashing the app.

Used by url_safety.py as a fallback when GOOGLE_SAFE_BROWSING_API_KEY
isn't set or the API call fails -- weaker than a live threat feed (a
static model trained once will miss brand-new malicious domains), so
url_safety.py hedges its verdict accordingly ("suspicious", not
"malicious").
"""
from __future__ import annotations

import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml", "models", "url_classifier.joblib")

_model = None
_load_error: str | None = None
_attempted = False


def _load() -> None:
    global _model, _load_error, _attempted
    if _attempted:
        return
    _attempted = True
    try:
        import joblib
        _model = joblib.load(MODEL_PATH)
    except Exception as e:
        _load_error = str(e)


def is_available() -> bool:
    _load()
    return _model is not None


def classify_url(url: str) -> dict:
    """Returns {"label", "confidence", "scores"} or {"error"} if the model
    isn't available or the input is empty."""
    _load()
    if _model is None:
        return {"error": _load_error or "URL classifier model not available on this deployment."}
    url = (url or "").strip()
    if not url:
        return {"error": "Enter a URL to classify."}

    proba = _model.predict_proba([url])[0]
    classes = [str(c) for c in _model.classes_]
    scores = {cls: float(p) for cls, p in zip(classes, proba)}
    best_idx = int(proba.argmax())
    return {
        "label": classes[best_idx],
        "confidence": float(proba[best_idx]),
        "scores": dict(sorted(scores.items(), key=lambda kv: -kv[1])),
    }
