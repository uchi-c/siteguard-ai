"""
Loads the trained payload classifier (see ml/train.py) and classifies a
pasted string as benign / sql / xss / cmdinj / traversal / ssti with a
confidence score. Purely local inference -- no network calls, nothing sent
anywhere. Lazy-loaded so importing this module never fails even if the
model file is missing (e.g. a fresh checkout before running ml/train.py);
classify_payload() reports that state instead of crashing the app.
"""
from __future__ import annotations

import os

MODEL_PATH = os.path.join(os.path.dirname(__file__), "ml", "models", "payload_classifier.joblib")

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


def classify_payload(text: str) -> dict:
    """Returns {"label", "confidence", "scores"} or {"error"} if the model
    isn't available or the input is empty."""
    _load()
    if _model is None:
        return {"error": _load_error or "Classifier model not available on this deployment."}
    text = (text or "").strip()
    if not text:
        return {"error": "Enter some text to classify."}

    proba = _model.predict_proba([text])[0]
    classes = [str(c) for c in _model.classes_]
    scores = {cls: float(p) for cls, p in zip(classes, proba)}
    best_idx = int(proba.argmax())
    return {
        "label": classes[best_idx],
        "confidence": float(proba[best_idx]),
        "scores": dict(sorted(scores.items(), key=lambda kv: -kv[1])),
    }
