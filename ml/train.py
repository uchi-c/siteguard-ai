"""
Trains a payload classifier (benign / sql / xss / cmdinj / traversal / ssti)
on the "Web application attack payload dataset" (Kaggle, mreowie).

Not part of the deployed app's request path -- run this once locally to
produce ml/models/payload_classifier.joblib, which IS committed (a small,
static artifact the app loads at runtime, like any other build output).
Re-run only to retrain on updated or different data.

Usage:
    pip install kaggle scikit-learn joblib
    kaggle datasets download mreowie/web-application-attack-payload-dataset \
        --unzip -p ml/data
    python ml/train.py
"""
from __future__ import annotations

import csv
import json
import os

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "clean_payloads.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "payload_classifier.joblib")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "models", "metrics.json")


def load_data():
    texts, labels = [], []
    with open(DATA_PATH, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            payload = (row.get("Payload") or "").strip()
            label = (row.get("Type") or "").strip()
            if payload and label:
                texts.append(payload)
                labels.append(label)
    return texts, labels


def main():
    texts, labels = load_data()
    classes = sorted(set(labels))
    print(f"Loaded {len(texts)} labeled payloads across {len(classes)} classes: {classes}")

    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), max_features=20000)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced", C=5.0)),
    ])

    print("Training...")
    pipeline.fit(X_train, y_train)

    print("Evaluating on held-out test split...")
    y_pred = pipeline.predict(X_test)
    report = classification_report(y_test, y_pred, digits=3)
    print(report)

    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH, compress=3)
    with open(METRICS_PATH, "w") as f:
        json.dump({"classes": classes, "report": report, "n_samples": len(texts)}, f, indent=2)

    size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"Saved model to {MODEL_PATH} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
