"""
Trains a URL classifier (benign / phishing / malware / defacement) on the
"Malicious URLs dataset" (Kaggle, sid321axn) -- ~651k labeled URLs:
428k benign, 96k defacement, 94k phishing, 33k malware.

Not part of the deployed app's request path -- run this once locally to
produce ml/models/url_classifier.joblib, which IS committed (a small,
static artifact the app loads at runtime, like any other build output).
Re-run only to retrain on updated or different data.

Same pipeline shape as ml/train.py (char n-grams + logistic regression) --
char-level n-grams work well on URL strings too: they pick up suspicious
TLDs, brand-lookalike substrings, IP-literal hosts, and excessive
hyphens/subdomains without needing hand-engineered lexical features.

Usage:
    pip install kaggle scikit-learn joblib
    kaggle datasets download sid321axn/malicious-urls-dataset \
        --unzip -p ml/data
    python ml/train_url_classifier.py
"""
from __future__ import annotations

import csv
import json
import os
import sys

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from known_domains import KNOWN_SAFE_DOMAINS  # noqa: E402 -- see sys.path.insert above
from scanner import _normalize_url  # noqa: E402

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "malicious_phish.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "url_classifier.joblib")
METRICS_PATH = os.path.join(os.path.dirname(__file__), "models", "url_classifier_metrics.json")

# How many times each known-safe domain is duplicated into the training
# set -- see load_data()'s docstring for why this exists at all. Large
# enough to actually move the decision boundary for "bare, short,
# well-known-brand-shaped domain" (a few hundred domains vs. a 428k-row
# benign class would otherwise be statistically invisible), small enough
# to stay a nudge rather than let the model just memorize this exact list
# (the runtime allowlist in url_safety.py is what makes THESE SPECIFIC
# domains reliably safe; this is about generalizing the pattern).
KNOWN_SAFE_OVERSAMPLE = 400


def load_data():
    """Every URL is run through the SAME _normalize_url() that
    url_safety.py applies before inference. Without this, the raw
    dataset's scheme-prefix presence correlates almost perfectly with
    label (defacement: 100% "http://"-prefixed, malware: 96%, benign:
    only 8%) -- a real, confirmed bug found by hand: a first training run
    without this normalization scored 96.6% held-out accuracy yet
    confidently misclassified https://www.google.com and
    https://github.com/... as phishing, because it had learned "starts
    with a scheme" as a shortcut for "not benign" rather than any genuine
    URL pattern. Normalizing every training example so 100% of them carry
    a scheme prefix removes that shortcut entirely.

    Fixing that alone wasn't enough, though: even after normalizing, the
    SAME URLs were still misclassified as phishing with 98-99.9%
    confidence. The dataset's "benign" class turned out to be mostly deep
    links to arbitrary web content (blog posts, forum threads) rather
    than bare domain homepages, while "phishing" examples disproportion-
    ately impersonate exactly the bare-domain, www-prefixed homepage
    shape (38% of phishing rows start with "www.", vs. only 3% of benign
    ones) -- so a bare "www.google.com"-shaped URL statistically
    resembles this dataset's phishing class more than its benign one,
    completely independent of the actual brand name. Oversampling
    known-safe domains (known_domains.py) directly into the benign class
    corrects that specific blind spot; the runtime allowlist in
    url_safety.py is the actual safety net for the exact domains listed
    there, this is about generalizing the shape."""
    urls, labels = [], []
    with open(DATA_PATH, encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            url = (row.get("url") or "").strip()
            label = (row.get("type") or "").strip().lower()
            if url and label:
                urls.append(_normalize_url(url))
                labels.append(label)
    return urls, labels


def oversampled_known_safe_domains() -> tuple[list[str], list[str]]:
    urls, labels = [], []
    for domain in KNOWN_SAFE_DOMAINS:
        normalized = _normalize_url(domain)
        for _ in range(KNOWN_SAFE_OVERSAMPLE):
            urls.append(normalized)
            labels.append("benign")
    return urls, labels


def main():
    urls, labels = load_data()
    classes = sorted(set(labels))
    print(f"Loaded {len(urls)} labeled URLs across {len(classes)} classes: {classes}")

    X_train, X_test, y_train, y_test = train_test_split(
        urls, labels, test_size=0.2, random_state=42, stratify=labels
    )

    # Added only to the training side, AFTER the split -- these are
    # duplicated synthetic rows (see load_data's docstring), so mixing
    # them into the split first would leak near-identical copies into
    # both train and test, inflating the reported held-out accuracy
    # without actually reflecting real generalization.
    safe_urls, safe_labels = oversampled_known_safe_domains()
    X_train = X_train + safe_urls
    y_train = y_train + safe_labels
    print(f"Added {len(safe_urls)} oversampled known-safe-domain examples to the training set only.")

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
        json.dump({"classes": classes, "report": report, "n_samples": len(urls)}, f, indent=2)

    size_kb = os.path.getsize(MODEL_PATH) / 1024
    print(f"Saved model to {MODEL_PATH} ({size_kb:.0f} KB)")


if __name__ == "__main__":
    main()
