"""
Checks whether a URL is a known malicious/phishing site -- a different
question from everything else in this app. scanner.py/active_scan.py ask
"is THIS site configured securely"; this asks "is this URL itself
dangerous" (reputation/threat lookup), and never fetches the destination
at all -- no SSRF concern, no active-testing-style gating needed, safe to
expose publicly.

Google Safe Browsing (a live, constantly-updated threat database) is the
primary source when GOOGLE_SAFE_BROWSING_API_KEY is set. Without a key, or
if the API call fails, this falls back to a known-safe-domain allowlist
(known_domains.py) and then url_classifier.py (a small locally-trained
model, same approach as payload_classifier.py) -- weaker than a live
feed, so its verdict is deliberately hedged ("suspicious", not
"malicious"). The allowlist exists because of a real bug found while
building this: the ML model's training data skews toward deep-linked
"benign" pages rather than bare domain homepages, so it confidently
mis-flagged google.com/wikipedia.org as phishing -- see known_domains.py
for the full story.

Language matters here: Safe Browsing returning no match means "not on our
known-bad list," not "confirmed safe" -- a URL can be malicious without
being cataloged yet. Nothing in this module ever claims a URL is safe,
only that no known threat was found.
"""
from __future__ import annotations

import os
from urllib.parse import urlparse

import requests

from known_domains import KNOWN_SAFE_DOMAINS
from scanner import _normalize_url

SAFE_BROWSING_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
TIMEOUT = 8

# Google's threat type -> a friendly label for the UI. SOCIAL_ENGINEERING
# is Safe Browsing's name for phishing.
THREAT_LABELS = {
    "MALWARE": "malware",
    "SOCIAL_ENGINEERING": "phishing",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful app",
}

# Below this confidence, the ML fallback's opinion isn't worth surfacing --
# a static model trained once is noisy near the decision boundary, and a
# low-confidence "suspicious" verdict would just be alarmist.
ML_CONFIDENCE_THRESHOLD = 0.6


def _check_safe_browsing(url: str) -> dict | None:
    """Returns a result dict, or None if the API is unusable (no key, or
    the call failed) -- callers treat None as "fall back to the ML path."
    """
    if not SAFE_BROWSING_API_KEY:
        return None
    try:
        resp = requests.post(
            SAFE_BROWSING_URL,
            params={"key": SAFE_BROWSING_API_KEY},
            json={
                "client": {"clientId": "siteguard-ai", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": list(THREAT_LABELS.keys()),
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            },
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
    except (requests.RequestException, ValueError):
        return None

    threats = sorted({THREAT_LABELS.get(m.get("threatType", ""), "unknown threat") for m in matches})
    return {
        "verdict": "malicious" if threats else "no-known-threats",
        "threats": threats,
        "source": "safe-browsing",
        "confidence": None,
    }


def _is_known_safe_domain(url: str) -> bool:
    hostname = (urlparse(url).hostname or "").lower()
    return hostname in KNOWN_SAFE_DOMAINS


def _check_ml_fallback(url: str) -> dict:
    if _is_known_safe_domain(url):
        return {"verdict": "no-known-threats", "threats": [], "source": "allowlist", "confidence": None}

    import url_classifier

    if not url_classifier.is_available():
        return {"verdict": "unavailable", "threats": [], "source": "none", "confidence": None}

    result = url_classifier.classify_url(url)
    if "error" in result:
        return {"verdict": "unavailable", "threats": [], "source": "none", "confidence": None}

    if result["label"] != "benign" and result["confidence"] >= ML_CONFIDENCE_THRESHOLD:
        return {
            "verdict": "suspicious", "threats": [result["label"]],
            "source": "ml", "confidence": result["confidence"],
        }
    return {
        "verdict": "no-known-threats", "threats": [],
        "source": "ml", "confidence": result["confidence"],
    }


def check_url(url: str) -> dict:
    """Returns {url, verdict, threats, source, confidence}. verdict is one
    of "malicious", "suspicious", "no-known-threats", or "unavailable"."""
    normalized = _normalize_url(url)

    result = _check_safe_browsing(normalized)
    if result is None:
        result = _check_ml_fallback(normalized)

    return {"url": normalized, **result}
