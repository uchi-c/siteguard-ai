"""
Shared abuse-protection policy for anything that triggers a real scan
(run_scan() -- outbound requests to a third-party target, plus an
Anthropic API call for the narrative on every reachable one). Used by
both /scan and /batch in app.py/batch.py, so a domain can't be hammered
by just wrapping it in a batch submission instead of single scans.

Per-IP rate limiting (Flask-Limiter, already in app.py) throttles one
requester; this throttles one TARGET regardless of who's asking, and
catches simple bots before a scan ever runs.
"""
from __future__ import annotations

import storage

# "Don't allow the same target scanned more than N times per hour
# regardless of requester" -- generous enough that a legitimate user
# re-checking after a fix isn't blocked, tight enough to stop a target
# from being hammered (each reachable scan costs an outbound request
# burst to that target plus an Anthropic API call for the narrative).
DOMAIN_COOLDOWN_MAX_REQUESTS = 5
DOMAIN_COOLDOWN_WINDOW_MINUTES = 60

# A hidden form field real visitors never see or fill in; a non-empty
# value here means the submission came from an automated form-filler, not
# a person. Deliberately a normal text input styled off-screen rather
# than type="hidden" -- some simple bots skip hidden inputs entirely,
# defeating the point. See index.html for the field itself.
HONEYPOT_FIELD_NAME = "company_website"


def is_honeypot_triggered(form) -> bool:
    return bool((form.get(HONEYPOT_FIELD_NAME) or "").strip())


def is_domain_in_cooldown(target: str) -> bool:
    """target must already be normalized (scanner._normalize_url) --
    caller's responsibility, so "example.com" and "https://example.com/"
    count as the same target."""
    return storage.count_recent_scan_requests(target, DOMAIN_COOLDOWN_WINDOW_MINUTES) >= DOMAIN_COOLDOWN_MAX_REQUESTS
