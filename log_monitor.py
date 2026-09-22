"""
Rule-based alerting on security events a client's own app pushes to
SiteGuard -- the "log monitoring" add-on, one tier above the passive
re-scan monitoring in monitoring.py. Nothing here scans or probes
anything; every event arrives because the client's own code POSTed it (see
app.py's POST /ingest/<token> route), the same trust model as the client
choosing to grant repo access for the Advanced audit tier.

v1 ships a small FIXED set of rules against a small FIXED set of event
types -- deliberately narrow rather than a general-purpose SIEM rule
engine (which would be a much bigger build): brute-force login attempts,
automated 404 scanning/probing, and client-flagged critical errors. Each
rule fires at most once per (target, rule, source IP) every
ALERT_COOLDOWN_MINUTES, however many events cross the threshold in that
window, so an active attack sends one alert, not one per request.

Explicitly deferred, not built here: ingesting logs directly from a
hosting platform (Cloudflare/Vercel/Render log push) rather than a
client-added webhook call, and letting a client define their own rules.
Both are real follow-ups, each sizable enough to scope on their own.
"""
from __future__ import annotations

from datetime import datetime

from emailer import send_log_alert_email
from storage import (
    count_recent_log_events, get_target_id_for_token, insert_log_event,
    list_monitored_target_configs, try_claim_alert_cooldown,
)

MAX_EVENTS_PER_REQUEST = 20
MAX_MESSAGE_LENGTH = 500
MAX_PATH_LENGTH = 200
MAX_IP_LENGTH = 64

EVENT_TYPES = ("login_failure", "http_403", "http_404", "error")

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 10
SCAN_THRESHOLD = 20
SCAN_WINDOW_MINUTES = 5
# However many events cross a rule's threshold in one window, at most one
# alert goes out per (target, rule, source IP) this often.
ALERT_COOLDOWN_MINUTES = 30


def _clean_str(value, max_len: int) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_len]


def _parse_event(raw: dict, fallback_ip: str) -> dict | None:
    if not isinstance(raw, dict):
        return None
    event_type = raw.get("type")
    if event_type not in EVENT_TYPES:
        return None

    occurred_at = raw.get("occurred_at")
    if isinstance(occurred_at, str):
        try:
            datetime.fromisoformat(occurred_at)
        except ValueError:
            occurred_at = None
    else:
        occurred_at = None

    return {
        "type": event_type,
        "ip": _clean_str(raw.get("ip"), MAX_IP_LENGTH) or fallback_ip,
        "path": _clean_str(raw.get("path"), MAX_PATH_LENGTH),
        "message": _clean_str(raw.get("message"), MAX_MESSAGE_LENGTH),
        "severity": _clean_str(raw.get("severity"), 20).lower(),
        "occurred_at": occurred_at,
    }


def _rule_threshold_crossed(target_id: str, rule: str, event_type: str, ip: str,
                             threshold: int, window_minutes: int) -> bool:
    if count_recent_log_events(target_id, event_type, ip, window_minutes) < threshold:
        return False
    return try_claim_alert_cooldown(target_id, rule, ip, ALERT_COOLDOWN_MINUTES)


def _send_alert(target_id: str, headline: str, detail: str) -> None:
    # The alert destination lives in monitored_target_config (set from
    # /admin alongside the re-scan interval) rather than duplicated here --
    # one client email per target, however many features use it.
    client_email = (list_monitored_target_configs().get(target_id) or {}).get("client_email") or ""
    if not client_email:
        return
    try:
        send_log_alert_email(client_email, headline, detail)
    except Exception:
        pass


def record_events(token: str, raw_events, fallback_ip: str) -> dict:
    """Validates and stores up to MAX_EVENTS_PER_REQUEST events for the
    target this token belongs to, then evaluates the fixed rule set.
    Never raises on bad input -- an unknown token or malformed event is
    reported back in the result, not an exception, since the caller is an
    unauthenticated client webhook that must never see a 500 for sending
    something odd."""
    target_id = get_target_id_for_token(token)
    if not target_id:
        return {"accepted": False, "error": "unknown or disabled token"}

    if not isinstance(raw_events, list):
        raw_events = [raw_events]
    truncated = len(raw_events) > MAX_EVENTS_PER_REQUEST
    raw_events = raw_events[:MAX_EVENTS_PER_REQUEST]

    stored, skipped, alerts = 0, 0, []
    for raw in raw_events:
        event = _parse_event(raw, fallback_ip)
        if event is None:
            skipped += 1
            continue
        insert_log_event(target_id, event["type"], event["ip"], event["path"], event["message"],
                          event["occurred_at"])
        stored += 1

        if event["type"] == "login_failure" and _rule_threshold_crossed(
            target_id, "brute-force", "login_failure", event["ip"],
            BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW_MINUTES,
        ):
            alerts.append("brute-force")
            _send_alert(
                target_id, f"Possible brute-force attempt from {event['ip']}",
                f"{BRUTE_FORCE_THRESHOLD}+ failed logins from {event['ip']} in the last "
                f"{BRUTE_FORCE_WINDOW_MINUTES} minutes.",
            )
        elif event["type"] == "http_404" and _rule_threshold_crossed(
            target_id, "scanning", "http_404", event["ip"], SCAN_THRESHOLD, SCAN_WINDOW_MINUTES,
        ):
            alerts.append("scanning")
            _send_alert(
                target_id, f"Possible scanning/probing from {event['ip']}",
                f"{SCAN_THRESHOLD}+ not-found requests from {event['ip']} in the last "
                f"{SCAN_WINDOW_MINUTES} minutes -- may be automated probing for hidden paths.",
            )
        elif event["type"] == "error" and event["severity"] == "critical":
            if try_claim_alert_cooldown(target_id, "critical-error", event["ip"] or "-",
                                        ALERT_COOLDOWN_MINUTES):
                alerts.append("critical-error")
                _send_alert(
                    target_id, "Critical error reported by your app",
                    event["message"] or "(no message provided)",
                )

    return {"accepted": True, "stored": stored, "skipped": skipped, "truncated": truncated,
            "alerts": alerts}
