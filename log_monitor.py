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

Also handles Cloudflare Logpush directly (record_cloudflare_batch): a
client points a Logpush HTTP destination job at their /ingest/cloudflare/
URL and every EdgeResponseStatus 404/5xx Cloudflare's edge sees feeds the
same rules below, no code change on the client's side. Cloudflare's wire
format (ndjson batches, a one-time gzip validation payload, no ownership
challenge for HTTP destinations) is unrelated to the generic webhook's
JSON schema, so it's parsed separately and then handed to record_events
once mapped into the same event shape -- one rule engine, two ingestion
paths.

Still deferred, not built here: Vercel/Render log push, and letting a
client define their own rules. Both are real follow-ups, each sizable
enough to scope on their own.
"""
from __future__ import annotations

import gzip
import json
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


# --- Cloudflare Logpush -----------------------------------------------------
#
# Cloudflare posts two very different bodies to an HTTP destination, both
# possibly gzip-compressed on the wire: a one-time validation upload made
# when the job is created (must succeed or job creation is refused), and
# real batches of newline-delimited JSON, one line per HTTP request. We
# ask clients to configure the job with exactly the fields below (see
# CLOUDFLARE_SETUP_FIELDS / the setup instructions in log_events.html) so
# mapping stays a fixed, known shape rather than a general parser.

CLOUDFLARE_VALIDATION_PAYLOAD = '{"content":"tests"}'
CLOUDFLARE_SETUP_FIELDS = (
    "ClientIP", "ClientRequestMethod", "ClientRequestURI", "EdgeResponseStatus",
    "EdgeStartTimestamp",
)
# Cloudflare's own max_upload_records floor is 1,000; we ask clients to set
# their job to that, and cap defensively at the same number regardless of
# what a job is actually configured to send.
CLOUDFLARE_MAX_RECORDS_PER_BATCH = 1000


def _cloudflare_decompress(raw_body: bytes) -> bytes:
    if not isinstance(raw_body, (bytes, bytearray)):
        return b""
    if bytes(raw_body[:2]) == b"\x1f\x8b":
        try:
            return gzip.decompress(raw_body)
        except OSError:
            return bytes(raw_body)  # not actually valid gzip -- fall through as-is
    return bytes(raw_body)


def _map_cloudflare_record(row: dict) -> dict | None:
    """Translates one http_requests dataset record into our internal event
    shape. Only 404s and 5xx responses map to anything -- everything else
    (the vast majority of any site's traffic) isn't signal any of our
    fixed rules act on, so it's dropped here rather than stored."""
    if not isinstance(row, dict):
        return None
    status = row.get("EdgeResponseStatus")
    occurred_at = row.get("EdgeStartTimestamp")
    if not isinstance(occurred_at, str):
        occurred_at = None  # only rfc3339 strings parse; numeric formats are dropped, not guessed at

    if status == 404:
        return {"type": "http_404", "ip": row.get("ClientIP"), "path": row.get("ClientRequestURI"),
                "occurred_at": occurred_at}
    if isinstance(status, int) and status >= 500:
        method = row.get("ClientRequestMethod") or ""
        path = row.get("ClientRequestURI") or ""
        return {
            "type": "error", "severity": "critical", "ip": row.get("ClientIP"), "path": path,
            "occurred_at": occurred_at, "message": f"{status} from origin on {method} {path}".strip(),
        }
    return None


def record_cloudflare_batch(token: str, raw_body: bytes, fallback_ip: str) -> dict:
    """Entry point for POST /ingest/cloudflare/<token>. Never raises: a
    malformed or unexpected body must not turn into a 500, since Cloudflare
    marks a Logpush job unhealthy (and eventually disables it) after
    repeated destination failures -- exactly what we must never cause for
    a body shape we simply didn't anticipate."""
    if not get_target_id_for_token(token):
        return {"accepted": False, "error": "unknown or disabled token"}

    text = _cloudflare_decompress(raw_body).decode("utf-8", errors="replace").strip()
    if text == CLOUDFLARE_VALIDATION_PAYLOAD:
        # The one-time destination-ownership upload Cloudflare makes before
        # allowing the job to go live -- acknowledge it, nothing to store.
        return {"accepted": True, "validation": True, "stored": 0, "skipped": 0, "alerts": []}

    mapped, malformed = [], 0
    for line in text.splitlines()[:CLOUDFLARE_MAX_RECORDS_PER_BATCH]:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            malformed += 1
            continue
        event = _map_cloudflare_record(row)
        if event is not None:
            mapped.append(event)

    result = record_events(token, mapped, fallback_ip)
    result["skipped"] = result.get("skipped", 0) + malformed
    return result
