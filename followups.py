"""
Sends a one-time automatic follow-up email 48 hours after a lead gives
their address, if they haven't converted yet -- the one real gap Phase 0
found: PDF/report delivery on submission was already automatic
(app.py's _send_report_email_background), but nudging a lead who never
replies was previously a manual-only action (the "Draft follow-up" button
in /admin, which still exists for anything outside this window or a
message someone wants to review/personalize first).

"Converted" is read off the lead's own status flag (already admin-
editable in /admin) rather than any Fiverr/payment integration -- "won"
or "lost" both mean stop, everything else is fair game once the window
has passed. Each lead gets AT MOST ONE automatic follow-up ever (tracked
in storage.py's lead_followups table), never a drip sequence.

Triggered three ways: an in-process background timer started in app.py
(runs every FOLLOWUP_CHECK_INTERVAL_SECONDS while the dyno is awake --
no paid cron needed for this one), /admin's manual "Send due follow-ups
now" button, and a token-guarded /internal/run-followups route for an
external scheduler if one is ever configured (see the README's
Monitoring section for why a real Render Cron Job costs money on this
plan and isn't set up by default -- same tradeoff would apply here).
"""
from __future__ import annotations

from datetime import datetime, timezone

from ai_narrative import generate_followup_message
from emailer import send_followup_email
from storage import (
    has_lead_followup_been_sent, list_leads, list_recent_scans, load_scan,
    record_lead_followup_sent,
)

FOLLOWUP_DELAY_HOURS = 48
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
# Same restriction as the manual "Draft follow-up" button in app.py --
# a lead already marked quoted/won/lost has moved past the point where an
# automatic "just checking in" nudge makes sense.
ELIGIBLE_STATUSES = ("new", "contacted")


def _hours_since(iso_timestamp: str) -> float:
    then = datetime.fromisoformat(iso_timestamp)
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then).total_seconds() / 3600


def _top_finding_for_target(target: str) -> tuple[str, str]:
    """Best-effort match to the scan that likely produced this lead --
    same approach as app.py's draft_lead_followup route (leads aren't
    linked to a specific scan_id)."""
    for s in list_recent_scans():
        if s["target"] == target:
            loaded = load_scan(s["id"])
            if loaded:
                result, _, _ = loaded
                if result.findings:
                    top = max(result.findings, key=lambda f: SEVERITY_RANK[f.severity])
                    return top.title, top.detail
            break
    return "", ""


def _send_one(lead: dict) -> dict:
    top_title, top_detail = _top_finding_for_target(lead["target"])
    days_since = int(_hours_since(lead["created_at"]) // 24)
    message, source = generate_followup_message(lead["target"], top_title, top_detail, days_since)

    if send_followup_email(lead["email"], lead["target"], message):
        record_lead_followup_sent(lead["id"], message, source)
        return {"lead_id": lead["id"], "email": lead["email"], "status": "sent"}
    return {"lead_id": lead["id"], "email": lead["email"], "status": "skipped: SMTP not configured"}


def run_followup_check() -> list[dict]:
    """Sends the one-time 48h follow-up to every lead that's due. One bad
    lead (a send failure, a missing scan) must never stop the rest --
    same principle as batch.py/monitoring.py. Leads that were skipped
    because SMTP isn't configured are NOT recorded as sent, so they're
    picked up again on the next check once it is."""
    results = []
    for lead in list_leads():
        if lead["status"] not in ELIGIBLE_STATUSES:
            continue
        if _hours_since(lead["created_at"]) < FOLLOWUP_DELAY_HOURS:
            continue
        if has_lead_followup_been_sent(lead["id"]):
            continue
        try:
            results.append(_send_one(lead))
        except Exception as e:
            results.append({"lead_id": lead["id"], "email": lead["email"], "status": f"error: {e}"})
    return results
