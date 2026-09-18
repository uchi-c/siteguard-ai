"""
Runs the autonomous re-scan check for every monitored target that's due:
re-scans, diffs findings against the last saved scan for that target, and
records what changed. This is the actual "agent" in the monitoring
workflow -- everything else (the in-process scheduler and
/internal/run-monitoring route in app.py) exists only to trigger this
without a human remembering to click anything.

Each target picks its own re-scan cadence (weekly or monthly, see
MONITOR_INTERVALS) via storage.py's monitored_target_config table --
run_monitoring_check() only actually re-scans a target once that interval
has elapsed since its last check, regardless of how often it's called
(the in-process scheduler ticks far more often than that; see app.py).
Pass force=True (the admin "Run check now" button) to bypass the
schedule and check everything immediately.

Two alert paths on a real change: if the target's config has a
client_email, that client is emailed directly (the actual value of a
paid monitoring retainer -- "we'll tell you if something changes"). If
MONITORING_ALERT_EMAIL is set, a separate combined digest also goes to
the OPERATOR's own inbox regardless of any client_email, same safety
level as the operator emailing themselves a copy of anything else here.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

from ai_narrative import generate_monitoring_digest, generate_narrative
from emailer import send_monitoring_alert_email, send_plain_email
from scanner import Finding, run_scan
from storage import (
    list_monitored_target_configs, list_monitored_targets, load_scan,
    record_monitor_check, save_scan,
)

MONITORING_ALERT_EMAIL = os.environ.get("MONITORING_ALERT_EMAIL", "")

# Render sets RENDER_EXTERNAL_URL automatically on a web service; PUBLIC_BASE_URL
# lets that be overridden (e.g. for local testing). Building the client-facing
# report link this way, rather than Flask's url_for(_external=True), because this
# module runs from a background thread with no active request to derive a host
# from -- see app.py's scheduler.
PUBLIC_BASE_URL = (os.environ.get("PUBLIC_BASE_URL") or os.environ.get("RENDER_EXTERNAL_URL", "")).rstrip("/")

# "weekly/monthly, configurable" -- each monitored target's own choice,
# stored in monitored_target_config. Unconfigured targets (added before
# this existed, or never explicitly set) fall back to DEFAULT_INTERVAL.
MONITOR_INTERVALS = ("weekly", "monthly")
DEFAULT_INTERVAL = "weekly"
INTERVAL_DAYS = {"weekly": 7, "monthly": 30}


def _diff_findings(old_findings: list[Finding], new_findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    old_ids = {f.id for f in old_findings}
    new_ids = {f.id for f in new_findings}
    newly_appeared = [f for f in new_findings if f.id not in old_ids]
    resolved = [f for f in old_findings if f.id not in new_ids]
    return newly_appeared, resolved


def _is_due(monitored: dict, config: dict | None) -> bool:
    if not monitored["last_checked_at"]:
        return True
    interval = (config or {}).get("interval") or DEFAULT_INTERVAL
    days_required = INTERVAL_DAYS.get(interval, INTERVAL_DAYS[DEFAULT_INTERVAL])
    then = datetime.fromisoformat(monitored["last_checked_at"])
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - then) >= timedelta(days=days_required)


def _send_client_alert_if_configured(
    config: dict | None, target: str, scan_id: str, grade: str, score: int,
    new_count: int, resolved_count: int, digest: str,
) -> None:
    client_email = (config or {}).get("client_email") or ""
    if not client_email:
        return
    try:
        report_url = f"{PUBLIC_BASE_URL}/report/{scan_id}" if PUBLIC_BASE_URL else ""
        send_monitoring_alert_email(
            client_email, target, grade, score, new_count, resolved_count, digest, report_url,
        )
    except Exception:
        pass


def _check_one(monitored: dict, config: dict | None) -> dict:
    result = run_scan(monitored["target"])
    if not result.reachable:
        return {"target": monitored["target"], "status": "error", "error": result.error}

    old_findings: list[Finding] = []
    if monitored["last_scan_id"]:
        loaded = load_scan(monitored["last_scan_id"])
        if loaded:
            old_findings = loaded[0].findings

    new_findings, resolved_findings = _diff_findings(old_findings, result.findings)

    narrative, source = generate_narrative(result)
    scan_id = save_scan(result, narrative, source)

    digest = ""
    if new_findings or resolved_findings:
        digest, _ = generate_monitoring_digest(monitored["target"], new_findings, resolved_findings)

    record_monitor_check(monitored["id"], scan_id, len(new_findings), len(resolved_findings), digest)

    if new_findings or resolved_findings:
        _send_client_alert_if_configured(
            config, monitored["target"], scan_id, result.grade, result.score,
            len(new_findings), len(resolved_findings), digest,
        )

    return {
        "target": monitored["target"], "status": "checked", "scan_id": scan_id,
        "new_findings": len(new_findings), "resolved_findings": len(resolved_findings),
    }


def run_monitoring_check(force: bool = False) -> list[dict]:
    """Re-scans every DUE monitored target once (force=True re-scans all
    of them regardless of schedule -- the admin "Run check now" button).
    One bad target must never stop the rest -- same principle as
    batch.py's _scan_one."""
    configs = list_monitored_target_configs()
    results = []
    for monitored in list_monitored_targets():
        config = configs.get(monitored["id"])
        if not force and not _is_due(monitored, config):
            continue
        try:
            results.append(_check_one(monitored, config))
        except Exception as e:
            results.append({"target": monitored["target"], "status": "error", "error": str(e)})

    _send_alert_email_if_configured(results)
    return results


def _send_alert_email_if_configured(results: list[dict]) -> None:
    """Optional: if MONITORING_ALERT_EMAIL is set, one combined digest goes
    to the OPERATOR's own inbox (regardless of any per-target client_email)
    when anything actually changed -- same safety level as the operator
    emailing themselves a copy of a report. Never raises; a bad SMTP
    config shouldn't affect the monitoring run that already completed and
    saved its results."""
    if not MONITORING_ALERT_EMAIL:
        return
    changed = [r for r in results if r.get("status") == "checked" and r.get("new_findings")]
    if not changed:
        return
    try:
        lines = [f"- {r['target']}: {r['new_findings']} new finding(s)" for r in changed]
        body = "Monitoring found changes on:\n\n" + "\n".join(lines) + "\n\nCheck /admin for details."
        send_plain_email(
            MONITORING_ALERT_EMAIL,
            f"SiteGuard AI monitoring: {len(changed)} target(s) with new findings",
            body,
        )
    except Exception:
        pass
