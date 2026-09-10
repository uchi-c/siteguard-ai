"""
Runs the autonomous re-scan check for every monitored target: re-scans,
diffs findings against the last saved scan for that target, and records
what changed. This is the actual "agent" in the monitoring workflow --
everything else (the Render Cron Job, the /internal/run-monitoring route
in app.py) exists only to trigger this on a schedule without a human
remembering to click anything.

Deliberately does not email or notify the client automatically -- what
changed is surfaced in /admin for the operator to review and decide what
(if anything) to send, same human-in-the-loop principle as the lead
follow-up drafts. The one exception is MONITORING_ALERT_EMAIL: if set, a
digest goes to the OPERATOR's own inbox (not the client's), same safety
level as the operator emailing themselves a copy of anything else here.
"""
from __future__ import annotations

import os

from ai_narrative import generate_monitoring_digest, generate_narrative
from emailer import send_plain_email
from scanner import Finding, run_scan
from storage import list_monitored_targets, load_scan, record_monitor_check, save_scan

MONITORING_ALERT_EMAIL = os.environ.get("MONITORING_ALERT_EMAIL", "")


def _diff_findings(old_findings: list[Finding], new_findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    old_ids = {f.id for f in old_findings}
    new_ids = {f.id for f in new_findings}
    newly_appeared = [f for f in new_findings if f.id not in old_ids]
    resolved = [f for f in old_findings if f.id not in new_ids]
    return newly_appeared, resolved


def _check_one(monitored: dict) -> dict:
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
    return {
        "target": monitored["target"], "status": "checked", "scan_id": scan_id,
        "new_findings": len(new_findings), "resolved_findings": len(resolved_findings),
    }


def run_monitoring_check() -> list[dict]:
    """Re-scans every monitored target once. One bad target must never
    stop the rest -- same principle as batch.py's _scan_one."""
    results = []
    for monitored in list_monitored_targets():
        try:
            results.append(_check_one(monitored))
        except Exception as e:
            results.append({"target": monitored["target"], "status": "error", "error": str(e)})

    _send_alert_email_if_configured(results)
    return results


def _send_alert_email_if_configured(results: list[dict]) -> None:
    """Optional: if MONITORING_ALERT_EMAIL is set, one combined digest goes
    to the OPERATOR's own inbox (never a client's) when anything actually
    changed -- same safety level as the operator emailing themselves a
    copy of a report. Never raises; a bad SMTP config shouldn't affect the
    monitoring run that already completed and saved its results."""
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
