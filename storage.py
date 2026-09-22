"""
Persists scan results (so a report can be revisited via a shareable link,
/report/<id>, instead of being thrown away after the first render), leads
(email + target + grade/score, plus an editable status/notes pair for
working them as a pipeline -- new/contacted/quoted/won/lost), monitored
targets (a target flagged for recurring re-scans, with the result of its
last check -- see monitoring.py for the actual re-scan/diff logic that
reads and writes these rows) plus a separate per-target config (re-scan
interval, client email for direct alerts -- kept in its own table rather
than added as columns on the already-deployed monitored_targets, same
reasoning as every other table here), a scan-request log (every /scan and
/batch attempt, including ones blocked by the honeypot/cooldown/rate
limiter -- see abuse_guard.py) for abuse visibility in /admin, and a
lead-followups log recording which leads have already gotten their
one-time automatic 48h nudge (see followups.py), so a lead is never
emailed twice by the scheduler, and log-event ingestion for the optional
"log monitoring" add-on (see log_monitor.py) -- a per-target token and
enabled flag (log_ingest_targets) plus the events a client's own app
pushes in (log_events), pruned on a rolling window so this stays bounded
on SQLite.

SQLite on local disk -- ephemeral on a Render free-tier redeploy; fine for
a link meant to stay useful for days or weeks, and for a lead list you'd
want to export before any redeploy that might wipe it, not permanent
archival.
"""
from __future__ import annotations

import csv
import json
import os
import secrets
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from scanner import Finding, ScanResult

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")

LEAD_STATUSES = ["new", "contacted", "quoted", "won", "lost"]


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scans ("
        "id TEXT PRIMARY KEY, "
        "created_at TEXT NOT NULL, "
        "target TEXT NOT NULL, "
        "data TEXT NOT NULL, "
        "narrative TEXT, "
        "narrative_source TEXT)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS active_scan_audit ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "created_at TEXT NOT NULL, "
        "target TEXT NOT NULL, "
        "hostname TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS leads ("
        "id TEXT PRIMARY KEY, "
        "created_at TEXT NOT NULL, "
        "email TEXT NOT NULL, "
        "target TEXT NOT NULL, "
        "grade TEXT, "
        "score INTEGER, "
        "status TEXT NOT NULL DEFAULT 'new', "
        "notes TEXT NOT NULL DEFAULT '')"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS scan_requests ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "created_at TEXT NOT NULL, "
        "source_ip TEXT NOT NULL, "
        "target TEXT NOT NULL, "
        "result_summary TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS lead_followups ("
        "lead_id TEXT PRIMARY KEY, "
        "sent_at TEXT NOT NULL, "
        "message TEXT NOT NULL, "
        "source TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS monitored_targets ("
        "id TEXT PRIMARY KEY, "
        "target TEXT NOT NULL UNIQUE, "
        "added_at TEXT NOT NULL, "
        "last_checked_at TEXT, "
        "last_scan_id TEXT, "
        "last_new_count INTEGER NOT NULL DEFAULT 0, "
        "last_resolved_count INTEGER NOT NULL DEFAULT 0, "
        "last_digest TEXT NOT NULL DEFAULT '')"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS monitored_target_config ("
        "target_id TEXT PRIMARY KEY, "
        "interval TEXT NOT NULL DEFAULT 'weekly', "
        "client_email TEXT NOT NULL DEFAULT '')"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS log_ingest_targets ("
        "target_id TEXT PRIMARY KEY, "
        "token TEXT NOT NULL UNIQUE, "
        "enabled INTEGER NOT NULL DEFAULT 1, "
        "created_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS log_events ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "target_id TEXT NOT NULL, "
        "event_type TEXT NOT NULL, "
        "source_ip TEXT NOT NULL DEFAULT '', "
        "path TEXT NOT NULL DEFAULT '', "
        "message TEXT NOT NULL DEFAULT '', "
        "occurred_at TEXT NOT NULL, "
        "received_at TEXT NOT NULL)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_log_events_target_received "
        "ON log_events (target_id, received_at)"
    )
    conn.execute(
        "CREATE TABLE IF NOT EXISTS log_alert_cooldowns ("
        "target_id TEXT NOT NULL, "
        "rule TEXT NOT NULL, "
        "source_ip TEXT NOT NULL, "
        "last_alerted_at TEXT NOT NULL, "
        "PRIMARY KEY (target_id, rule, source_ip))"
    )
    return conn


def save_lead(email: str, target: str, grade: str, score: int) -> str:
    lead_id = secrets.token_urlsafe(8)
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT INTO leads (id, created_at, email, target, grade, score, status, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, 'new', '')",
            (lead_id, datetime.now(timezone.utc).isoformat(), email, target, grade, score),
        )
        conn.commit()
    return lead_id


def list_leads(limit: int = 200) -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT id, created_at, email, target, grade, score, status, notes "
            "FROM leads ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {"id": r[0], "created_at": r[1], "email": r[2], "target": r[3],
         "grade": r[4], "score": r[5], "status": r[6], "notes": r[7]}
        for r in rows
    ]


def get_lead(lead_id: str) -> dict | None:
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT id, created_at, email, target, grade, score, status, notes "
            "FROM leads WHERE id = ?",
            (lead_id,),
        ).fetchone()
    if not row:
        return None
    return {"id": row[0], "created_at": row[1], "email": row[2], "target": row[3],
            "grade": row[4], "score": row[5], "status": row[6], "notes": row[7]}


def update_lead(lead_id: str, status: str, notes: str) -> bool:
    if status not in LEAD_STATUSES:
        raise ValueError(f"invalid status: {status!r}")
    with closing(_connect()) as conn:
        cur = conn.execute(
            "UPDATE leads SET status = ?, notes = ? WHERE id = ?", (status, notes, lead_id),
        )
        conn.commit()
        return cur.rowcount > 0


def import_leads_csv_once(csv_path: str) -> int:
    """One-time migration: leads used to live only in a flat leads.csv,
    appended to but never updated. Now that leads are per-row SQLite
    records with an editable status, this imports any existing CSV rows
    into the leads table (as status='new') so history isn't lost --
    but only if the table is still empty, so it never re-imports or
    duplicates rows on later calls. Safe to call unconditionally at
    startup."""
    if not os.path.exists(csv_path):
        return 0
    with closing(_connect()) as conn:
        already_migrated = conn.execute("SELECT COUNT(*) FROM leads").fetchone()[0]
        if already_migrated:
            return 0
        imported = 0
        with open(csv_path, newline="") as f:
            for row in csv.DictReader(f):
                score_raw = row.get("score", "")
                conn.execute(
                    "INSERT INTO leads (id, created_at, email, target, grade, score, status, notes) "
                    "VALUES (?, ?, ?, ?, ?, ?, 'new', '')",
                    (secrets.token_urlsafe(8), row.get("timestamp_utc", ""), row.get("email", ""),
                     row.get("target", ""), row.get("grade", ""),
                     int(score_raw) if score_raw.isdigit() else 0),
                )
                imported += 1
        conn.commit()
    return imported


def log_active_scan_authorization(target: str, hostname: str) -> None:
    """Audit trail for the gated active-testing mode: every run is logged
    with the target and the confirmed hostname, regardless of outcome."""
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT INTO active_scan_audit (created_at, target, hostname) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), target, hostname),
        )
        conn.commit()


def list_active_scan_audit(limit: int = 50) -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT created_at, target, hostname FROM active_scan_audit "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"created_at": c, "target": t, "hostname": h} for c, t, h in rows]


def save_scan(result: ScanResult, narrative: str, narrative_source: str) -> str:
    scan_id = secrets.token_urlsafe(8)
    payload = json.dumps({
        "target": result.target,
        "scanned_at": result.scanned_at,
        "findings": [asdict(f) for f in result.findings],
        "reachable": result.reachable,
        "error": result.error,
        "js_files_checked": result.js_files_checked,
    })
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT INTO scans (id, created_at, target, data, narrative, narrative_source) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (scan_id, datetime.now(timezone.utc).isoformat(), result.target, payload,
             narrative, narrative_source),
        )
        conn.commit()
    return scan_id


def load_scan(scan_id: str) -> tuple[ScanResult, str, str] | None:
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT data, narrative, narrative_source FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if not row:
        return None
    data, narrative, narrative_source = row
    d = json.loads(data)
    result = ScanResult(
        target=d["target"],
        scanned_at=d["scanned_at"],
        findings=[Finding(**f) for f in d["findings"]],
        reachable=d["reachable"],
        error=d["error"],
        js_files_checked=d.get("js_files_checked"),  # absent on scans saved before this existed
    )
    return result, narrative, narrative_source


def list_recent_scans(limit: int = 50) -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT id, created_at, target, data FROM scans ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()

    out = []
    for scan_id, created_at, target, data in rows:
        d = json.loads(data)
        result = ScanResult(
            target=d["target"],
            scanned_at=d["scanned_at"],
            findings=[Finding(**f) for f in d["findings"]],
            reachable=d["reachable"],
            error=d["error"],
        )
        out.append({
            "id": scan_id,
            "created_at": created_at,
            "target": target,
            "grade": result.grade,
            "score": result.score,
        })
    return out


# --- Scan request log (abuse visibility + per-domain cooldown) ---------------

def log_scan_request(source_ip: str, target: str, result_summary: str) -> None:
    """Records every /scan (and /batch sub-scan) attempt that reaches a
    real target string -- including ones blocked by the honeypot, domain
    cooldown, or rate limiter, not just completed scans, so this is an
    actual abuse-visibility log rather than just a success log. Also the
    source of truth for count_recent_scan_requests's cooldown check."""
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT INTO scan_requests (created_at, source_ip, target, result_summary) "
            "VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), source_ip, target, result_summary),
        )
        conn.commit()


def list_scan_requests(limit: int = 200) -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT created_at, source_ip, target, result_summary FROM scan_requests "
            "ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [{"created_at": c, "source_ip": ip, "target": t, "result_summary": r} for c, ip, t, r in rows]


def count_recent_scan_requests(target: str, since_minutes: int) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM scan_requests WHERE target = ? AND created_at >= ?",
            (target, cutoff),
        ).fetchone()
    return row[0]


# --- Lead follow-ups (one-time automatic 48h nudge) --------------------------

def record_lead_followup_sent(lead_id: str, message: str, source: str) -> None:
    """One row per lead, ever -- INSERT OR REPLACE so a retry after a rare
    failure-then-success doesn't need a separate upsert path, but in
    practice this is only called once a send actually succeeds."""
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO lead_followups (lead_id, sent_at, message, source) "
            "VALUES (?, ?, ?, ?)",
            (lead_id, datetime.now(timezone.utc).isoformat(), message, source),
        )
        conn.commit()


def has_lead_followup_been_sent(lead_id: str) -> bool:
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT 1 FROM lead_followups WHERE lead_id = ?", (lead_id,)
        ).fetchone()
    return row is not None


def list_lead_followups() -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT lead_id, sent_at, message, source FROM lead_followups ORDER BY sent_at DESC"
        ).fetchall()
    return [{"lead_id": r[0], "sent_at": r[1], "message": r[2], "source": r[3]} for r in rows]


# --- Monitored targets (autonomous re-scan tracking) -------------------------

def add_monitored_target(target: str) -> str:
    """Idempotent: adding an already-monitored target just returns its
    existing id rather than erroring or creating a duplicate row."""
    with closing(_connect()) as conn:
        existing = conn.execute(
            "SELECT id FROM monitored_targets WHERE target = ?", (target,)
        ).fetchone()
        if existing:
            return existing[0]
        target_id = secrets.token_urlsafe(8)
        conn.execute(
            "INSERT INTO monitored_targets "
            "(id, target, added_at, last_checked_at, last_scan_id, "
            "last_new_count, last_resolved_count, last_digest) "
            "VALUES (?, ?, ?, NULL, NULL, 0, 0, '')",
            (target_id, target, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return target_id


def list_monitored_targets() -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT id, target, added_at, last_checked_at, last_scan_id, "
            "last_new_count, last_resolved_count, last_digest "
            "FROM monitored_targets ORDER BY added_at DESC"
        ).fetchall()
    return [
        {"id": r[0], "target": r[1], "added_at": r[2], "last_checked_at": r[3],
         "last_scan_id": r[4], "last_new_count": r[5], "last_resolved_count": r[6],
         "last_digest": r[7]}
        for r in rows
    ]


def is_monitored(target: str) -> bool:
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT 1 FROM monitored_targets WHERE target = ?", (target,)
        ).fetchone()
    return row is not None


def remove_monitored_target(target_id: str) -> bool:
    with closing(_connect()) as conn:
        cur = conn.execute("DELETE FROM monitored_targets WHERE id = ?", (target_id,))
        conn.execute("DELETE FROM monitored_target_config WHERE target_id = ?", (target_id,))
        conn.execute("DELETE FROM log_ingest_targets WHERE target_id = ?", (target_id,))
        conn.execute("DELETE FROM log_events WHERE target_id = ?", (target_id,))
        conn.commit()
        return cur.rowcount > 0


def set_monitored_target_config(target_id: str, interval: str, client_email: str) -> None:
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT INTO monitored_target_config (target_id, interval, client_email) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(target_id) DO UPDATE SET interval = excluded.interval, "
            "client_email = excluded.client_email",
            (target_id, interval, client_email),
        )
        conn.commit()


def list_monitored_target_configs() -> dict[str, dict]:
    """Keyed by target_id -- monitoring.py joins this against
    list_monitored_targets() in Python rather than a SQL join, since a
    target with no config row yet (added before this existed, or never
    configured) should just fall back to defaults, not be excluded."""
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT target_id, interval, client_email FROM monitored_target_config"
        ).fetchall()
    return {r[0]: {"target_id": r[0], "interval": r[1], "client_email": r[2]} for r in rows}


def record_monitor_check(
    target_id: str, scan_id: str, new_count: int, resolved_count: int, digest: str,
) -> None:
    with closing(_connect()) as conn:
        conn.execute(
            "UPDATE monitored_targets SET last_checked_at = ?, last_scan_id = ?, "
            "last_new_count = ?, last_resolved_count = ?, last_digest = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), scan_id, new_count, resolved_count,
             digest, target_id),
        )
        conn.commit()


# --- Log ingestion (client-pushed security events -> rule-based alerts) ------

def enable_log_ingest(target_id: str) -> str:
    """Idempotent: a target that already has ingestion enabled just gets its
    existing token back rather than a new one, so re-clicking "Enable" in
    /admin never silently breaks a client's already-configured webhook."""
    with closing(_connect()) as conn:
        existing = conn.execute(
            "SELECT token FROM log_ingest_targets WHERE target_id = ?", (target_id,)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE log_ingest_targets SET enabled = 1 WHERE target_id = ?", (target_id,)
            )
            conn.commit()
            return existing[0]
        token = secrets.token_urlsafe(24)
        conn.execute(
            "INSERT INTO log_ingest_targets (target_id, token, enabled, created_at) "
            "VALUES (?, ?, 1, ?)",
            (target_id, token, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        return token


def regenerate_log_ingest_token(target_id: str) -> str | None:
    """Invalidates the old token immediately -- for when a client's webhook
    URL may have leaked. Returns None if this target never had ingestion
    enabled at all."""
    with closing(_connect()) as conn:
        existing = conn.execute(
            "SELECT target_id FROM log_ingest_targets WHERE target_id = ?", (target_id,)
        ).fetchone()
        if not existing:
            return None
        token = secrets.token_urlsafe(24)
        conn.execute(
            "UPDATE log_ingest_targets SET token = ?, enabled = 1 WHERE target_id = ?",
            (token, target_id),
        )
        conn.commit()
        return token


def disable_log_ingest(target_id: str) -> None:
    with closing(_connect()) as conn:
        conn.execute("UPDATE log_ingest_targets SET enabled = 0 WHERE target_id = ?", (target_id,))
        conn.commit()


def get_log_ingest_config(target_id: str) -> dict | None:
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT target_id, token, enabled, created_at FROM log_ingest_targets WHERE target_id = ?",
            (target_id,),
        ).fetchone()
    if not row:
        return None
    return {"target_id": row[0], "token": row[1], "enabled": bool(row[2]), "created_at": row[3]}


def list_log_ingest_configs() -> dict[str, dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT target_id, token, enabled, created_at FROM log_ingest_targets"
        ).fetchall()
    return {
        r[0]: {"target_id": r[0], "token": r[1], "enabled": bool(r[2]), "created_at": r[3]}
        for r in rows
    }


def get_target_id_for_token(token: str) -> str | None:
    """Only returns a target for a token that's currently enabled -- a
    disabled/rotated token must be rejected exactly like an unknown one,
    not just hidden from the admin UI."""
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT target_id FROM log_ingest_targets WHERE token = ? AND enabled = 1", (token,)
        ).fetchone()
    return row[0] if row else None


def insert_log_event(target_id: str, event_type: str, source_ip: str, path: str, message: str,
                      occurred_at: str | None) -> None:
    with closing(_connect()) as conn:
        conn.execute(
            "INSERT INTO log_events (target_id, event_type, source_ip, path, message, "
            "occurred_at, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (target_id, event_type, source_ip, path, message,
             occurred_at or datetime.now(timezone.utc).isoformat(),
             datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()


def count_recent_log_events(target_id: str, event_type: str, source_ip: str, since_minutes: int) -> int:
    """Windowed on received_at (server clock), not the client-supplied
    occurred_at -- occurred_at is untrusted input and must never be able to
    push an event in or out of a detection window."""
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT COUNT(*) FROM log_events "
            "WHERE target_id = ? AND event_type = ? AND source_ip = ? AND received_at >= ?",
            (target_id, event_type, source_ip, cutoff),
        ).fetchone()
    return row[0]


def list_recent_log_events(target_id: str, limit: int = 100) -> list[dict]:
    with closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT id, event_type, source_ip, path, message, occurred_at, received_at "
            "FROM log_events WHERE target_id = ? ORDER BY received_at DESC LIMIT ?",
            (target_id, limit),
        ).fetchall()
    return [
        {"id": r[0], "event_type": r[1], "source_ip": r[2], "path": r[3], "message": r[4],
         "occurred_at": r[5], "received_at": r[6]}
        for r in rows
    ]


def try_claim_alert_cooldown(target_id: str, rule: str, source_ip: str, cooldown_minutes: int) -> bool:
    """Atomically checks whether (target_id, rule, source_ip) is past its
    cooldown and, if so, claims it (records now as the last-alerted time)
    in the same call -- log_monitor.py relies on this to send at most one
    alert per window even if many events cross the threshold at once."""
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(minutes=cooldown_minutes)).isoformat()
    with closing(_connect()) as conn:
        row = conn.execute(
            "SELECT last_alerted_at FROM log_alert_cooldowns "
            "WHERE target_id = ? AND rule = ? AND source_ip = ?",
            (target_id, rule, source_ip),
        ).fetchone()
        if row and row[0] >= cutoff:
            return False
        conn.execute(
            "INSERT INTO log_alert_cooldowns (target_id, rule, source_ip, last_alerted_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(target_id, rule, source_ip) DO UPDATE SET last_alerted_at = excluded.last_alerted_at",
            (target_id, rule, source_ip, now.isoformat()),
        )
        conn.commit()
        return True


def prune_old_log_events(older_than_days: int = 30) -> int:
    """Keeps log_events from growing without bound on SQLite -- called on
    every scheduler tick (see app.py), not just once, so a target that logs
    heavily can't outrun it between deploys."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
    with closing(_connect()) as conn:
        cur = conn.execute("DELETE FROM log_events WHERE received_at < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
