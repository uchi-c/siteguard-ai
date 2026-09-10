"""
Persists scan results (so a report can be revisited via a shareable link,
/report/<id>, instead of being thrown away after the first render), leads
(email + target + grade/score, plus an editable status/notes pair for
working them as a pipeline -- new/contacted/quoted/won/lost), and
monitored targets (a target flagged for recurring re-scans, with the
result of its last check -- see monitoring.py for the actual re-scan/diff
logic that reads and writes these rows).

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
from datetime import datetime, timezone

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
        conn.commit()
        return cur.rowcount > 0


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
