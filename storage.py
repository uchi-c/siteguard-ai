"""
Persists scan results (so a report can be revisited via a shareable link,
/report/<id>, instead of being thrown away after the first render) and
leads (email + target + grade/score, plus an editable status/notes pair
for working them as a pipeline -- new/contacted/quoted/won/lost).

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
