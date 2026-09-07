"""
Persists scan results so a report can be revisited via a shareable link
(/report/<id>) instead of being thrown away after the first render.

SQLite on local disk -- same durability tradeoff as leads.csv (wiped on a
Render free-tier redeploy); fine for a link meant to stay useful for days
or weeks after a scan, not permanent archival.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone

from scanner import Finding, ScanResult

DB_PATH = os.path.join(os.path.dirname(__file__), "scans.db")


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
    return conn


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
