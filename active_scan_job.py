"""
Runs the gated active-scan probes on a background thread and lets the admin
UI poll for progress -- the same pattern batch.py already uses for /batch,
and for the same reason: with 6 checks run against every discovered
injection point (up to MAX_INJECTION_POINTS of them), a full active scan can
now take minutes, far past what a single HTTP request should hold open (and
past gunicorn's default 30-second worker timeout, which would otherwise kill
the request -- and the scan -- partway through).

Job state lives in an in-memory dict: same "fine for one gunicorn worker,
resets on restart" tradeoff as batch.py and the rate limiter. A job only
needs to survive a few minutes of polling, not a redeploy.
"""
from __future__ import annotations

import threading
from dataclasses import asdict
from datetime import datetime, timezone

from active_scan import run_active_scan

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def create_job(job_id: str, target: str, test_post_forms: bool = False) -> None:
    with _lock:
        _jobs[job_id] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "test_post_forms": test_post_forms,
            "finished": False,
            "result": None,
        }


def get_job(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def run_job(job_id: str, target: str, test_post_forms: bool = False) -> None:
    result = run_active_scan(target, test_post_forms=test_post_forms)
    with _lock:
        job = _jobs.get(job_id)
        if not job:
            return  # job was never created, or the process restarted mid-scan
        job["result"] = {
            "target": result.target,
            "scanned_at": result.scanned_at,
            "injection_points_tested": result.injection_points_tested,
            "error": result.error,
            "findings": [asdict(f) for f in result.findings],
        }
        job["finished"] = True
