"""
Runs several scans (plus a drafted outreach message each) in the background,
so prospecting a list of sites isn't limited to one at a time through the
main form. A batch can take minutes end to end -- far past what a single
HTTP request should hold open -- so /batch kicks off a background thread
and the client polls for progress instead of waiting on one long response.

Job state lives in an in-memory dict: same "fine for one gunicorn worker,
resets on restart" tradeoff as the rate limiter in app.py. A batch job only
needs to survive a few minutes of polling, not a redeploy.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from ai_narrative import generate_narrative, generate_outreach_message
from scanner import run_scan
from storage import save_scan

MAX_BATCH_TARGETS = 8
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def create_job(job_id: str, targets: list[str]) -> None:
    with _lock:
        _jobs[job_id] = {
            "created_at": datetime.now(timezone.utc).isoformat(),
            "total": len(targets),
            "done_count": 0,
            "finished": False,
            "items": [
                {"target": t, "status": "pending", "scan_id": None, "grade": None,
                 "score": None, "error": None, "outreach": None}
                for t in targets
            ],
        }


def get_job(job_id: str) -> dict | None:
    with _lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def _scan_one(target: str) -> dict:
    try:
        result = run_scan(target)
        if not result.reachable:
            return {"status": "error", "error": result.error}

        narrative, source = generate_narrative(result)
        top = (max(result.findings, key=lambda f: SEVERITY_RANK[f.severity])
               if result.findings else None)
        outreach_text, _ = generate_outreach_message(
            result.target, top.title if top else "", top.detail if top else "",
            bool(result.findings),
        )
        scan_id = save_scan(result, narrative, source)
        return {
            "status": "done", "scan_id": scan_id, "grade": result.grade,
            "score": result.score, "outreach": outreach_text,
        }
    except Exception as e:
        # A single bad target (or an API hiccup) should never take the rest
        # of the batch down with it.
        return {"status": "error", "error": f"Scan failed: {e}"}


def run_job(job_id: str) -> None:
    with _lock:
        job = _jobs.get(job_id)
        targets = [i["target"] for i in job["items"]] if job else []

    for target in targets:
        update = _scan_one(target)
        with _lock:
            job = _jobs.get(job_id)
            if not job:
                return
            entry = next(i for i in job["items"] if i["target"] == target)
            entry.update(update)
            job["done_count"] += 1
            if job["done_count"] >= job["total"]:
                job["finished"] = True
