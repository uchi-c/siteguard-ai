"""
SiteGuard AI -- free AI-narrated security scan, used as a lead magnet.

Flow: visitor enters their site URL -> gets a real passive security scan with
an AI-written, plain-English executive summary and prioritized fix list ->
CTA to book a paid remediation call. Leads are logged to leads.csv.

Run locally:
    export ANTHROPIC_API_KEY=sk-ant-...   # optional -- works without it
    python app.py
Then open http://localhost:5000
"""
import csv
import os
import secrets
import threading
from datetime import datetime, timezone

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # fine to skip -- just export env vars directly instead

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

from scanner import run_scan
from ai_narrative import generate_narrative, generate_outreach_message
from storage import save_scan, load_scan
from batch import MAX_BATCH_TARGETS, create_job, get_job, run_job

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-in-production")
csrf = CSRFProtect(app)

# Each scan makes 15+ outbound requests to the target site, so an unlimited
# /scan is both an abuse vector (this server as a free scanning/SSRF-probing
# proxy) and a way to run up Anthropic API costs. In-memory storage is fine
# for a single-process deployment; swap storage_uri for Redis if this ever
# runs with multiple gunicorn workers, since counts aren't shared across them.
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

LEADS_FILE = os.path.join(os.path.dirname(__file__), "leads.csv")


def _log_lead(email: str, target: str, grade: str, score: int):
    is_new = not os.path.exists(LEADS_FILE)
    with open(LEADS_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(["timestamp_utc", "email", "target", "grade", "score"])
        writer.writerow([datetime.now(timezone.utc).isoformat(), email, target, grade, score])


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
@limiter.limit("5 per minute; 30 per hour")
def scan():
    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Enter a website URL to scan.")
        return redirect(url_for("index"))

    result = run_scan(target)

    if not result.reachable:
        return render_template("report.html", result=None, error=result.error, target=target)

    narrative, source = generate_narrative(result)
    top_finding = max(result.findings, key=lambda f: SEVERITY_RANK[f.severity]) if result.findings else None
    scan_id = save_scan(result, narrative, source)

    return render_template(
        "report.html",
        result=result,
        narrative=narrative,
        narrative_source=source,
        counts=result.counts(),
        error=None,
        target=target,
        top_finding=top_finding,
        scan_id=scan_id,
    )


@app.route("/report/<scan_id>", methods=["GET"])
def view_report(scan_id):
    loaded = load_scan(scan_id)
    if not loaded:
        flash("That report link doesn't exist or has expired.")
        return redirect(url_for("index"))

    result, narrative, source = loaded
    top_finding = max(result.findings, key=lambda f: SEVERITY_RANK[f.severity]) if result.findings else None

    return render_template(
        "report.html",
        result=result,
        narrative=narrative,
        narrative_source=source,
        counts=result.counts(),
        error=None,
        target=result.target,
        top_finding=top_finding,
        scan_id=scan_id,
    )


@app.route("/outreach", methods=["POST"])
@limiter.limit("10 per minute; 60 per hour")
def outreach():
    target = (request.form.get("target") or "").strip()
    top_title = request.form.get("top_title", "")
    top_detail = request.form.get("top_detail", "")
    has_findings = request.form.get("has_findings") == "1"
    if not target:
        return {"error": "Missing target."}, 400
    message, source = generate_outreach_message(target, top_title, top_detail, has_findings)
    return {"message": message, "source": source}


@app.route("/batch", methods=["GET"])
def batch_form():
    return render_template("batch.html", max_targets=MAX_BATCH_TARGETS)


@app.route("/batch", methods=["POST"])
@limiter.limit("3 per hour")
def batch_start():
    raw = request.form.get("targets", "")
    seen = set()
    targets = []
    for line in raw.splitlines():
        t = line.strip()
        if t and t not in seen:
            targets.append(t)
            seen.add(t)

    if not targets:
        flash("Enter at least one website URL, one per line.")
        return redirect(url_for("batch_form"))

    if len(targets) > MAX_BATCH_TARGETS:
        flash(f"Only scanning the first {MAX_BATCH_TARGETS} URLs -- that's the batch limit.")
        targets = targets[:MAX_BATCH_TARGETS]

    job_id = secrets.token_urlsafe(8)
    create_job(job_id, targets)
    threading.Thread(target=run_job, args=(job_id,), daemon=True).start()

    return redirect(url_for("batch_view", job_id=job_id))


@app.route("/batch/<job_id>", methods=["GET"])
def batch_view(job_id):
    job = get_job(job_id)
    if not job:
        flash("That batch job doesn't exist or has expired.")
        return redirect(url_for("batch_form"))
    return render_template("batch_status.html", job=job, job_id=job_id)


@app.route("/batch/<job_id>/status", methods=["GET"])
def batch_status(job_id):
    job = get_job(job_id)
    if not job:
        return {"error": "not found"}, 404
    return job


@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Too many scans from this connection -- please wait a bit and try again.")
    return redirect(url_for("index"))


@app.errorhandler(CSRFError)
def csrf_error_handler(e):
    flash("Your session expired -- please try again.")
    return redirect(url_for("index"))


@app.route("/lead", methods=["POST"])
def lead():
    email = (request.form.get("email") or "").strip()
    target = request.form.get("target", "")
    grade = request.form.get("grade", "")
    score = request.form.get("score", "0")
    if email:
        _log_lead(email, target, grade, int(score) if score.isdigit() else 0)
        flash("Got it -- we'll reach out with a fix plan shortly.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug, host="0.0.0.0", port=5000)
