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

    return render_template(
        "report.html",
        result=result,
        narrative=narrative,
        narrative_source=source,
        counts=result.counts(),
        error=None,
        target=target,
        top_finding=top_finding,
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
