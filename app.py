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

from scanner import run_scan
from ai_narrative import generate_narrative

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-in-production")

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
def scan():
    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Enter a website URL to scan.")
        return redirect(url_for("index"))

    result = run_scan(target)

    if not result.reachable:
        return render_template("report.html", result=None, error=result.error, target=target)

    narrative, source = generate_narrative(result)

    return render_template(
        "report.html",
        result=result,
        narrative=narrative,
        narrative_source=source,
        counts=result.counts(),
        error=None,
        target=target,
    )


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
