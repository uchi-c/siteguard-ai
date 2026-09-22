"""
SiteGuard AI -- free AI-narrated security scan, used as a lead magnet.

Flow: visitor enters their site URL -> gets a real passive security scan with
an AI-written, plain-English executive summary and prioritized fix list ->
CTA to book a paid remediation call. Leads are saved as per-lead records
(storage.py) with an editable status (new/contacted/quoted/won/lost) so
/admin doubles as a lightweight pipeline, not just a log.

Run locally:
    export ANTHROPIC_API_KEY=sk-ant-...   # optional -- works without it
    python app.py
Then open http://localhost:5000
"""
import hmac
import os
import secrets
import sys
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from urllib.parse import urlparse

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # fine to skip -- just export env vars directly instead

from flask import Flask, render_template, request, redirect, url_for, flash, session, Response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError

from scanner import run_scan, _normalize_url
from ai_narrative import generate_narrative, generate_outreach_message, generate_followup_message
from storage import (
    save_scan, load_scan, list_recent_scans,
    log_active_scan_authorization, list_active_scan_audit,
    save_lead, list_leads, get_lead, update_lead, import_leads_csv_once, LEAD_STATUSES,
    add_monitored_target, list_monitored_targets, remove_monitored_target, is_monitored,
    log_scan_request, list_scan_requests, list_lead_followups,
    set_monitored_target_config, list_monitored_target_configs,
    enable_log_ingest, disable_log_ingest, regenerate_log_ingest_token,
    get_log_ingest_config, list_log_ingest_configs, list_recent_log_events,
    prune_old_log_events,
)
from abuse_guard import (
    is_honeypot_triggered, is_domain_in_cooldown, HONEYPOT_FIELD_NAME,
    DOMAIN_COOLDOWN_MAX_REQUESTS, DOMAIN_COOLDOWN_WINDOW_MINUTES,
)
from batch import MAX_BATCH_TARGETS, create_job, get_job, run_job
from branding import get_branding
from monitoring import run_monitoring_check, MONITOR_INTERVALS, DEFAULT_INTERVAL
from followups import (
    run_followup_check, FOLLOWUP_DELAY_HOURS,
    ELIGIBLE_STATUSES as ELIGIBLE_FOLLOWUP_STATUSES,
)
from log_monitor import (
    record_events as record_log_events, record_cloudflare_batch,
    EVENT_TYPES as LOG_EVENT_TYPES, CLOUDFLARE_SETUP_FIELDS,
    MAX_EVENTS_PER_REQUEST as LOG_MAX_EVENTS_PER_REQUEST,
)
import active_scan_job
import pdf_export
import emailer
import payload_classifier
import url_safety

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Deployment-level kill switch for the gated active-testing mode (real
# non-destructive attack probes, not passive checks). Off unless the
# operator explicitly sets it -- adding the route doesn't make it usable.
ACTIVE_TESTING_ENABLED = os.environ.get("ACTIVE_TESTING_ENABLED") == "1"

# Shared secret for /internal/run-monitoring and /internal/run-followups --
# an app-generated token, not a personal credential, so it's fine to set
# programmatically. Unset means both routes refuse to run at all rather
# than accepting an empty token.
INTERNAL_JOB_TOKEN = os.environ.get("INTERNAL_JOB_TOKEN", "")

# How often the in-process background thread ticks -- checking both for
# leads due their one-time automatic 48h follow-up (followups.py) and for
# monitored targets due their next weekly/monthly re-scan (monitoring.py).
# Runs only while this process is alive -- on Render's free tier the web
# service sleeps after 15 minutes idle, so anything overdue is caught on
# the next tick after something wakes it back up, not necessarily right
# on schedule. Good enough for "a nudge/re-scan a bit later," not a hard SLA.
SCHEDULER_TICK_SECONDS = 30 * 60

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-key-change-in-production")
# Render sets RENDER=true in its runtime; only force HTTPS-only cookies
# there, so plain-HTTP local dev (python app.py on localhost) still works.
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("RENDER") == "true"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
csrf = CSRFProtect(app)

# Each scan makes 15+ outbound requests to the target site, so an unlimited
# /scan is both an abuse vector (this server as a free scanning/SSRF-probing
# proxy) and a way to run up Anthropic API costs. In-memory storage is fine
# for a single-process deployment; swap storage_uri for Redis if this ever
# runs with multiple gunicorn workers, since counts aren't shared across them.
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")

# Leads used to live only here, appended to but never updated. Now they're
# per-row SQLite records (storage.py) with an editable status -- this path
# is kept only so import_leads_csv_once can pull any pre-existing rows in
# on first admin-dashboard load, so history from before this feature isn't
# lost. Nothing writes to it anymore.
LEADS_FILE = os.path.join(os.path.dirname(__file__), "leads.csv")


@app.context_processor
def inject_branding():
    return {"brand": get_branding()}


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("admin_login_form"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", honeypot_field=HONEYPOT_FIELD_NAME)


@app.route("/scan", methods=["POST"])
@limiter.limit("5 per minute; 30 per hour")
def scan():
    source_ip = get_remote_address()

    if is_honeypot_triggered(request.form):
        # A real visitor never fills this field in -- don't tip off
        # whatever filled it out that it was caught, just fail exactly
        # like a normal empty-target submission would.
        log_scan_request(source_ip, request.form.get("target", "")[:200] or "(honeypot, no target)",
                          "blocked: honeypot")
        flash("Enter a website URL to scan.")
        return redirect(url_for("index"))

    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Enter a website URL to scan.")
        return redirect(url_for("index"))

    normalized_target = _normalize_url(target)
    if is_domain_in_cooldown(normalized_target):
        log_scan_request(source_ip, normalized_target, "blocked: domain cooldown")
        flash("This site was already scanned recently -- please try again in a little while.")
        return redirect(url_for("index"))

    result = run_scan(target)

    if not result.reachable:
        log_scan_request(source_ip, normalized_target, f"unreachable: {result.error}")
        return render_template("report.html", result=None, error=result.error, target=target)

    narrative, source = generate_narrative(result)
    top_finding = max(result.findings, key=lambda f: SEVERITY_RANK[f.severity]) if result.findings else None
    scan_id = save_scan(result, narrative, source)
    log_scan_request(
        source_ip, normalized_target,
        f"grade {result.grade}, score {result.score}/100, {len(result.findings)} finding(s)",
    )

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


@app.route("/report/<scan_id>/pdf", methods=["GET"])
@limiter.limit("20 per hour")
def report_pdf(scan_id):
    loaded = load_scan(scan_id)
    if not loaded:
        flash("That report link doesn't exist or has expired.")
        return redirect(url_for("index"))

    result, narrative, source = loaded
    html = render_template(
        "report_print.html", result=result, narrative=narrative,
        narrative_source=source, counts=result.counts(),
    )
    pdf_bytes = pdf_export.render_pdf(html)
    if not pdf_bytes:
        flash("Couldn't generate a PDF right now -- try again in a moment.")
        return redirect(url_for("view_report", scan_id=scan_id))

    return Response(
        pdf_bytes, mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="siteguard-report-{scan_id}.pdf"'},
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


@app.route("/check-url", methods=["GET"])
def check_url_form():
    return render_template("check_url_form.html")


@app.route("/check-url", methods=["POST"])
@limiter.limit("20 per minute; 100 per hour")
def check_url_start():
    url = (request.form.get("url") or "").strip()
    if not url:
        flash("Enter a URL to check.")
        return redirect(url_for("check_url_form"))
    result = url_safety.check_url(url)
    return render_template("check_url_form.html", result=result)


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
    threading.Thread(target=run_job, args=(job_id, get_remote_address()), daemon=True).start()

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


@app.route("/admin/login", methods=["GET"])
def admin_login_form():
    if session.get("is_admin"):
        return redirect(url_for("admin_dashboard"))
    return render_template("admin_login.html")


@app.route("/admin/login", methods=["POST"])
@limiter.limit("5 per minute")
def admin_login():
    admin_password = os.environ.get("ADMIN_PASSWORD")
    submitted = request.form.get("password", "")
    if not admin_password:
        flash("Admin login isn't configured -- set ADMIN_PASSWORD.")
        return redirect(url_for("admin_login_form"))
    if hmac.compare_digest(submitted, admin_password):
        session["is_admin"] = True
        return redirect(url_for("admin_dashboard"))
    flash("Wrong password.")
    return redirect(url_for("admin_login_form"))


@app.route("/admin/logout", methods=["POST"])
def admin_logout():
    session.pop("is_admin", None)
    return redirect(url_for("admin_login_form"))


@app.route("/admin", methods=["GET"])
@admin_required
def admin_dashboard():
    imported = import_leads_csv_once(LEADS_FILE)
    if imported:
        flash(f"Imported {imported} lead(s) from the old leads.csv into the new tracker.")
    monitored = list_monitored_targets()
    return render_template(
        "admin.html",
        leads=list_leads(),
        lead_statuses=LEAD_STATUSES,
        scans=list_recent_scans(),
        active_testing_enabled=ACTIVE_TESTING_ENABLED,
        monitored_targets=monitored,
        monitored_target_set={m["target"] for m in monitored},
        monitored_target_configs=list_monitored_target_configs(),
        monitor_intervals=MONITOR_INTERVALS,
        default_interval=DEFAULT_INTERVAL,
        monitoring_configured=bool(INTERNAL_JOB_TOKEN),
        log_ingest_configs=list_log_ingest_configs(),
        followups_sent={f["lead_id"]: f for f in list_lead_followups()},
        followup_eligible_statuses=ELIGIBLE_FOLLOWUP_STATUSES,
        followup_delay_hours=FOLLOWUP_DELAY_HOURS,
        smtp_configured=emailer.is_configured(),
    )


@app.route("/admin/leads/<lead_id>/status", methods=["POST"])
@admin_required
def update_lead_status(lead_id):
    status = (request.form.get("status") or "").strip().lower()
    notes = (request.form.get("notes") or "").strip()
    if status not in LEAD_STATUSES:
        flash("Unknown status.")
        return redirect(url_for("admin_dashboard"))
    if not update_lead(lead_id, status, notes):
        flash("That lead doesn't exist -- it may predate the tracker or already be gone.")
    return redirect(url_for("admin_dashboard"))


def _days_since(iso_timestamp: str) -> int:
    then = datetime.fromisoformat(iso_timestamp)
    if then.tzinfo is None:
        then = then.replace(tzinfo=timezone.utc)
    return max(0, (datetime.now(timezone.utc) - then).days)


@app.route("/admin/leads/<lead_id>/draft-followup", methods=["POST"])
@admin_required
@limiter.limit("20 per minute")
def draft_lead_followup(lead_id):
    lead = get_lead(lead_id)
    if not lead:
        return {"error": "Lead not found."}, 404

    # Best-effort match to the scan that likely produced this lead -- leads
    # aren't linked to a specific scan_id (see storage.py), so this takes
    # the most recent scan of the same target, which is right in the
    # overwhelming majority of cases (a prospect rarely gets rescanned
    # between submitting their email and a follow-up going out).
    top_title, top_detail = "", ""
    for s in list_recent_scans():
        if s["target"] == lead["target"]:
            loaded = load_scan(s["id"])
            if loaded:
                result, _, _ = loaded
                if result.findings:
                    top = max(result.findings, key=lambda f: SEVERITY_RANK[f.severity])
                    top_title, top_detail = top.title, top.detail
            break

    days_since = _days_since(lead["created_at"])
    message, source = generate_followup_message(lead["target"], top_title, top_detail, days_since)
    return {"message": message, "source": source}


@app.route("/admin/monitoring/toggle", methods=["POST"])
@admin_required
def toggle_monitoring():
    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Missing target.")
        return redirect(url_for("admin_dashboard"))
    target = _normalize_url(target)
    if is_monitored(target):
        for m in list_monitored_targets():
            if m["target"] == target:
                remove_monitored_target(m["id"])
                break
        flash(f"Stopped monitoring {target}.")
    else:
        add_monitored_target(target)
        flash(f"Now monitoring {target} -- it'll be re-scanned on the next scheduled check.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/monitoring/run-now", methods=["POST"])
@admin_required
def run_monitoring_now():
    results = run_monitoring_check(force=True)
    changed = sum(1 for r in results if r.get("status") == "checked" and r.get("new_findings"))
    errored = sum(1 for r in results if r.get("status") == "error")
    if not results:
        flash("No monitored targets to check yet.")
    else:
        flash(f"Checked {len(results)} target(s): {changed} with new findings, {errored} failed.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/monitoring/<target_id>/config", methods=["POST"])
@admin_required
def update_monitoring_config(target_id):
    interval = (request.form.get("interval") or "").strip().lower()
    client_email = (request.form.get("client_email") or "").strip()
    if interval not in MONITOR_INTERVALS:
        flash("Unknown re-scan interval.")
        return redirect(url_for("admin_dashboard"))
    set_monitored_target_config(target_id, interval, client_email)
    flash("Monitoring settings saved.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/monitoring/<target_id>/log-ingest/enable", methods=["POST"])
@admin_required
def enable_log_monitoring(target_id):
    enable_log_ingest(target_id)
    flash("Log monitoring enabled -- see the ingestion URL below to wire up the client's app.")
    return redirect(url_for("view_log_events", target_id=target_id))


@app.route("/admin/monitoring/<target_id>/log-ingest/disable", methods=["POST"])
@admin_required
def disable_log_monitoring(target_id):
    disable_log_ingest(target_id)
    flash("Log monitoring disabled -- the old ingestion URL no longer accepts events.")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/monitoring/<target_id>/log-ingest/regenerate", methods=["POST"])
@admin_required
def regenerate_log_monitoring_token(target_id):
    token = regenerate_log_ingest_token(target_id)
    if token is None:
        flash("Log monitoring was never enabled for this target.")
        return redirect(url_for("admin_dashboard"))
    flash("Ingestion URL regenerated -- the old one stopped working immediately.")
    return redirect(url_for("view_log_events", target_id=target_id))


@app.route("/admin/log-events/<target_id>", methods=["GET"])
@admin_required
def view_log_events(target_id):
    config = get_log_ingest_config(target_id)
    if not config:
        flash("Log monitoring hasn't been enabled for this target yet.")
        return redirect(url_for("admin_dashboard"))
    target = next((m for m in list_monitored_targets() if m["id"] == target_id), None)
    ingest_url = url_for("ingest_log_events", token=config["token"], _external=True)
    cloudflare_ingest_url = url_for("ingest_cloudflare_log_events", token=config["token"], _external=True)
    return render_template(
        "log_events.html",
        target=target, target_id=target_id, config=config, ingest_url=ingest_url,
        cloudflare_ingest_url=cloudflare_ingest_url, cloudflare_fields=CLOUDFLARE_SETUP_FIELDS,
        event_types=LOG_EVENT_TYPES, max_events_per_request=LOG_MAX_EVENTS_PER_REQUEST,
        entries=list_recent_log_events(target_id),
    )


@app.route("/ingest/<token>", methods=["POST"])
@csrf.exempt
@limiter.limit("30 per minute; 300 per hour")
def ingest_log_events(token):
    """A client's own app POSTs security events here -- no browser session,
    no CSRF token, so this is guarded by the per-target token in the URL
    instead (same shared-secret-in-the-URL pattern as a webhook from any
    other SaaS product). Never raises on bad input: an unknown token or a
    malformed body gets a clear JSON error, not a 500, since a
    misconfigured client integration must be debuggable from its own logs."""
    body = request.get_json(silent=True)
    if body is None:
        return {"accepted": False, "error": "expected a JSON body"}, 400
    raw_events = body.get("events", body) if isinstance(body, dict) else body
    result = record_log_events(token, raw_events, get_remote_address())
    if not result["accepted"]:
        return result, 404
    return result, 200


@app.route("/ingest/cloudflare/<token>", methods=["POST"])
@csrf.exempt
@limiter.limit("120 per minute; 3000 per hour")
def ingest_cloudflare_log_events(token):
    """Cloudflare Logpush HTTP destination posts batches here -- same
    token-in-URL auth as /ingest/<token>, but the body is Cloudflare's own
    shape (gzip-compressed ndjson, or a one-time gzip validation payload
    made when the job is created), not our JSON schema, so it's parsed
    separately in log_monitor.record_cloudflare_batch. Rate limit is much
    higher than the generic webhook: Logpush delivers on its own schedule,
    as often as roughly every 30 seconds once a job is live, not once per
    client request. request.get_data() is used instead of get_json()
    because the body may be gzip binary, not directly-parseable JSON."""
    result = record_cloudflare_batch(token, request.get_data(), get_remote_address())
    if not result["accepted"]:
        return result, 404
    return result, 200


@app.route("/internal/run-monitoring", methods=["POST"])
@csrf.exempt
@limiter.limit("10 per hour")
def run_monitoring_internal():
    """Triggered by a Render Cron Job on a schedule (see render.yaml /
    the Render dashboard), not a browser -- no CSRF token or admin
    session available, so this is guarded by a shared secret instead
    (constant-time compare, same pattern as the admin password check).
    INTERNAL_JOB_TOKEN is an app-generated token, never a credential
    anyone types in, and unset means this refuses to run at all."""
    if not INTERNAL_JOB_TOKEN:
        return {"error": "monitoring is not configured on this deployment"}, 503
    provided = request.headers.get("X-Internal-Token", "")
    if not hmac.compare_digest(provided, INTERNAL_JOB_TOKEN):
        return {"error": "unauthorized"}, 401
    results = run_monitoring_check()
    return {"checked": len(results), "results": results}


@app.route("/admin/leads/run-followups-now", methods=["POST"])
@admin_required
def run_followups_now():
    results = run_followup_check()
    sent = sum(1 for r in results if r["status"] == "sent")
    if not results:
        flash("No leads are due their follow-up yet.")
    else:
        flash(f"Checked {len(results)} due lead(s): {sent} follow-up email(s) sent.")
    return redirect(url_for("admin_dashboard"))


@app.route("/internal/run-followups", methods=["POST"])
@csrf.exempt
@limiter.limit("10 per hour")
def run_followups_internal():
    """Same trigger pattern as /internal/run-monitoring -- an external
    scheduler, not a browser, so it's guarded by the same shared secret
    instead of a CSRF token or admin session."""
    if not INTERNAL_JOB_TOKEN:
        return {"error": "follow-ups are not configured on this deployment"}, 503
    provided = request.headers.get("X-Internal-Token", "")
    if not hmac.compare_digest(provided, INTERNAL_JOB_TOKEN):
        return {"error": "unauthorized"}, 401
    results = run_followup_check()
    return {"checked": len(results), "results": results}


@app.route("/admin/active-scan", methods=["GET"])
@admin_required
def active_scan_form():
    if not ACTIVE_TESTING_ENABLED:
        flash("Active testing is disabled on this deployment (set ACTIVE_TESTING_ENABLED=1 to enable).")
        return redirect(url_for("admin_dashboard"))
    return render_template("active_scan_form.html")


@app.route("/admin/active-scan", methods=["POST"])
@admin_required
@limiter.limit("5 per hour")
def active_scan_start():
    if not ACTIVE_TESTING_ENABLED:
        flash("Active testing is disabled on this deployment.")
        return redirect(url_for("admin_dashboard"))

    target = (request.form.get("target") or "").strip()
    confirm_host = (request.form.get("confirm_host") or "").strip()
    authorized = request.form.get("authorized") == "on"
    test_post_forms = request.form.get("test_post_forms") == "on"

    if not target or not authorized:
        flash("Enter a target and confirm you're authorized to test it.")
        return redirect(url_for("active_scan_form"))

    expected_host = urlparse(_normalize_url(target)).hostname or ""
    if not expected_host or confirm_host.lower() != expected_host.lower():
        flash(f"Type the exact hostname ({expected_host or 'unknown'}) to confirm -- it didn't match.")
        return redirect(url_for("active_scan_form"))

    log_active_scan_authorization(target, expected_host)

    job_id = secrets.token_urlsafe(8)
    active_scan_job.create_job(job_id, target, test_post_forms=test_post_forms)
    threading.Thread(
        target=active_scan_job.run_job, args=(job_id, target, test_post_forms), daemon=True,
    ).start()

    return redirect(url_for("active_scan_status", job_id=job_id))


@app.route("/admin/active-scan/<job_id>", methods=["GET"])
@admin_required
def active_scan_status(job_id):
    job = active_scan_job.get_job(job_id)
    if not job:
        flash("That active-scan job doesn't exist or has expired.")
        return redirect(url_for("active_scan_form"))
    return render_template("active_scan_status.html", job=job, job_id=job_id)


@app.route("/admin/active-scan/<job_id>/status", methods=["GET"])
@admin_required
def active_scan_status_json(job_id):
    job = active_scan_job.get_job(job_id)
    if not job:
        return {"error": "not found"}, 404
    return job


@app.route("/admin/active-scan/audit", methods=["GET"])
@admin_required
def active_scan_audit():
    return render_template("active_scan_audit.html", entries=list_active_scan_audit())


@app.route("/admin/scan-log", methods=["GET"])
@admin_required
def scan_log():
    return render_template(
        "scan_log.html", entries=list_scan_requests(),
        cooldown_max=DOMAIN_COOLDOWN_MAX_REQUESTS,
        cooldown_window_minutes=DOMAIN_COOLDOWN_WINDOW_MINUTES,
    )


@app.route("/admin/classify", methods=["GET"])
@admin_required
def classify_form():
    return render_template("classify_form.html", available=payload_classifier.is_available())


@app.route("/admin/classify", methods=["POST"])
@admin_required
@limiter.limit("30 per minute")
def classify_start():
    text = request.form.get("text", "")
    result = payload_classifier.classify_payload(text)
    return render_template(
        "classify_form.html",
        available=payload_classifier.is_available(),
        result=result,
        submitted_text=text,
    )


@app.errorhandler(429)
def ratelimit_handler(e):
    if request.path == "/scan":
        target = (request.form.get("target") or "").strip()
        if target:
            log_scan_request(get_remote_address(), _normalize_url(target), "blocked: rate limit")
    flash("Too many scans from this connection -- please wait a bit and try again.")
    return redirect(url_for("index"))


@app.errorhandler(CSRFError)
def csrf_error_handler(e):
    flash("Your session expired -- please try again.")
    return redirect(url_for("index"))


def _send_report_email_background(to_email: str, scan_id: str, report_url: str) -> None:
    """Renders the PDF and sends the report email on a background thread --
    PDF rendering shells out to headless Chromium (see pdf_export.py) and
    can take a few real seconds, which has no business blocking the lead-
    capture request that already logged the lead and is the part that
    actually matters. Never raises -- a bad SMTP config, a slow/failed PDF
    render, or a network hiccup should never surface anywhere; the lead is
    already saved regardless of whether this succeeds."""
    try:
        loaded = load_scan(scan_id)
        if not loaded:
            return
        result, narrative, source = loaded
        with app.app_context():
            html = render_template(
                "report_print.html", result=result, narrative=narrative,
                narrative_source=source, counts=result.counts(),
            )
        pdf_bytes = pdf_export.render_pdf(html)
        emailer.send_report_email(to_email, result.target, result.grade, result.score, report_url, pdf_bytes)
    except Exception:
        pass


@app.route("/lead", methods=["POST"])
def lead():
    email = (request.form.get("email") or "").strip()
    target = request.form.get("target", "")
    grade = request.form.get("grade", "")
    score = request.form.get("score", "0")
    scan_id = request.form.get("scan_id", "")
    if email:
        save_lead(email, target, grade, int(score) if score.isdigit() else 0)
        if scan_id:
            report_url = url_for("view_report", scan_id=scan_id, _external=True)
            threading.Thread(
                target=_send_report_email_background, args=(email, scan_id, report_url), daemon=True,
            ).start()
        flash("Got it -- we'll reach out with a fix plan shortly.")
    return redirect(url_for("index"))


def _background_scheduler_loop() -> None:
    """One shared tick for both scheduled jobs -- each one's own due-ness
    check (followups.py's 48h window, monitoring.py's per-target
    weekly/monthly interval) decides whether anything actually happens on
    a given tick, so ticking more often than either cadence is harmless."""
    while True:
        time.sleep(SCHEDULER_TICK_SECONDS)
        try:
            run_followup_check()
        except Exception:
            pass
        try:
            run_monitoring_check()
        except Exception:
            pass
        try:
            prune_old_log_events()
        except Exception:
            pass


# Started at import time, not inside `if __name__ == "__main__"`, because
# production runs this module via gunicorn ("gunicorn app:app"), which
# imports it and never executes that block -- import time is the only
# reliable "the app just started" hook available without a separate
# gunicorn server-hook config. Skipped under pytest so the test suite
# never has a live thread hitting the real DB/SMTP in the background;
# every test that needs this behavior calls run_followup_check /
# run_monitoring_check directly instead.
if "pytest" not in sys.modules:
    threading.Thread(target=_background_scheduler_loop, daemon=True).start()


if __name__ == "__main__":
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(debug=debug, host="0.0.0.0", port=5000)
