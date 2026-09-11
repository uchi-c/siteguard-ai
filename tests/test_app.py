import types
from unittest.mock import MagicMock

import app as app_module


# --- Basic routes -----------------------------------------------------------

def test_index_loads(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Run free scan" in resp.data


def test_scan_empty_target_flashes_and_redirects(client):
    resp = client.post("/scan", data={"target": ""}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Enter a website URL to scan." in resp.data


def test_scan_private_target_is_blocked_by_ssrf_guard(client):
    resp = client.post("/scan", data={"target": "127.0.0.1"})
    assert resp.status_code == 200
    assert b"private/internal" in resp.data


def test_report_missing_id_redirects_with_flash(client):
    resp = client.get("/report/does-not-exist", follow_redirects=True)
    assert resp.status_code == 200
    assert "doesn't exist or has expired".encode() in resp.data.replace(b"&#39;", b"'")


def test_report_pdf_missing_id_redirects_with_flash(client):
    resp = client.get("/report/does-not-exist/pdf", follow_redirects=True)
    assert resp.status_code == 200
    assert "doesn't exist or has expired".encode() in resp.data.replace(b"&#39;", b"'")


def _stub_successful_scan(monkeypatch):
    """Monkeypatches run_scan to a canned reachable result -- avoids a real
    network call (and example.test/.test never resolves anyway) for tests
    that just need *a* saved scan with a real scan_id to exercise routes
    downstream of a successful /scan."""
    from scanner import Finding, ScanResult

    def fake_run_scan(target):
        return ScanResult(
            target=target, scanned_at="t",
            findings=[Finding("hsts", "Missing HSTS header", "high", "detail", "fix")],
            reachable=True, error=None,
        )

    monkeypatch.setattr(app_module, "run_scan", fake_run_scan)


def test_report_pdf_returns_pdf_bytes_on_success(client, monkeypatch):
    _stub_successful_scan(monkeypatch)
    resp = client.post("/scan", data={"target": "https://example.test"})
    import re
    m = re.search(rb'/report/([\w-]+)/pdf', resp.data)
    assert m, "expected a Download PDF link with a scan_id on the report page"
    scan_id = m.group(1).decode()

    monkeypatch.setattr(app_module.pdf_export, "render_pdf", lambda html: b"%PDF-fake-bytes")
    resp = client.get(f"/report/{scan_id}/pdf")
    assert resp.status_code == 200
    assert resp.mimetype == "application/pdf"
    assert f"siteguard-report-{scan_id}.pdf" in resp.headers["Content-Disposition"]
    assert resp.data == b"%PDF-fake-bytes"


def test_report_pdf_flashes_and_redirects_when_render_fails(client, monkeypatch):
    _stub_successful_scan(monkeypatch)
    resp = client.post("/scan", data={"target": "https://example.test"})
    import re
    m = re.search(rb'/report/([\w-]+)/pdf', resp.data)
    scan_id = m.group(1).decode()

    monkeypatch.setattr(app_module.pdf_export, "render_pdf", lambda html: None)
    resp = client.get(f"/report/{scan_id}/pdf", follow_redirects=True)
    assert resp.status_code == 200
    assert b"Couldn&#39;t generate a PDF" in resp.data or b"Couldn't generate a PDF" in resp.data


def test_batch_empty_targets_flashes(client):
    resp = client.post("/batch", data={"targets": ""}, follow_redirects=True)
    assert b"Enter at least one website URL" in resp.data


def test_outreach_missing_target_returns_400(client):
    resp = client.post("/outreach", data={})
    assert resp.status_code == 400


# --- URL safety checker (/check-url, public -- no SSRF/gating needed since --
# --- it never fetches the target, only looks it up against a threat DB) -----

def test_check_url_form_loads(client):
    resp = client.get("/check-url")
    assert resp.status_code == 200
    assert b"malicious" in resp.data.lower()


def test_check_url_empty_flashes_and_redirects(client):
    resp = client.post("/check-url", data={"url": ""}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Enter a URL to check." in resp.data


def test_check_url_renders_malicious_verdict(client, monkeypatch):
    monkeypatch.setattr(app_module.url_safety, "check_url", lambda url: {
        "url": "https://evil.test", "verdict": "malicious",
        "threats": ["phishing"], "source": "safe-browsing", "confidence": None,
    })
    resp = client.post("/check-url", data={"url": "evil.test"})
    assert resp.status_code == 200
    assert b"Known threat" in resp.data
    assert b"phishing" in resp.data


def test_check_url_renders_no_known_threats(client, monkeypatch):
    monkeypatch.setattr(app_module.url_safety, "check_url", lambda url: {
        "url": "https://example.test", "verdict": "no-known-threats",
        "threats": [], "source": "safe-browsing", "confidence": None,
    })
    resp = client.post("/check-url", data={"url": "example.test"})
    assert resp.status_code == 200
    assert b"No known threats found" in resp.data


def test_check_url_renders_suspicious_with_hedged_language(client, monkeypatch):
    monkeypatch.setattr(app_module.url_safety, "check_url", lambda url: {
        "url": "https://maybe-bad.test", "verdict": "suspicious",
        "threats": ["phishing"], "source": "ml", "confidence": 0.72,
    })
    resp = client.post("/check-url", data={"url": "maybe-bad.test"})
    assert resp.status_code == 200
    assert b"Possibly" in resp.data
    assert b"local heuristic model" in resp.data  # never claims certainty for an ML verdict


def test_check_url_renders_unavailable(client, monkeypatch):
    monkeypatch.setattr(app_module.url_safety, "check_url", lambda url: {
        "url": "https://example.test", "verdict": "unavailable",
        "threats": [], "source": "none", "confidence": None,
    })
    resp = client.post("/check-url", data={"url": "example.test"})
    assert resp.status_code == 200
    assert b"Couldn" in resp.data


def test_check_url_never_claims_safe_only_no_known_threats(client, monkeypatch):
    """Language check: this tool must never affirmatively claim a URL IS
    safe -- only that no known threat was found. "not the same as
    confirmed safe" (a deliberate disclaimer) is fine; "this url is safe"
    would not be."""
    monkeypatch.setattr(app_module.url_safety, "check_url", lambda url: {
        "url": "https://example.test", "verdict": "no-known-threats",
        "threats": [], "source": "safe-browsing", "confidence": None,
    })
    resp = client.post("/check-url", data={"url": "example.test"})
    assert b"this url is safe" not in resp.data.lower()
    assert b"url is confirmed safe" not in resp.data.lower()
    assert b"no known threats found" in resp.data.lower()


# --- CSRF protection ---------------------------------------------------------

def test_scan_without_csrf_token_is_rejected(client):
    app_module.app.config["WTF_CSRF_ENABLED"] = True
    try:
        resp = client.post("/scan", data={"target": "https://example.test"}, follow_redirects=True)
        assert "session expired".encode() in resp.data.replace(b"&#39;", b"'")
    finally:
        app_module.app.config["WTF_CSRF_ENABLED"] = False


# --- Rate limiting ------------------------------------------------------------

def test_scan_rate_limit_blocks_after_five_per_minute(client):
    app_module.app.config["RATELIMIT_ENABLED"] = True
    try:
        for _ in range(5):
            client.post("/scan", data={"target": "127.0.0.1"})  # SSRF-blocked, no real network
        resp = client.post("/scan", data={"target": "127.0.0.1"}, follow_redirects=True)
        assert b"Too many scans" in resp.data
    finally:
        app_module.app.config["RATELIMIT_ENABLED"] = False


# --- Admin auth ----------------------------------------------------------------

def test_admin_requires_login(client):
    resp = client.get("/admin")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_admin_login_not_configured_fails_safe(client, monkeypatch):
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    resp = client.post("/admin/login", data={"password": "anything"}, follow_redirects=True)
    assert "isn't configured".encode() in resp.data.replace(b"&#39;", b"'")
    # And GET /admin must still be gated -- no accidental bypass.
    resp2 = client.get("/admin")
    assert resp2.status_code == 302


def test_admin_login_wrong_password(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    resp = client.post("/admin/login", data={"password": "wrong"}, follow_redirects=True)
    assert b"Wrong password." in resp.data


def test_admin_login_success_reaches_dashboard(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    resp = client.post("/admin/login", data={"password": "correct-horse"}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"Leads (" in resp.data
    assert b"Recent scans (" in resp.data


def test_admin_logout_clears_session(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    client.post("/admin/logout")
    resp = client.get("/admin")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_lead_appears_in_admin_dashboard(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/lead", data={
        "email": "prospect@test.com", "target": "https://example.test",
        "grade": "C", "score": "63",
    })
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.get("/admin")
    assert b"prospect@test.com" in resp.data
    assert b"Leads (1)" in resp.data


# --- Lead status tracker -------------------------------------------------------

def test_update_lead_status_requires_admin_login(client):
    resp = client.post("/admin/leads/some-id/status", data={"status": "contacted"})
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_update_lead_status_changes_status_and_notes(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/lead", data={
        "email": "prospect@test.com", "target": "https://example.test",
        "grade": "C", "score": "63",
    })
    client.post("/admin/login", data={"password": "correct-horse"})

    import storage
    lead_id = storage.list_leads()[0]["id"]

    resp = client.post(f"/admin/leads/{lead_id}/status", data={
        "status": "contacted", "notes": "Called, left voicemail",
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Contacted" in resp.data
    assert b"Called, left voicemail" in resp.data


def test_update_lead_status_rejects_unknown_status(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/lead", data={
        "email": "prospect@test.com", "target": "https://example.test",
        "grade": "C", "score": "63",
    })
    client.post("/admin/login", data={"password": "correct-horse"})

    import storage
    lead_id = storage.list_leads()[0]["id"]

    resp = client.post(f"/admin/leads/{lead_id}/status", data={
        "status": "definitely-not-real", "notes": "",
    }, follow_redirects=True)
    assert b"Unknown status" in resp.data
    assert storage.list_leads()[0]["status"] == "new"  # unchanged


def test_update_lead_status_unknown_id_flashes_and_redirects(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/leads/no-such-lead/status", data={
        "status": "contacted", "notes": "",
    }, follow_redirects=True)
    assert "doesn&#39;t exist".encode() in resp.data or "doesn't exist".encode() in resp.data


def test_admin_dashboard_imports_legacy_leads_csv_once(client, monkeypatch, tmp_path):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    csv_path = tmp_path / "legacy-leads.csv"
    csv_path.write_text(
        "timestamp_utc,email,target,grade,score\n"
        "2026-01-01T00:00:00+00:00,legacy@test.com,https://legacy.test,B,82\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(app_module, "LEADS_FILE", str(csv_path))

    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.get("/admin", follow_redirects=True)

    assert b"legacy@test.com" in resp.data
    assert b"Imported 1 lead" in resp.data

    # A second load must not re-import or duplicate.
    resp2 = client.get("/admin")
    assert b"Leads (1)" in resp2.data


# --- Lead follow-up drafting (agentic: Claude drafts, operator sends) --------

def test_draft_lead_followup_requires_admin_login(client):
    resp = client.post("/admin/leads/some-id/draft-followup")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_draft_lead_followup_unknown_lead_returns_404(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/leads/no-such-lead/draft-followup")
    assert resp.status_code == 404
    assert resp.get_json()["error"]


def test_draft_lead_followup_uses_top_finding_from_matching_scan(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    from scanner import Finding, ScanResult

    def fake_run_scan(target):
        return ScanResult(
            target=target, scanned_at="t",
            findings=[Finding("hsts", "Missing HSTS header", "high", "detail", "fix")],
            reachable=True, error=None,
        )

    monkeypatch.setattr(app_module, "run_scan", fake_run_scan)
    client.post("/scan", data={"target": "https://example.test"})  # saves a matching scan

    client.post("/lead", data={
        "email": "prospect@test.com", "target": "https://example.test",
        "grade": "C", "score": "63",
    })
    client.post("/admin/login", data={"password": "correct-horse"})

    import storage
    lead_id = storage.list_leads()[0]["id"]

    resp = client.post(f"/admin/leads/{lead_id}/draft-followup")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["source"] == "rule-based"
    assert "missing hsts header" in data["message"].lower()


def test_draft_lead_followup_with_no_matching_scan_still_drafts(client, monkeypatch):
    """No scan on record for this target (e.g. it was deleted, or the lead
    predates the scan) -- must still draft a generic follow-up, never 500."""
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    client.post("/lead", data={
        "email": "prospect@test.com", "target": "https://no-scan-for-this.test",
        "grade": "C", "score": "63",
    })
    client.post("/admin/login", data={"password": "correct-horse"})

    import storage
    lead_id = storage.list_leads()[0]["id"]

    resp = client.post(f"/admin/leads/{lead_id}/draft-followup")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "no-scan-for-this.test" in data["message"]


# --- Monitoring (agentic workflow, phase 2) -----------------------------------

def test_toggle_monitoring_requires_admin_login(client):
    resp = client.post("/admin/monitoring/toggle", data={"target": "https://example.test"})
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_toggle_monitoring_adds_then_removes(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})

    import storage
    resp = client.post("/admin/monitoring/toggle", data={"target": "https://example.test"}, follow_redirects=True)
    assert b"Now monitoring" in resp.data
    assert storage.is_monitored("https://example.test") is True

    resp2 = client.post("/admin/monitoring/toggle", data={"target": "https://example.test"}, follow_redirects=True)
    assert b"Stopped monitoring" in resp2.data
    assert storage.is_monitored("https://example.test") is False


def test_toggle_monitoring_normalizes_target(client, monkeypatch):
    """example.test and https://example.test must land on the same
    monitored row, or the un-monitor toggle would never match."""
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})

    import storage
    client.post("/admin/monitoring/toggle", data={"target": "example.test"})
    assert storage.is_monitored("https://example.test") is True


def test_run_monitoring_now_requires_admin_login(client):
    resp = client.post("/admin/monitoring/run-now")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_run_monitoring_now_with_no_targets_flashes(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/monitoring/run-now", follow_redirects=True)
    assert b"No monitored targets" in resp.data


def test_run_monitoring_now_checks_targets_and_flashes_summary(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    client.post("/admin/monitoring/toggle", data={"target": "https://example.test"})

    monkeypatch.setattr(app_module, "run_monitoring_check", lambda: [
        {"target": "https://example.test", "status": "checked", "new_findings": 2, "resolved_findings": 0},
    ])

    resp = client.post("/admin/monitoring/run-now", follow_redirects=True)
    assert b"Checked 1 target" in resp.data
    assert b"1 with new findings" in resp.data


def test_internal_run_monitoring_disabled_when_token_unset(client, monkeypatch):
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "")
    resp = client.post("/internal/run-monitoring")
    assert resp.status_code == 503


def test_internal_run_monitoring_rejects_missing_token(client, monkeypatch):
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "the-real-token")
    resp = client.post("/internal/run-monitoring")
    assert resp.status_code == 401


def test_internal_run_monitoring_rejects_wrong_token(client, monkeypatch):
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "the-real-token")
    resp = client.post("/internal/run-monitoring", headers={"X-Internal-Token": "wrong-token"})
    assert resp.status_code == 401


def test_internal_run_monitoring_accepts_correct_token(client, monkeypatch):
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "the-real-token")
    monkeypatch.setattr(app_module, "run_monitoring_check", lambda: [
        {"target": "https://example.test", "status": "checked", "new_findings": 0, "resolved_findings": 0},
    ])
    resp = client.post("/internal/run-monitoring", headers={"X-Internal-Token": "the-real-token"})
    assert resp.status_code == 200
    assert resp.get_json()["checked"] == 1


def test_internal_run_monitoring_has_no_csrf_requirement(client, monkeypatch):
    """A cron job has no browser session or CSRF token -- this route must
    work even with CSRF protection globally enabled (unlike every other
    POST route in the app)."""
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "the-real-token")
    monkeypatch.setattr(app_module, "run_monitoring_check", lambda: [])
    app_module.app.config["WTF_CSRF_ENABLED"] = True
    try:
        resp = client.post("/internal/run-monitoring", headers={"X-Internal-Token": "the-real-token"})
        assert resp.status_code == 200
    finally:
        app_module.app.config["WTF_CSRF_ENABLED"] = False


# --- Report email on lead capture --------------------------------------------

def test_lead_without_scan_id_does_not_start_an_email_thread(client, monkeypatch):
    """No scan_id (e.g. an old bookmarked report, or the field stripped) --
    nothing to email, and the lead-capture flow must still work exactly as
    before this feature existed.

    Replaces app_module's OWN `threading` name binding with a fake object,
    not threading.Thread itself -- the latter is the real, shared stdlib
    module, and mutating it out from under Flask-Limiter's internal Timer
    usage corrupts unrelated tests (confirmed: it did, cascading failures
    in tests that never touch this code at all)."""
    started = []
    fake_threading = types.SimpleNamespace(
        Thread=lambda *a, **k: started.append(1) or MagicMock(),
    )
    monkeypatch.setattr(app_module, "threading", fake_threading)

    resp = client.post("/lead", data={
        "email": "prospect@test.com", "target": "https://example.test",
        "grade": "C", "score": "63",
    }, follow_redirects=True)
    assert resp.status_code == 200
    assert b"reach out with a fix plan shortly" in resp.data
    assert started == []


def test_lead_with_scan_id_starts_a_background_email_thread(client, monkeypatch):
    fake_thread = MagicMock()
    thread_calls = []

    def fake_thread_ctor(*args, **kwargs):
        thread_calls.append((args, kwargs))
        return fake_thread

    fake_threading = types.SimpleNamespace(Thread=fake_thread_ctor)
    monkeypatch.setattr(app_module, "threading", fake_threading)

    resp = client.post("/lead", data={
        "email": "prospect@test.com", "target": "https://example.test",
        "grade": "C", "score": "63", "scan_id": "abc123",
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"reach out with a fix plan shortly" in resp.data
    assert len(thread_calls) == 1
    kwargs = thread_calls[0][1]
    assert kwargs["target"] == app_module._send_report_email_background
    assert kwargs["args"][0] == "prospect@test.com"
    assert kwargs["args"][1] == "abc123"
    fake_thread.start.assert_called_once()


def test_send_report_email_background_calls_emailer_with_pdf(monkeypatch):
    """Direct unit test of the background function itself (run
    synchronously here, not via a real thread) -- covers the
    app.app_context()-wrapped render_template call and the handoff to
    pdf_export + emailer."""
    from scanner import Finding, ScanResult

    result = ScanResult(
        target="https://example.test", scanned_at="t",
        findings=[Finding("hsts", "Missing HSTS header", "high", "detail", "fix")],
        reachable=True, error=None,
    )
    monkeypatch.setattr(app_module, "load_scan", lambda scan_id: (result, "summary text", "rule-based"))
    monkeypatch.setattr(app_module.pdf_export, "render_pdf", lambda html: b"%PDF-fake")

    sent = {}
    monkeypatch.setattr(
        app_module.emailer, "send_report_email",
        lambda to_email, target, grade, score, report_url, pdf_bytes=None:
            sent.update(to=to_email, target=target, grade=grade, score=score,
                        report_url=report_url, pdf_bytes=pdf_bytes) or True,
    )

    app_module._send_report_email_background("lead@test.com", "abc123", "https://x.test/report/abc123")

    assert sent["to"] == "lead@test.com"
    assert sent["target"] == "https://example.test"
    assert sent["pdf_bytes"] == b"%PDF-fake"
    assert sent["report_url"] == "https://x.test/report/abc123"


def test_send_report_email_background_swallows_errors(monkeypatch):
    """Must never raise -- a bad SMTP config, a slow PDF render, whatever --
    the lead-capture request that spawned this already returned to the
    visitor and doesn't care."""
    def boom(scan_id):
        raise RuntimeError("db exploded")

    monkeypatch.setattr(app_module, "load_scan", boom)
    app_module._send_report_email_background("lead@test.com", "abc123", "https://x.test/report/abc123")


# --- Gated active-testing mode -----------------------------------------------

def test_active_scan_form_requires_admin_login(client, monkeypatch):
    monkeypatch.setattr(app_module, "ACTIVE_TESTING_ENABLED", True)
    resp = client.get("/admin/active-scan")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_active_scan_disabled_by_default(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(app_module, "ACTIVE_TESTING_ENABLED", False)
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.get("/admin/active-scan", follow_redirects=True)
    assert b"disabled on this deployment" in resp.data


def test_active_scan_start_rejects_mismatched_hostname(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(app_module, "ACTIVE_TESTING_ENABLED", True)
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/active-scan", data={
        "target": "https://example.test", "confirm_host": "wrong-host.test", "authorized": "on",
    }, follow_redirects=True)
    assert b"didn&#39;t match" in resp.data or b"didn't match" in resp.data


def test_active_scan_start_requires_authorization_checkbox(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(app_module, "ACTIVE_TESTING_ENABLED", True)
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/active-scan", data={
        "target": "https://example.test", "confirm_host": "example.test",
    }, follow_redirects=True)
    assert b"confirm you" in resp.data


def test_active_scan_start_logs_authorization_and_starts_a_job(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(app_module, "ACTIVE_TESTING_ENABLED", True)

    logged = {}
    monkeypatch.setattr(app_module, "log_active_scan_authorization",
                         lambda target, hostname: logged.update(target=target, hostname=hostname))

    # The scan itself now runs on a background thread (see active_scan_job.py
    # -- necessary once scans could take minutes and exceed gunicorn's
    # worker timeout), so this only checks that authorization is logged and
    # the request redirects straight to the polling status page without
    # waiting on the scan.
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/active-scan", data={
        "target": "https://example.test", "confirm_host": "example.test", "authorized": "on",
    })

    assert resp.status_code == 302
    assert "/admin/active-scan/" in resp.headers["Location"]
    assert logged == {"target": "https://example.test", "hostname": "example.test"}


def test_active_scan_start_passes_test_post_forms_checkbox_through(client, monkeypatch):
    """The POST-forms checkbox is a separate, higher-risk opt-in from the
    general authorization checkbox -- must actually reach create_job, not
    just get silently dropped. (Doesn't touch threading.Thread -- that's
    the real, shared stdlib module, and mocking it out from under
    Flask-Limiter's internal Timer usage corrupts unrelated tests. The
    background thread this route starts is harmless to let run for real:
    create_job is mocked below, so the real run_job finds no job under
    this id and returns immediately without making any network call.)"""
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(app_module, "ACTIVE_TESTING_ENABLED", True)
    monkeypatch.setattr(app_module, "log_active_scan_authorization", lambda target, hostname: None)

    created = {}
    monkeypatch.setattr(app_module.active_scan_job, "create_job",
                         lambda job_id, target, test_post_forms=False:
                             created.update(target=target, test_post_forms=test_post_forms))

    client.post("/admin/login", data={"password": "correct-horse"})
    client.post("/admin/active-scan", data={
        "target": "https://example.test", "confirm_host": "example.test",
        "authorized": "on", "test_post_forms": "on",
    })

    assert created == {"target": "https://example.test", "test_post_forms": True}


def test_active_scan_start_defaults_test_post_forms_to_false(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(app_module, "ACTIVE_TESTING_ENABLED", True)
    monkeypatch.setattr(app_module, "log_active_scan_authorization", lambda target, hostname: None)

    created = {}
    monkeypatch.setattr(app_module.active_scan_job, "create_job",
                         lambda job_id, target, test_post_forms=False:
                             created.update(test_post_forms=test_post_forms))

    client.post("/admin/login", data={"password": "correct-horse"})
    client.post("/admin/active-scan", data={
        "target": "https://example.test", "confirm_host": "example.test", "authorized": "on",
    })

    assert created == {"test_post_forms": False}


def test_active_scan_status_unknown_job_flashes_and_redirects(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.get("/admin/active-scan/no-such-job", follow_redirects=True)
    assert b"doesn&#39;t exist or has expired" in resp.data or b"doesn't exist or has expired" in resp.data


def test_active_scan_status_json_requires_admin_login(client):
    resp = client.get("/admin/active-scan/some-job/status")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_active_scan_status_json_unknown_job_404s(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.get("/admin/active-scan/no-such-job/status")
    assert resp.status_code == 404


def test_active_scan_status_json_reflects_finished_job(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    import active_scan_job
    active_scan_job.create_job("job-abc", "https://example.test")
    active_scan_job._jobs["job-abc"]["finished"] = True
    active_scan_job._jobs["job-abc"]["result"] = {
        "target": "https://example.test", "scanned_at": "t",
        "injection_points_tested": 0, "error": None, "findings": [],
    }

    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.get("/admin/active-scan/job-abc/status")
    assert resp.status_code == 200
    assert resp.get_json()["finished"] is True


def test_active_scan_audit_requires_admin_login(client):
    resp = client.get("/admin/active-scan/audit")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


# --- Payload classifier -------------------------------------------------------

def test_classify_form_requires_admin_login(client):
    resp = client.get("/admin/classify")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_classify_start_returns_a_real_classification(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/classify", data={"text": "' OR 1=1--"})
    assert resp.status_code == 200
    assert b"sql" in resp.data
    assert b"confidence" in resp.data


def test_classify_start_empty_input_shows_error(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/classify", data={"text": ""})
    assert resp.status_code == 200
    assert b"Enter some text to classify." in resp.data
