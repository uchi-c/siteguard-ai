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


# --- Abuse gate: honeypot, per-domain cooldown, scan-request logging --------

def test_index_includes_honeypot_field(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b'name="company_website"' in resp.data


def test_scan_honeypot_triggered_fails_silently_like_empty_target(client):
    import storage

    resp = client.post(
        "/scan",
        data={"target": "https://example.test", "company_website": "I am a bot"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Enter a website URL to scan." in resp.data

    logged = storage.list_scan_requests()
    assert len(logged) == 1
    assert logged[0]["result_summary"] == "blocked: honeypot"


def test_scan_honeypot_empty_proceeds_normally(client, monkeypatch):
    _stub_successful_scan(monkeypatch)
    resp = client.post(
        "/scan",
        data={"target": "https://example.test", "company_website": ""},
    )
    assert resp.status_code == 200
    assert b"Missing HSTS header" in resp.data


def test_scan_domain_cooldown_blocks_repeat_target(client, monkeypatch):
    # Drive the cooldown check directly rather than firing
    # DOMAIN_COOLDOWN_MAX_REQUESTS real POSTs -- that count collides with
    # /scan's own real "5 per minute" per-IP limit (flask-limiter resolves
    # RATELIMIT_ENABLED once at extension-init time, so toggling it on the
    # test client's app.config afterward doesn't actually gate enforcement;
    # storage is only reset between tests via limiter.reset() in conftest).
    import storage

    monkeypatch.setattr(app_module, "is_domain_in_cooldown", lambda target: True)

    def fail_if_called(target):
        raise AssertionError("run_scan should not be called when the target is in cooldown")

    monkeypatch.setattr(app_module, "run_scan", fail_if_called)

    resp = client.post("/scan", data={"target": "https://example.test"}, follow_redirects=True)
    assert resp.status_code == 200
    assert b"already scanned recently" in resp.data

    logged = storage.list_scan_requests()
    assert logged[0]["result_summary"] == "blocked: domain cooldown"


def test_scan_logs_unreachable_target(client, monkeypatch):
    import storage
    from scanner import ScanResult

    monkeypatch.setattr(app_module, "run_scan", lambda target: ScanResult(
        target=target, scanned_at="t", findings=[], reachable=False, error="connection refused",
    ))
    client.post("/scan", data={"target": "https://unreachable.test"})

    logged = storage.list_scan_requests()
    assert len(logged) == 1
    assert logged[0]["result_summary"] == "unreachable: connection refused"


def test_scan_logs_successful_scan_summary(client, monkeypatch):
    import storage

    _stub_successful_scan(monkeypatch)
    client.post("/scan", data={"target": "https://example.test"})

    logged = storage.list_scan_requests()
    assert len(logged) == 1
    assert "grade" in logged[0]["result_summary"]
    assert "1 finding(s)" in logged[0]["result_summary"]


def test_scan_rate_limit_block_is_logged(client):
    # Exercises ratelimit_handler directly rather than firing enough real
    # /scan POSTs to trip flask-limiter's actual "5 per minute" window --
    # that's a real fixed wall-clock window, so a request burst that happens
    # to straddle a minute boundary can silently not trip it, making an
    # integration-style version of this test flaky. The 429-triggers-a-block
    # behavior itself is already covered by
    # test_scan_rate_limit_blocks_after_five_per_minute; this test only
    # needs to confirm the errorhandler logs the block.
    import storage

    with app_module.app.test_request_context(
        "/scan", method="POST", data={"target": "127.0.0.1"},
    ):
        app_module.ratelimit_handler(None)

    logged = storage.list_scan_requests()
    assert logged[0]["result_summary"] == "blocked: rate limit"


def test_admin_scan_log_requires_login(client):
    resp = client.get("/admin/scan-log")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_admin_scan_log_renders_entries(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/scan", data={"target": "https://example.test", "company_website": "bot"})
    client.post("/admin/login", data={"password": "correct-horse"})

    resp = client.get("/admin/scan-log")
    assert resp.status_code == 200
    assert b"blocked: honeypot" in resp.data
    assert b"example.test" in resp.data


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

    calls = []
    monkeypatch.setattr(app_module, "run_monitoring_check", lambda **kwargs: (
        calls.append(kwargs) or
        [{"target": "https://example.test", "status": "checked", "new_findings": 2, "resolved_findings": 0}]
    ))

    resp = client.post("/admin/monitoring/run-now", follow_redirects=True)
    assert b"Checked 1 target" in resp.data
    assert b"1 with new findings" in resp.data
    assert calls == [{"force": True}]  # "Run check now" bypasses each target's own schedule


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


# --- Per-target monitoring interval + direct client alert -------------------

def test_update_monitoring_config_requires_admin_login(client):
    resp = client.post("/admin/monitoring/some-id/config", data={"interval": "weekly"})
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_update_monitoring_config_saves_interval_and_email(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    client.post("/admin/monitoring/toggle", data={"target": "https://example.test"})

    import storage
    target_id = storage.list_monitored_targets()[0]["id"]

    resp = client.post(f"/admin/monitoring/{target_id}/config", data={
        "interval": "monthly", "client_email": "client@business.test",
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert b"Monitoring settings saved" in resp.data
    config = storage.list_monitored_target_configs()[target_id]
    assert config["interval"] == "monthly"
    assert config["client_email"] == "client@business.test"


def test_update_monitoring_config_rejects_unknown_interval(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    client.post("/admin/monitoring/toggle", data={"target": "https://example.test"})

    import storage
    target_id = storage.list_monitored_targets()[0]["id"]

    resp = client.post(f"/admin/monitoring/{target_id}/config", data={
        "interval": "daily", "client_email": "client@business.test",
    }, follow_redirects=True)

    assert b"Unknown re-scan interval" in resp.data
    assert storage.list_monitored_target_configs() == {}


def test_admin_dashboard_renders_monitoring_config_fields(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    client.post("/admin/monitoring/toggle", data={"target": "https://example.test"})

    import storage
    target_id = storage.list_monitored_targets()[0]["id"]
    storage.set_monitored_target_config(target_id, "monthly", "client@business.test")

    resp = client.get("/admin")
    assert resp.status_code == 200
    assert b"client@business.test" in resp.data
    assert b"Monthly" in resp.data


# --- Log monitoring (client-pushed security events) --------------------------

def _monitored_target_id(client):
    client.post("/admin/monitoring/toggle", data={"target": "https://example.test"})
    import storage
    return storage.list_monitored_targets()[0]["id"]


def test_enable_log_monitoring_requires_admin_login(client):
    resp = client.post("/admin/monitoring/some-id/log-ingest/enable")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_enable_log_monitoring_creates_a_token_and_redirects_to_the_event_log(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)

    resp = client.post(f"/admin/monitoring/{target_id}/log-ingest/enable", follow_redirects=True)

    assert resp.status_code == 200
    assert b"Ingestion URL" in resp.data
    import storage
    assert storage.get_log_ingest_config(target_id)["enabled"] is True


def test_disable_log_monitoring_rejects_the_token_afterward(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")

    import storage
    token = storage.get_log_ingest_config(target_id)["token"]
    resp = client.post(f"/admin/monitoring/{target_id}/log-ingest/disable", follow_redirects=True)

    assert b"disabled" in resp.data
    assert storage.get_target_id_for_token(token) is None


def test_regenerate_log_monitoring_token_changes_the_url(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")

    import storage
    old_token = storage.get_log_ingest_config(target_id)["token"]
    resp = client.post(f"/admin/monitoring/{target_id}/log-ingest/regenerate", follow_redirects=True)

    assert resp.status_code == 200
    new_token = storage.get_log_ingest_config(target_id)["token"]
    assert new_token != old_token
    assert storage.get_target_id_for_token(old_token) is None


def test_regenerate_log_monitoring_token_when_never_enabled_flashes(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)

    resp = client.post(f"/admin/monitoring/{target_id}/log-ingest/regenerate", follow_redirects=True)
    assert b"never enabled" in resp.data


def test_view_log_events_requires_admin_login(client):
    resp = client.get("/admin/log-events/some-id")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_view_log_events_without_enabling_first_flashes_and_redirects(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)

    resp = client.get(f"/admin/log-events/{target_id}", follow_redirects=True)
    assert b"hasn&#39;t been enabled" in resp.data or b"hasn't been enabled" in resp.data


def test_view_log_events_shows_the_ingestion_url_and_recent_events(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")

    import storage
    token = storage.get_log_ingest_config(target_id)["token"]
    storage.insert_log_event(target_id, "http_404", "1.2.3.4", "/wp-admin", "not found", None)

    resp = client.get(f"/admin/log-events/{target_id}")
    assert resp.status_code == 200
    assert token.encode() in resp.data
    assert b"http_404" in resp.data
    assert b"/wp-admin" in resp.data


def test_admin_dashboard_shows_enable_button_before_enabled(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    _monitored_target_id(client)

    resp = client.get("/admin")
    assert b"Enable" in resp.data


def test_admin_dashboard_links_to_event_log_once_enabled(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")

    resp = client.get("/admin")
    assert b"View events" in resp.data


# --- POST /ingest/<token> (public, client-pushed security events) -----------

def test_ingest_unknown_token_returns_404(client):
    resp = client.post("/ingest/no-such-token", json={"events": [{"type": "http_404"}]})
    assert resp.status_code == 404
    assert resp.get_json()["accepted"] is False


def test_ingest_non_json_body_returns_400(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")
    import storage
    token = storage.get_log_ingest_config(target_id)["token"]

    resp = client.post(f"/ingest/{token}", data="not json", content_type="text/plain")
    assert resp.status_code == 400


def test_ingest_stores_events_and_reports_the_count(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")
    import storage
    token = storage.get_log_ingest_config(target_id)["token"]

    resp = client.post(f"/ingest/{token}", json={"events": [
        {"type": "http_403", "path": "/admin"}, {"type": "http_404", "path": "/wp-login.php"},
    ]})

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["accepted"] is True
    assert body["stored"] == 2
    assert len(storage.list_recent_log_events(target_id)) == 2


def test_ingest_accepts_a_bare_array_not_just_an_events_key(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")
    import storage
    token = storage.get_log_ingest_config(target_id)["token"]

    resp = client.post(f"/ingest/{token}", json=[{"type": "http_404"}])

    assert resp.status_code == 200
    assert resp.get_json()["stored"] == 1


def test_ingest_has_no_csrf_requirement(client, monkeypatch):
    """A client's server-side app has no browser session or CSRF token --
    this route must work even with CSRF protection globally enabled,
    exactly like /internal/run-monitoring."""
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")
    import storage
    token = storage.get_log_ingest_config(target_id)["token"]

    app_module.app.config["WTF_CSRF_ENABLED"] = True
    try:
        resp = client.post(f"/ingest/{token}", json={"events": [{"type": "http_404"}]})
        assert resp.status_code == 200
    finally:
        app_module.app.config["WTF_CSRF_ENABLED"] = False


def test_ingest_a_disabled_target_stops_accepting_events(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    target_id = _monitored_target_id(client)
    client.post(f"/admin/monitoring/{target_id}/log-ingest/enable")
    import storage
    token = storage.get_log_ingest_config(target_id)["token"]
    client.post(f"/admin/monitoring/{target_id}/log-ingest/disable")

    resp = client.post(f"/ingest/{token}", json={"events": [{"type": "http_404"}]})
    assert resp.status_code == 404


def test_scheduler_prunes_old_log_events(monkeypatch):
    """The background scheduler tick calls prune_old_log_events() -- verify
    it's actually wired in, the same way the followup/monitoring calls
    are checked elsewhere, rather than trusting the source read alone."""
    import inspect
    source = inspect.getsource(app_module._background_scheduler_loop)
    assert "prune_old_log_events" in source


# --- Automatic 48h lead follow-up --------------------------------------------

def test_run_followups_now_requires_admin_login(client):
    resp = client.post("/admin/leads/run-followups-now")
    assert resp.status_code == 302
    assert "/admin/login" in resp.headers["Location"]


def test_run_followups_now_with_none_due_flashes(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    monkeypatch.setattr(app_module, "run_followup_check", lambda: [])

    resp = client.post("/admin/leads/run-followups-now", follow_redirects=True)
    assert b"No leads are due" in resp.data


def test_run_followups_now_flashes_summary(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/admin/login", data={"password": "correct-horse"})
    monkeypatch.setattr(app_module, "run_followup_check", lambda: [
        {"lead_id": "lead-1", "email": "a@test.com", "status": "sent"},
        {"lead_id": "lead-2", "email": "b@test.com", "status": "skipped: SMTP not configured"},
    ])

    resp = client.post("/admin/leads/run-followups-now", follow_redirects=True)
    assert b"Checked 2 due lead" in resp.data
    assert b"1 follow-up email" in resp.data


def test_internal_run_followups_disabled_when_token_unset(client, monkeypatch):
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "")
    resp = client.post("/internal/run-followups")
    assert resp.status_code == 503


def test_internal_run_followups_rejects_wrong_token(client, monkeypatch):
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "the-real-token")
    resp = client.post("/internal/run-followups", headers={"X-Internal-Token": "wrong-token"})
    assert resp.status_code == 401


def test_internal_run_followups_accepts_correct_token(client, monkeypatch):
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "the-real-token")
    monkeypatch.setattr(app_module, "run_followup_check", lambda: [
        {"lead_id": "lead-1", "email": "a@test.com", "status": "sent"},
    ])
    resp = client.post("/internal/run-followups", headers={"X-Internal-Token": "the-real-token"})
    assert resp.status_code == 200
    assert resp.get_json()["checked"] == 1


def test_internal_run_followups_has_no_csrf_requirement(client, monkeypatch):
    monkeypatch.setattr(app_module, "INTERNAL_JOB_TOKEN", "the-real-token")
    monkeypatch.setattr(app_module, "run_followup_check", lambda: [])
    app_module.app.config["WTF_CSRF_ENABLED"] = True
    try:
        resp = client.post("/internal/run-followups", headers={"X-Internal-Token": "the-real-token"})
        assert resp.status_code == 200
    finally:
        app_module.app.config["WTF_CSRF_ENABLED"] = False


def test_admin_dashboard_shows_followup_sent_status(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    client.post("/lead", data={
        "email": "prospect@test.com", "target": "https://example.test",
        "grade": "C", "score": "63",
    })
    import storage
    lead_id = storage.list_leads()[0]["id"]
    storage.record_lead_followup_sent(lead_id, "following up...", "rule-based")

    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.get("/admin")
    assert b"Sent " in resp.data


def test_admin_dashboard_notes_when_smtp_not_configured(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(app_module.emailer, "SMTP_USERNAME", "")
    monkeypatch.setattr(app_module.emailer, "SMTP_PASSWORD", "")
    client.post("/admin/login", data={"password": "correct-horse"})

    resp = client.get("/admin")
    assert b"Off right now" in resp.data


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


# --- Branded report output (contact info + paid-audit CTA) -------------------

def _render_print_html_via_pdf_route(client, monkeypatch):
    """Runs a real /scan then /report/<id>/pdf, capturing the HTML handed to
    pdf_export.render_pdf -- the exact document both the download and the
    emailed PDF are rendered from."""
    import re
    _stub_successful_scan(monkeypatch)
    resp = client.post("/scan", data={"target": "https://example.test"})
    scan_id = re.search(rb'/report/([\w-]+)/pdf', resp.data).group(1).decode()

    captured = {}
    monkeypatch.setattr(app_module.pdf_export, "render_pdf", lambda html: captured.setdefault("html", html) and b"%PDF")
    client.get(f"/report/{scan_id}/pdf")
    return captured["html"]


def test_print_report_always_carries_brand_and_audit_cta(client, monkeypatch):
    for var in ("BRAND_CONTACT_EMAIL", "BRAND_CONTACT_URL", "BRAND_AUDIT_CTA"):
        monkeypatch.delenv(var, raising=False)
    html = _render_print_html_via_pdf_route(client, monkeypatch)
    assert "SiteGuard AI" in html
    assert "Next step: full security audit" in html
    assert "human review of each finding" in html


def test_print_report_omits_contact_lines_when_unset(client, monkeypatch):
    for var in ("BRAND_CONTACT_EMAIL", "BRAND_CONTACT_URL"):
        monkeypatch.delenv(var, raising=False)
    html = _render_print_html_via_pdf_route(client, monkeypatch)
    assert "Contact SiteGuard AI" not in html
    assert "Questions about this report?" not in html
    assert "mailto:" not in html


def test_print_report_shows_contact_info_when_set(client, monkeypatch):
    monkeypatch.setenv("BRAND_CONTACT_EMAIL", "audits@siteguard.test")
    monkeypatch.setenv("BRAND_CONTACT_URL", "https://fiverr.example/siteguard")
    html = _render_print_html_via_pdf_route(client, monkeypatch)
    assert 'href="mailto:audits@siteguard.test"' in html
    assert 'href="https://fiverr.example/siteguard"' in html
    assert "Contact SiteGuard AI" in html
    assert "Questions about this report?" in html


def test_print_report_uses_custom_audit_cta_text(client, monkeypatch):
    monkeypatch.setenv("BRAND_AUDIT_CTA", "Book a 2-week audit with manual verification.")
    html = _render_print_html_via_pdf_route(client, monkeypatch)
    assert "Book a 2-week audit with manual verification." in html
    assert "human review of each finding" not in html


def test_print_report_escapes_contact_values(client, monkeypatch):
    monkeypatch.setenv("BRAND_CONTACT_EMAIL", '"><script>alert(1)</script>')
    html = _render_print_html_via_pdf_route(client, monkeypatch)
    assert "<script>alert(1)</script>" not in html


def test_emailed_pdf_html_carries_branding_too(monkeypatch):
    """The lead-capture email renders the same template on a background
    thread with only an app context (no request) -- the branding context
    processor has to work there too."""
    from scanner import ScanResult

    monkeypatch.setenv("BRAND_CONTACT_EMAIL", "audits@siteguard.test")
    result = ScanResult(target="https://example.test", scanned_at="t", findings=[], reachable=True, error=None)
    monkeypatch.setattr(app_module, "load_scan", lambda scan_id: (result, "summary", "rule-based"))

    captured = {}
    monkeypatch.setattr(app_module.pdf_export, "render_pdf", lambda html: captured.setdefault("html", html) and b"%PDF")
    monkeypatch.setattr(app_module.emailer, "send_report_email", lambda *a, **k: True)

    app_module._send_report_email_background("lead@test.com", "abc123", "https://x.test/report/abc123")

    assert "audits@siteguard.test" in captured["html"]
    assert "Next step: full security audit" in captured["html"]


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


# --- "JavaScript files checked" line on the report -------------------------------

def _saved_scan_id(js_files_checked):
    import storage
    from scanner import ScanResult
    result = ScanResult(target="https://example.test", scanned_at="t", findings=[], reachable=True,
                        error=None, js_files_checked=js_files_checked)
    return storage.save_scan(result, "summary", "rule-based")


def test_report_says_how_many_js_files_were_checked_plural(client):
    resp = client.get(f"/report/{_saved_scan_id(3)}")
    assert b"Also checked 3 JavaScript files" in resp.data


def test_report_says_how_many_js_files_were_checked_singular(client):
    resp = client.get(f"/report/{_saved_scan_id(1)}")
    assert b"Also checked 1 JavaScript file" in resp.data
    assert b"1 JavaScript files" not in resp.data


def test_report_says_when_no_js_files_were_found(client):
    resp = client.get(f"/report/{_saved_scan_id(0)}")
    assert b"No separate JavaScript files were found" in resp.data


def test_report_omits_the_line_for_scans_that_never_ran_the_check(client):
    resp = client.get(f"/report/{_saved_scan_id(None)}")
    assert b"JavaScript file" not in resp.data


def test_homepage_mentions_the_javascript_check(client):
    assert b"leaked keys or passwords in your JavaScript" in client.get("/").data
