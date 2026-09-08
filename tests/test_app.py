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
