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


def test_active_scan_start_logs_authorization_and_runs(client, monkeypatch):
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-horse")
    monkeypatch.setattr(app_module, "ACTIVE_TESTING_ENABLED", True)

    logged = {}
    monkeypatch.setattr(app_module, "log_active_scan_authorization",
                         lambda target, hostname: logged.update(target=target, hostname=hostname))

    from active_scan import ActiveScanResult
    monkeypatch.setattr(app_module, "run_active_scan",
                         lambda target: ActiveScanResult(target=target, scanned_at="t", findings=[]))

    client.post("/admin/login", data={"password": "correct-horse"})
    resp = client.post("/admin/active-scan", data={
        "target": "https://example.test", "confirm_host": "example.test", "authorized": "on",
    }, follow_redirects=True)

    assert resp.status_code == 200
    assert logged == {"target": "https://example.test", "hostname": "example.test"}
    assert b"No issues found by these checks." in resp.data


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
