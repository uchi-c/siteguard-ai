import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.serving import make_server

import app as app_module
import scanner
import storage


class _ServerThread(threading.Thread):
    """Runs a Flask app on an ephemeral localhost port for the life of a test session."""

    def __init__(self, flask_app):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", 0, flask_app)
        self.port = self.server.server_port

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


@pytest.fixture(scope="session")
def test_target_url():
    """test_target.py's real, deliberately-misconfigured Flask app -- the
    same fixture used for manual testing throughout development, run here
    on an ephemeral port instead of the fixed 5055 so tests never collide
    with a manually-running instance."""
    import test_target
    srv = _ServerThread(test_target.app)
    srv.start()
    yield f"http://127.0.0.1:{srv.port}"
    srv.shutdown()


@pytest.fixture(scope="session")
def spa_target_url():
    """A minimal stand-in for an SPA host with a catch-all rewrite (e.g.
    Vercel): every path, including nonexistent ones, returns the same
    shell. Regression-tests the false-positive fix in
    _check_sensitive_paths."""
    from flask import Flask

    spa = Flask("spa_test_target")

    @spa.route("/", defaults={"path": ""})
    @spa.route("/<path:path>")
    def catch_all(path):
        return "<html><body>SPA shell</body></html>", 200

    srv = _ServerThread(spa)
    srv.start()
    yield f"http://127.0.0.1:{srv.port}"
    srv.shutdown()


@pytest.fixture(scope="session")
def cloudflare_target_url():
    """A local server that mimics Cloudflare's response fingerprint, for
    testing passive WAF/CDN detection without hitting a real edge network."""
    from flask import Flask, make_response

    cf = Flask("cloudflare_test_target")

    @cf.route("/")
    def home():
        resp = make_response("<html><body>behind cloudflare</body></html>")
        resp.headers["CF-RAY"] = "8a1b2c3d4e5f6789-SJC"
        resp.headers["Server"] = "cloudflare"
        return resp

    srv = _ServerThread(cf)
    srv.start()
    yield f"http://127.0.0.1:{srv.port}"
    srv.shutdown()


@pytest.fixture(scope="session")
def vulnerable_target_url():
    """A deliberately vulnerable local app, used ONLY to validate
    active_scan.py's detection logic in a controlled, offline setting --
    reflected XSS on two params, error-based SQLi on one, and a login form
    that accepts one specific weak credential pair. No external network
    involved, matches the pattern already used by test_target.py."""
    from flask import Flask, redirect, request as flask_request

    vuln = Flask("vulnerable_test_target")

    @vuln.route("/")
    def home():
        q = flask_request.args.get("q", "")
        return (f'<html><body>'
                f'<a href="/?q=test">self link</a>'
                f'<form method="get" action="/search"><input name="term"></form>'
                f'Results: {q}'
                f'</body></html>')

    @vuln.route("/search")
    def search():
        term = flask_request.args.get("term", "")
        if "'" in term:
            return "Error: you have an error in your SQL syntax near...", 500
        return f"<html><body>Search results for: {term}</body></html>"

    @vuln.route("/admin", methods=["GET"])
    def admin_login_page():
        return ('<html><body><form method="post" action="/admin">'
                '<input name="username"><input type="password" name="password">'
                '</form></body></html>')

    @vuln.route("/admin", methods=["POST"])
    def admin_login_post():
        if flask_request.form.get("username") == "admin" and flask_request.form.get("password") == "admin":
            return redirect("/dashboard", code=302)
        return redirect("/admin/login?error=invalid", code=302)

    srv = _ServerThread(vuln)
    srv.start()
    yield f"http://127.0.0.1:{srv.port}"
    srv.shutdown()


@pytest.fixture(scope="session")
def wordpress_like_target_url():
    """Regression fixture for a real bug: a page with a real GET search
    form (a classic reflected-XSS target) plus 20 cache-busting `?ver=`
    links on its own static assets (very common on WordPress). Discovery
    used to collect link-based points before form-based ones, so with
    MAX_INJECTION_POINTS capping the total, the cache-busters filled every
    slot and the search form's real parameter was silently dropped --
    the scan would "run" and find nothing on a page with an obvious
    target sitting right there."""
    from flask import Flask, request as flask_request

    wp = Flask("wordpress_like_test_target")

    @wp.route("/")
    def home():
        asset_links = "".join(
            f'<link rel="stylesheet" href="/assets/style{i}.css?ver=1.0.{i}">'
            for i in range(20)
        )
        return (f'<html><head>{asset_links}</head><body>'
                f'<form method="get" class="search-form" action="/">'
                f'<input type="search" name="s"></form>'
                f'</body></html>')

    @wp.route("/assets/<path:filename>")
    def asset(filename):
        return "/* css */", 200, {"Content-Type": "text/css"}

    srv = _ServerThread(wp)
    srv.start()
    yield f"http://127.0.0.1:{srv.port}"
    srv.shutdown()


@pytest.fixture
def allow_private(monkeypatch):
    """Lets the SSRF guard through for tests that deliberately scan 127.0.0.1."""
    monkeypatch.setattr(scanner, "ALLOW_PRIVATE_TARGETS", True)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A Flask test client with leads/scans redirected to a temp dir, CSRF
    and rate limiting off by default (individual tests re-enable either
    when that's exactly what they're testing), and no ADMIN_PASSWORD
    unless a test sets one.

    RATELIMIT_ENABLED=False only skips *enforcement* -- Flask-Limiter's
    in-memory storage still records every hit. Since Werkzeug's test client
    always uses 127.0.0.1, that key is shared across every test in the
    session, so counts silently accumulate and can trip a real 429 in a
    later test that never touched the rate-limit config itself. Reset the
    limiter's storage before every test, not just the enabled flag.
    """
    app_module.limiter.reset()
    monkeypatch.setattr(app_module, "LEADS_FILE", str(tmp_path / "leads.csv"))
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    monkeypatch.delenv("ADMIN_PASSWORD", raising=False)
    app_module.app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=False,
        RATELIMIT_ENABLED=False,
    )
    with app_module.app.test_client() as c:
        yield c
    app_module.app.config.update(WTF_CSRF_ENABLED=False, RATELIMIT_ENABLED=False)
