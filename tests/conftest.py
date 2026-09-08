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
    reflected XSS, error-based SQLi, SSTI, path traversal, OS command
    injection, open redirect, and a login form that accepts one specific
    weak credential pair. No external network involved, matches the
    pattern already used by test_target.py."""
    from flask import Flask, redirect, request as flask_request

    vuln = Flask("vulnerable_test_target")

    @vuln.route("/")
    def home():
        q = flask_request.args.get("q", "")
        return (f'<html><body>'
                f'<a href="/?q=test">self link</a>'
                f'<form method="get" action="/search"><input name="term"></form>'
                f'<form method="get" action="/render"><input name="tpl"></form>'
                f'<form method="get" action="/file"><input name="path"></form>'
                f'<form method="get" action="/run"><input name="cmd"></form>'
                f'<form method="get" action="/go"><input name="redirect"></form>'
                f'Results: {q}'
                f'</body></html>')

    @vuln.route("/search")
    def search():
        term = flask_request.args.get("term", "")
        if "'" in term:
            return "Error: you have an error in your SQL syntax near...", 500
        return f"<html><body>Search results for: {term}</body></html>"

    @vuln.route("/render")
    def render_route():
        """Simulates a template engine evaluating user input -- only
        reflects the evaluated *result*, never the raw input, so this
        can't accidentally also trigger the reflected-XSS check."""
        tpl = flask_request.args.get("tpl", "")
        if tpl in ("{{7*7}}", "${7*7}"):
            return "<html><body>Result: 49</body></html>"
        return "<html><body>Result: (n/a)</body></html>"

    @vuln.route("/file")
    def file_route():
        """Simulates a path-traversal-vulnerable file reader -- only
        returns canned file content, never reflects the raw path."""
        path = flask_request.args.get("path", "")
        normalized = path.replace("\\", "/").lower()
        if "etc/passwd" in normalized:
            return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n"
        if "win.ini" in normalized:
            return "[extensions]\n[fonts]\n"
        return "File not found", 404

    @vuln.route("/run")
    def run_route():
        """Simulates OS command injection via string concatenation into a
        shell call -- only echoes back the marker after a real shell
        metacharacter + 'echo', matching the four payload templates."""
        cmd = flask_request.args.get("cmd", "")
        if "echo " in cmd and any(sep in cmd for sep in (";", "|", "`", "$(")):
            marker = cmd.split("echo ", 1)[1].rstrip("`) ")
            return f"<html><body>Output: {marker}</body></html>"
        return "<html><body>Output: command not found</body></html>"

    @vuln.route("/go")
    def go_route():
        """Simulates an unvalidated redirect -- sends the visitor wherever
        the param says, no allow-list check."""
        target = flask_request.args.get("redirect", "/")
        return redirect(target, code=302)

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
def vulnerable_scan_result(vulnerable_target_url):
    """Runs the full active scan against vulnerable_target_url exactly
    once for the whole session -- with 6 checks per discovered point, a
    full scan takes real wall-clock time, and most tests just want to
    assert on one specific finding, not re-run the whole thing each time.

    ALLOW_PRIVATE_TARGETS is patched directly (the allow_private fixture
    is function-scoped and can't be used from a session-scoped fixture),
    but the mutation window is closed BEFORE yielding: run the scan, then
    restore the flag, then yield the already-computed result. A
    session-scoped fixture's generator stays paused at its yield for the
    rest of the session, so restoring only *after* yield would leave
    ALLOW_PRIVATE_TARGETS=True leaking into every other test that runs
    afterward (this happened -- it broke the unrelated SSRF tests)."""
    import scanner
    import active_scan
    original = scanner.ALLOW_PRIVATE_TARGETS
    scanner.ALLOW_PRIVATE_TARGETS = True
    try:
        result = active_scan.run_active_scan(vulnerable_target_url)
    finally:
        scanner.ALLOW_PRIVATE_TARGETS = original
    yield result


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


@pytest.fixture(scope="session")
def vulnerable_post_target_url():
    """A page with ONLY a POST form (no GET points at all) -- validates
    active_scan.py's opt-in POST-form testing path end to end: discovery
    must capture the hidden CSRF token's real value and skip the
    checkbox, and the probe must submit a full body (all fields, not just
    the one under test) or the server-side checks below reject it and no
    finding is produced. A finding showing up is proof the whole pipeline
    (discovery -> field-filling -> probing) worked correctly; its absence
    would mean something regressed."""
    from flask import Flask, request as flask_request

    vuln = Flask("vulnerable_post_test_target")

    @vuln.route("/")
    def home():
        return ('<html><body>'
                '<form method="post" action="/contact">'
                '<input type="hidden" name="csrf_token" value="fixed-token-abc">'
                '<input type="text" name="name">'
                '<input type="email" name="email">'
                '<input type="text" name="message">'
                '<input type="checkbox" name="subscribe">'
                '<input type="submit" value="Send">'
                '</form>'
                '</body></html>')

    @vuln.route("/contact", methods=["POST"])
    def contact():
        if flask_request.form.get("csrf_token") != "fixed-token-abc":
            return "Invalid CSRF token", 403
        if "subscribe" in flask_request.form:
            return "Unexpected checkbox value submitted", 400
        message = flask_request.form.get("message", "")
        return f"<html><body>Thanks! Message: {message}</body></html>"

    srv = _ServerThread(vuln)
    srv.start()
    yield f"http://127.0.0.1:{srv.port}"
    srv.shutdown()


@pytest.fixture(scope="session")
def js_spa_target_url():
    """A minimal SPA-style page whose form only exists in the DOM after
    client-side JS runs -- the raw HTML response has none, matching real
    React/Vue/Next.js sites (this is what surfaced the gap against a real
    site, uruu.enterprises). Regression target for js_discovery.py: the
    regex-based crawl in active_scan.py finds 0 points here on its own; the
    headless-browser fallback should find the real one once it renders."""
    from flask import Flask, request as flask_request

    spa = Flask("js_spa_test_target")

    @spa.route("/")
    def home():
        return ('<html><body><div id="root"></div><script>'
                'document.getElementById("root").innerHTML = '
                '\'<form method="get" action="/search"><input name="q"></form>\';'
                '</script></body></html>')

    @spa.route("/search")
    def search():
        q = flask_request.args.get("q", "")
        return f"<html><body>Results: {q}</body></html>"

    srv = _ServerThread(spa)
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
