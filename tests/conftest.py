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


@pytest.fixture
def allow_private(monkeypatch):
    """Lets the SSRF guard through for tests that deliberately scan 127.0.0.1."""
    monkeypatch.setattr(scanner, "ALLOW_PRIVATE_TARGETS", True)


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A Flask test client with leads/scans redirected to a temp dir, CSRF
    and rate limiting off by default (individual tests re-enable either
    when that's exactly what they're testing), and no ADMIN_PASSWORD
    unless a test sets one."""
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
