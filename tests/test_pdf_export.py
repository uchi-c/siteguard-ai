"""
Tests pdf_export.py against a real headless Chromium. Skipped entirely
when Playwright's browser isn't installed (this dev sandbox has no network
access to download it) -- the graceful-degradation path (what happens when
rendering fails) is covered without a real browser below.
"""
import pytest

from pdf_export import render_pdf


def test_render_pdf_returns_none_when_worker_fails(monkeypatch):
    """No real browser needed: a non-zero exit from the worker subprocess
    (Chromium missing, crashed, whatever) must degrade to None, never
    raise -- this is the path that runs in this sandbox and matters most
    for not breaking the /lead flow or the /report/<id>/pdf route."""
    import subprocess

    def fake_run(*a, **k):
        return subprocess.CompletedProcess(args=[], returncode=1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert render_pdf("<html><body>hi</body></html>") is None


def test_render_pdf_returns_none_on_subprocess_exception(monkeypatch):
    import subprocess

    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="x", timeout=30)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert render_pdf("<html><body>hi</body></html>") is None


playwright = pytest.importorskip("playwright")


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.launch().close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _chromium_available(), reason="Chromium not installed for Playwright")
def test_render_pdf_produces_real_pdf_bytes():
    result = render_pdf("<html><body><h1>Test report</h1></body></html>")
    assert result is not None
    assert result[:5] == b"%PDF-"
