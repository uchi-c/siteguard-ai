"""
Tests js_discovery.py against a real headless Chromium. Skipped entirely
when Playwright's browser isn't installed (this dev sandbox has no network
access to download it) -- the wiring itself (that active_scan.py falls back
to this module correctly) is covered without a real browser in
test_active_scan.py; these confirm the browser side actually works.
"""
import pytest

pytest.importorskip("playwright")


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            p.chromium.launch().close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _chromium_available(), reason="Chromium not installed for Playwright")

from js_discovery import discover_injection_points_js  # noqa: E402


def test_discovers_form_rendered_by_client_side_js(js_spa_target_url):
    points = discover_injection_points_js(js_spa_target_url)
    assert {"url": js_spa_target_url + "/search", "param": "q"} in points


def test_returns_empty_list_when_disabled(monkeypatch, js_spa_target_url):
    import js_discovery
    monkeypatch.setattr(js_discovery, "JS_DISCOVERY_ENABLED", False)
    assert js_discovery.discover_injection_points_js(js_spa_target_url) == []


def test_returns_empty_list_on_unreachable_target():
    assert discover_injection_points_js("http://127.0.0.1:1/nope") == []
