"""
Standalone worker, run as a subprocess by js_discovery.py: renders a URL in
headless Chromium and prints the discovered {"url", "param"} injection
points as JSON on stdout.

Runs in its own fresh OS process rather than a thread inside the main
gunicorn worker -- a Chromium crash, OOM, or hang can't take the rest of
the site down with it, and there's no ambiguity about Playwright's sync API
running outside the main thread of whatever process calls it, since this
process's main thread is all it ever uses.

Not meant to be imported -- run directly:
    python js_discovery_worker.py <url> [test_post_forms: 0|1]
Prints `[]` and exits non-zero on any failure; the caller treats that the
same as "found nothing", never as something to propagate or retry.
"""
from __future__ import annotations

import json
import sys
from urllib.parse import parse_qs, urljoin, urlparse

STATIC_ASSET_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".ico", ".map",
)
# Deliberately much lower than the GET/link cap above (implicitly
# unbounded here, capped by MAX_INJECTION_POINTS back in active_scan.py)
# -- every POST point means a real form submission, repeated once per
# check, unlike an inert GET request. See active_scan.py's module
# docstring for the full reasoning.
MAX_POST_INJECTION_POINTS = 3
POST_FORM_SKIP_TYPES = ("checkbox", "radio", "submit", "button", "image", "reset", "file")
NAV_TIMEOUT_MS = 15_000
# How long to let client-side JS run after the initial HTML loads before
# reading the DOM -- long enough for a typical React/Vue/Next.js app to
# hydrate and render its real forms, short enough to keep the whole
# discovery step well under active-scan's per-point time budget.
RENDER_SETTLE_MS = 1500
USER_AGENT = "SiteGuardAI-Scanner/1.0 (+active security test; JS-rendered discovery)"


def _extract_points(page, base_url: str) -> list[dict]:
    points: list[dict] = []
    seen = set()

    def add(url, param):
        key = (url, param)
        if key not in seen:
            seen.add(key)
            points.append({"url": url, "param": param})

    for form in page.query_selector_all("form"):
        method = (form.get_attribute("method") or "get").lower()
        if method != "get":
            continue  # skip POST forms -- don't submit unknown data to them
        action = urljoin(base_url, form.get_attribute("action") or base_url)
        for input_el in form.query_selector_all("input[name]"):
            name = input_el.get_attribute("name")
            if name:
                add(action, name)

    origin = urlparse(base_url).netloc
    for a in page.query_selector_all("a[href*='?']"):
        href = a.get_attribute("href")
        if not href:
            continue
        link = urljoin(base_url, href)
        parsed = urlparse(link)
        if parsed.netloc != origin:
            continue
        if parsed.path.lower().endswith(STATIC_ASSET_EXTENSIONS):
            continue
        for param in parse_qs(parsed.query):
            add(link, param)

    return points


def _field_placeholder(name: str, input_type: str) -> str:
    """Kept in sync with the identical helper in active_scan.py -- this
    worker runs as its own subprocess and doesn't import that module (see
    the file docstring), so the logic is duplicated rather than shared."""
    n = name.lower()
    t = (input_type or "text").lower()
    if "email" in n or t == "email":
        return "sgaiprobe@example.test"
    if "pass" in n or t == "password":
        return "SgaiProbe123!@#"
    if "phone" in n or "tel" in n or t == "tel":
        return "5555550100"
    if t == "url":
        return "https://example.test"
    if "name" in n:
        return "SGAI Test"
    return "sgaiplaceholder1"


def _extract_post_points(page, base_url: str) -> list[dict]:
    points: list[dict] = []
    seen = set()

    def add(url, param, fields):
        key = (url, param)
        if key not in seen:
            seen.add(key)
            points.append({"url": url, "param": param, "method": "post", "fields": fields})

    for form in page.query_selector_all("form"):
        if len(points) >= MAX_POST_INJECTION_POINTS:
            break
        method = (form.get_attribute("method") or "get").lower()
        if method != "post":
            continue
        action = urljoin(base_url, form.get_attribute("action") or base_url)

        testable = []
        fields = {}
        for input_el in form.query_selector_all("input[name]"):
            name = input_el.get_attribute("name")
            if not name:
                continue
            input_type = (input_el.get_attribute("type") or "text").lower()
            if input_type in POST_FORM_SKIP_TYPES:
                continue
            if input_type == "hidden":
                fields[name] = input_el.get_attribute("value") or ""
                continue
            testable.append(name)
            fields[name] = _field_placeholder(name, input_type)

        for name in testable:
            if len(points) >= MAX_POST_INJECTION_POINTS:
                break
            add(action, name, {k: v for k, v in fields.items() if k != name})

    return points


def discover(base_url: str, test_post_forms: bool = False) -> list[dict]:
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            page = browser.new_page(user_agent=USER_AGENT)
            page.goto(base_url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            page.wait_for_timeout(RENDER_SETTLE_MS)
            try:
                # Some sites keep navigating after the initial load (a
                # client-side redirect, an SPA router settling on its real
                # route) -- give that a chance to finish before reading the
                # DOM, or a mid-flight navigation destroys the execution
                # context right as we try to query it.
                page.wait_for_load_state("networkidle", timeout=5000)
            except PlaywrightError:
                pass  # best-effort -- fine if it never goes fully idle

            def _gather():
                points = _extract_points(page, base_url)
                if test_post_forms:
                    points = points + _extract_post_points(page, base_url)
                return points

            try:
                return _gather()
            except PlaywrightError:
                # A navigation raced with the query above despite the wait
                # -- the page has almost certainly settled by now, so one
                # retry is worth it rather than giving up entirely.
                page.wait_for_timeout(1000)
                return _gather()
        finally:
            browser.close()


if __name__ == "__main__":
    try:
        test_post_forms = len(sys.argv) > 2 and sys.argv[2] == "1"
        print(json.dumps(discover(sys.argv[1], test_post_forms)))
    except Exception:
        import traceback
        traceback.print_exc()
        print(json.dumps([]))
        sys.exit(1)
