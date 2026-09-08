"""
Standalone worker, run as a subprocess by js_discovery.py: renders a URL in
headless Chromium and prints the discovered {"url", "param"} injection
points as JSON on stdout.

Runs in its own fresh OS process rather than a thread inside the main
gunicorn worker -- a Chromium crash, OOM, or hang can't take the rest of
the site down with it, and there's no ambiguity about Playwright's sync API
running outside the main thread of whatever process calls it, since this
process's main thread is all it ever uses.

Not meant to be imported -- run directly: `python js_discovery_worker.py <url>`
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
NAV_TIMEOUT_MS = 15_000
# How long to let client-side JS run after the initial HTML loads before
# reading the DOM -- long enough for a typical React/Vue/Next.js app to
# hydrate and render its real forms, short enough to keep the whole
# discovery step well under active-scan's per-point time budget.
RENDER_SETTLE_MS = 1500
USER_AGENT = "SiteGuardAI-Scanner/1.0 (+active security test; JS-rendered discovery)"


def discover(base_url: str) -> list[dict]:
    from playwright.sync_api import sync_playwright

    points: list[dict] = []
    seen = set()

    def add(url, param):
        key = (url, param)
        if key not in seen:
            seen.add(key)
            points.append({"url": url, "param": param})

    with sync_playwright() as p:
        browser = p.chromium.launch(
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            page = browser.new_page(user_agent=USER_AGENT)
            page.goto(base_url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
            page.wait_for_timeout(RENDER_SETTLE_MS)

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
        finally:
            browser.close()

    return points


if __name__ == "__main__":
    try:
        print(json.dumps(discover(sys.argv[1])))
    except Exception:
        import traceback
        traceback.print_exc()
        print(json.dumps([]))
        sys.exit(1)
