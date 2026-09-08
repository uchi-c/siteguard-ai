"""
Headless-browser fallback for active-scan discovery.

Some sites (React/Vue/Next.js-style SPAs) render their real forms via
client-side JavaScript, so the plain regex-based HTML crawl in
active_scan.py's _discover_injection_points finds nothing to test even on
a page with a real signup/login/contact form -- it only ever sees the raw
HTML a server returns, never what JS does to the DOM after. This is what
surfaced against uruu.enterprises: a real page with a real signup form, but
0 forms and 0 query-string links in the raw response.

Only used as a fallback when that fast, dependency-free crawl finds zero
points -- launching a browser is much heavier (memory, startup time, a
~150-300MB Chromium install) than a single GET request, so it's not worth
paying that cost on the more common traditional server-rendered site.

The actual rendering happens in js_discovery_worker.py, run as a *subprocess*
rather than imported and run on a thread here -- see that file's docstring
for why. This module's only job is spawning it and turning any failure
(Playwright not installed, browser not installed, launch failure, timeout,
a crash) into an empty list. A scan must never break because this fallback
didn't work; it should just behave as if the fallback didn't exist.

Gated by ACTIVE_SCAN_JS_DISCOVERY (on by default, wherever
ACTIVE_TESTING_ENABLED is already on) so it can be turned off with just an
env var -- no code change or redeploy -- if headless Chromium turns out to
be too heavy for the host's memory budget.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

JS_DISCOVERY_ENABLED = os.environ.get("ACTIVE_SCAN_JS_DISCOVERY", "1") != "0"
_WORKER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "js_discovery_worker.py")
_SUBPROCESS_TIMEOUT = 25  # seconds -- generous over the worker's own 15s nav timeout + 1.5s settle


def discover_injection_points_js(base_url: str) -> list[dict]:
    if not JS_DISCOVERY_ENABLED:
        return []
    try:
        proc = subprocess.run(
            [sys.executable, _WORKER_SCRIPT, base_url],
            capture_output=True, text=True, timeout=_SUBPROCESS_TIMEOUT,
        )
        if proc.returncode != 0:
            return []
        return json.loads(proc.stdout)
    except Exception:
        return []
