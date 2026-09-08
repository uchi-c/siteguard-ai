"""
PDF export for a saved scan report: renders the print-optimized report
template to a PDF using headless Chromium (see pdf_export_worker.py), the
same subprocess-isolation pattern js_discovery.py uses for active-scan's
SPA fallback, and for the same reason -- a Chromium crash, hang, or OOM
happens in its own process, not the main app, so it can't take the site
down. Any failure here (Playwright/Chromium not installed, render timeout,
a crash) just means "couldn't generate a PDF right now," same as the
JS-discovery fallback treats its own failures as "found nothing."
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import traceback

_WORKER_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pdf_export_worker.py")
_SUBPROCESS_TIMEOUT = 30  # seconds -- a single static page render, should be fast


def render_pdf(html: str) -> bytes | None:
    """Renders an HTML string to a PDF and returns its bytes, or None on
    any failure. Failures are logged (not just swallowed) so a broken
    Chromium install shows up in the app's logs instead of just silently
    never working."""
    try:
        with tempfile.TemporaryDirectory() as tmp:
            html_path = os.path.join(tmp, "report.html")
            pdf_path = os.path.join(tmp, "report.pdf")
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html)

            proc = subprocess.run(
                [sys.executable, _WORKER_SCRIPT, html_path, pdf_path],
                capture_output=True, timeout=_SUBPROCESS_TIMEOUT,
            )
            if proc.returncode != 0 or not os.path.exists(pdf_path):
                print(f"[pdf_export] worker failed (exit {proc.returncode}): "
                      f"{proc.stderr.decode('utf-8', 'replace')[-4000:]}", file=sys.stderr)
                return None
            with open(pdf_path, "rb") as f:
                return f.read()
    except Exception:
        print("[pdf_export] render_pdf failed:", file=sys.stderr)
        traceback.print_exc()
        return None
