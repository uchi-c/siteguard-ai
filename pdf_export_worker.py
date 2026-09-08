"""
Standalone worker, run as a subprocess by pdf_export.py: renders an HTML
string as a PDF using headless Chromium's print-to-PDF, the same isolation
pattern as js_discovery_worker.py and for the same reasons (a Chromium
crash/hang/OOM can't take the main app down with it if it's not running in
that process at all).

Not meant to be imported -- run directly:
    python pdf_export_worker.py <html_input_path> <pdf_output_path>
Reads the HTML to render from html_input_path, writes the PDF to
pdf_output_path. Exits non-zero on any failure; the caller (pdf_export.py)
treats that as "couldn't generate a PDF right now."
"""
from __future__ import annotations

import sys


def render(html_path: str, pdf_path: str) -> None:
    from playwright.sync_api import sync_playwright

    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    with sync_playwright() as p:
        browser = p.chromium.launch(
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        try:
            page = browser.new_page()
            page.set_content(html, wait_until="load")
            page.pdf(
                path=pdf_path,
                format="A4",
                print_background=True,
                margin={"top": "18mm", "bottom": "18mm", "left": "14mm", "right": "14mm"},
            )
        finally:
            browser.close()


if __name__ == "__main__":
    try:
        render(sys.argv[1], sys.argv[2])
    except Exception:
        sys.exit(1)
