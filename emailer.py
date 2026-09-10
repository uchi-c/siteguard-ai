"""
Emails a scan report to a lead who submitted their address on the "send me
the fix plan" form. Off by default -- like ANTHROPIC_API_KEY and
ADMIN_PASSWORD, it just does nothing useful until its env vars are set, so
a fresh checkout with no SMTP configured still works (lead capture still
logs to leads.csv; it just doesn't also email anything).

SMTP credentials (SMTP_USERNAME/SMTP_PASSWORD) are never something Claude
enters here or anywhere else -- set them directly in Render's environment
variables (or a local .env for dev), the same way ADMIN_PASSWORD is set.

send_report_email never raises: a bad SMTP config, a network hiccup, or a
rejected send should never break the lead-capture flow that triggers it --
the lead is already logged by the time this runs, and that's the part that
actually matters.
"""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM") or SMTP_USERNAME


def is_configured() -> bool:
    return bool(SMTP_USERNAME and SMTP_PASSWORD)


def send_report_email(
    to_email: str, target: str, grade: str, score: int, report_url: str,
    pdf_bytes: bytes | None = None,
) -> bool:
    """Sends the report link (and PDF, if generated) to to_email. Returns
    whether it actually sent -- never raises."""
    if not is_configured():
        return False

    try:
        msg = EmailMessage()
        msg["Subject"] = f"Your SiteGuard AI security report for {target} (grade {grade})"
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg.set_content(
            f"Here's your free security scan for {target}.\n\n"
            f"Grade: {grade}  ({score}/100)\n\n"
            f"Full report: {report_url}\n\n"
            + ("A PDF copy is attached.\n\n" if pdf_bytes else "")
            + "We'll follow up shortly with a prioritized, no-obligation fix plan.\n\n"
            "-- SiteGuard AI"
        )
        if pdf_bytes:
            msg.add_attachment(
                pdf_bytes, maintype="application", subtype="pdf",
                filename="siteguard-report.pdf",
            )

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls()
            s.login(SMTP_USERNAME, SMTP_PASSWORD)
            s.send_message(msg)
        return True
    except Exception:
        return False


def send_plain_email(to_email: str, subject: str, body: str) -> bool:
    """A minimal, general-purpose send for operator-facing alerts (e.g. the
    monitoring digest, sent only to the operator's own inbox, never a
    client's) that don't need send_report_email's report-specific
    formatting or attachment. Same never-raises contract."""
    if not is_configured():
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM
        msg["To"] = to_email
        msg.set_content(body)

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls()
            s.login(SMTP_USERNAME, SMTP_PASSWORD)
            s.send_message(msg)
        return True
    except Exception:
        return False
