"""
Contact info and the paid-audit call-to-action shown on every exported
report (the PDF download and the emailed PDF -- both render
report_print.html). Read from env vars at call time rather than
hardcoded, because the contact details are the operator's own business
information (email, booking/profile link), not something to bake into the
repo -- and an unset value just leaves that line off the report instead of
printing a blank label.
"""
from __future__ import annotations

import os

# Deliberately describes only what a report can honestly promise about a
# paid tier without inventing specifics (pricing, turnaround, deliverables)
# the operator hasn't stated -- override with BRAND_AUDIT_CTA to say
# exactly what the paid audit actually includes.
DEFAULT_AUDIT_CTA = (
    "This report comes from an automated, passive scan. A full security audit "
    "adds a human review of each finding above, a prioritized remediation plan, "
    "and hands-on help fixing what matters most."
)


def get_branding() -> dict:
    return {
        "contact_email": os.environ.get("BRAND_CONTACT_EMAIL", "").strip(),
        "contact_url": os.environ.get("BRAND_CONTACT_URL", "").strip(),
        "audit_cta": os.environ.get("BRAND_AUDIT_CTA", "").strip() or DEFAULT_AUDIT_CTA,
    }
