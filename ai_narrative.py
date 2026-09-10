"""
Turns raw scan findings into a client-facing narrative: an executive summary,
plain-English risk explanation, and a prioritized remediation plan.

This is the actual "AI" in the product. If ANTHROPIC_API_KEY is set, it calls
Claude to write the narrative. If not, it falls back to a fully-functional
rule-based narrative generator -- the demo works out of the box either way,
but the AI path is what makes each report feel personally written for that
prospect instead of a generic scanner printout.
"""
from __future__ import annotations

import os
from scanner import Finding, ScanResult

MODEL = os.environ.get("SITEGUARD_MODEL", "claude-sonnet-4-5")

SYSTEM_PROMPT = """You are a senior application security consultant writing a short,
client-facing findings summary for a small business owner who is NOT technical.
Given a list of security findings for their website, write:

1. A 2-3 sentence executive summary in plain English (no jargon), stating the
   overall risk level and the single biggest concern.
2. A prioritized action list (most urgent first) of at most 5 items, each one
   sentence, written for a business owner deciding what to fix first -- not a
   developer. Reference dollar/reputation impact where relevant (e.g. "a
   spoofed email risk that could be used to scam your customers").

Do not restate every finding verbatim. Be direct and specific to what's
actually wrong. Keep the whole response under 180 words. Do not use markdown
headers, just two short paragraphs separated by a blank line: summary, then
the numbered action list."""


def _findings_as_text(result: ScanResult) -> str:
    lines = []
    for f in result.findings:
        owasp_note = f" [{f.owasp}]" if f.owasp else ""
        lines.append(f"- [{f.severity.upper()}]{owasp_note} {f.title}: {f.detail}")
    return "\n".join(lines) if lines else "No issues found."


def _rule_based_narrative(result: ScanResult) -> str:
    counts = result.counts()
    top = sorted(result.findings, key=lambda f: -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[f.severity])[:5]

    if not result.findings:
        summary = (f"{result.target} passed every check in this scan -- no missing security "
                   f"headers, valid TLS, no exposed files, and email spoofing protections are in "
                   f"place. This is an unusually clean result; most sites we scan have at least "
                   f"3-5 findings.")
    else:
        headline = top[0].title.lower() if top else "several configuration gaps"
        summary = (f"This site scored {result.grade} ({result.score}/100) with "
                   f"{counts['critical']} critical, {counts['high']} high, and {counts['medium']} "
                   f"medium-severity issue(s). The most urgent problem is {headline}, which "
                   f"{'could let attackers directly compromise the site or its visitors' if counts['critical'] else 'meaningfully raises risk if left unaddressed'}.")

    actions = []
    for i, f in enumerate(top, 1):
        actions.append(f"{i}. {f.recommendation}")
    action_text = "\n".join(actions) if actions else "No action needed right now -- recheck after any major site changes."

    return f"{summary}\n\n{action_text}"


SYSTEM_PROMPT_OUTREACH = """You are a security consultant who just ran a free, passive
security scan on a business's public website (headers, TLS, DNS records -- nothing
invasive) and wants to send them a short, warm cold-outreach message about it.

Write ONE short paragraph (50-80 words) they can copy-paste into an email or LinkedIn
message. Reference the single most important finding in plain English (no jargon, no
severity labels). Mention it was found during a quick free security check. End with a
low-pressure offer to share the full breakdown -- not a hard sell. No subject line, no
greeting placeholder, no markdown, no signature. Just the message body as one paragraph."""


def _rule_based_outreach(target: str, top_title: str, top_detail: str, has_findings: bool) -> str:
    if not has_findings:
        return (f"Hey -- I ran a quick free security check on {target} out of curiosity and "
                 f"it came back clean, which is rare. Nice work on that. Happy to send over the "
                 f"full report if you'd like it for your records.")
    return (f"Hey -- I ran a quick free security check on {target} and noticed {top_title.lower()}. "
            f"Nothing that needs panic, but worth a look. Happy to send over the full breakdown "
            f"and a quick fix plan if that'd be useful.")


def generate_outreach_message(target: str, top_title: str, top_detail: str, has_findings: bool) -> tuple[str, str]:
    """Returns (message_text, source) where source is 'ai' or 'rule-based'."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _rule_based_outreach(target, top_title, top_detail, has_findings), "rule-based"

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        user_content = (
            f"Site: {target}\n"
            + (f"Top finding: {top_title} -- {top_detail}" if has_findings else "No issues found.")
        )
        message = client.messages.create(
            model=MODEL,
            max_tokens=200,
            system=SYSTEM_PROMPT_OUTREACH,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
        if text:
            return text, "ai"
        return _rule_based_outreach(target, top_title, top_detail, has_findings), "rule-based"
    except Exception:
        return _rule_based_outreach(target, top_title, top_detail, has_findings), "rule-based"


SYSTEM_PROMPT_FOLLOWUP = """You are a security consultant following up on a free security
report you sent a prospect a little while ago -- they gave their email for it but haven't
replied. Write ONE short, low-pressure follow-up message (40-70 words) they can copy-paste
into an email or LinkedIn message.

Reference the single most important finding in plain English (no jargon, no severity
labels) as the reason you're checking back in. Acknowledge the time gap naturally without
sounding passive-aggressive about the lack of reply. End with a low-key nudge (offering to
answer questions, or a quick call) -- not a hard sell, not a discount, not urgency/scarcity
language. No subject line, no greeting placeholder, no markdown, no signature. Just the
message body as one paragraph."""


def _rule_based_followup(target: str, top_title: str, days_since: int) -> str:
    gap = "a few days ago" if days_since <= 5 else ("a couple weeks ago" if days_since <= 16 else "a while back")
    if not top_title:
        return (f"Hey -- just following up on the security report for {target} I sent over "
                 f"{gap}. No rush at all, but happy to walk through it or answer any questions "
                 f"whenever's useful.")
    return (f"Hey -- following up on the security report for {target} from {gap}, specifically "
             f"{top_title.lower()}. No pressure, just wanted to make sure it didn't get buried -- "
             f"happy to walk through the fix or hop on a quick call if useful.")


def generate_followup_message(target: str, top_title: str, top_detail: str, days_since: int) -> tuple[str, str]:
    """Returns (message_text, source) where source is 'ai' or 'rule-based'. Same
    shape as generate_outreach_message -- this is the same idea (a short,
    low-pressure nudge), just for a lead who already gave their email
    instead of a cold-outreach opener."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _rule_based_followup(target, top_title, days_since), "rule-based"

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        user_content = (
            f"Site: {target}\n"
            f"Days since the report was sent: {days_since}\n"
            + (f"Top finding: {top_title} -- {top_detail}" if top_title else "No issues found.")
        )
        message = client.messages.create(
            model=MODEL,
            max_tokens=200,
            system=SYSTEM_PROMPT_FOLLOWUP,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
        if text:
            return text, "ai"
        return _rule_based_followup(target, top_title, days_since), "rule-based"
    except Exception:
        return _rule_based_followup(target, top_title, days_since), "rule-based"


def generate_narrative(result: ScanResult) -> tuple[str, str]:
    """Returns (narrative_text, source) where source is 'ai' or 'rule-based'."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _rule_based_narrative(result), "rule-based"

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        message = client.messages.create(
            model=MODEL,
            max_tokens=400,
            system=SYSTEM_PROMPT,
            messages=[{
                "role": "user",
                "content": (
                    f"Site: {result.target}\n"
                    f"Score: {result.score}/100 (grade {result.grade})\n"
                    f"Findings:\n{_findings_as_text(result)}"
                ),
            }],
        )
        text = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
        if text:
            return text, "ai"
        return _rule_based_narrative(result), "rule-based"
    except Exception:
        # Never let an API hiccup break the report -- fall back silently.
        return _rule_based_narrative(result), "rule-based"


SYSTEM_PROMPT_MONITORING = """You monitor a client's website security over time on their
behalf and just noticed a change since the last check. Given a list of newly-appeared
findings and a list of findings that look resolved since the last scan, write ONE short
paragraph (40-70 words) for whoever manages this client's monitoring, in plain English (no
jargon, no severity labels). Lead with what's most urgent if anything is new; mention
what got fixed if that's the only change. No markdown, no greeting, no signature -- just
the paragraph."""


def _rule_based_monitoring_digest(target: str, new_findings: list[Finding], resolved_findings: list[Finding]) -> str:
    parts = []
    if new_findings:
        top = new_findings[0]
        extra = f" and {len(new_findings) - 1} more" if len(new_findings) > 1 else ""
        parts.append(f"{len(new_findings)} new finding(s) on {target} since the last check, "
                      f"including {top.title.lower()}{extra}.")
    if resolved_findings:
        parts.append(f"{len(resolved_findings)} previous finding(s) on {target} appear resolved.")
    return " ".join(parts) if parts else f"No changes on {target} since the last check."


def generate_monitoring_digest(
    target: str, new_findings: list[Finding], resolved_findings: list[Finding],
) -> tuple[str, str]:
    """Returns (digest_text, source) where source is 'ai' or 'rule-based'.
    Only meaningful to call when something actually changed (the caller in
    monitoring.py only calls this when new_findings or resolved_findings is
    non-empty) -- same Claude-call-with-rule-based-fallback shape as the
    rest of this module."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return _rule_based_monitoring_digest(target, new_findings, resolved_findings), "rule-based"

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        new_text = "\n".join(
            f"- [{f.severity.upper()}] {f.title}: {f.detail}" for f in new_findings
        ) or "none"
        resolved_text = "\n".join(f"- {f.title}" for f in resolved_findings) or "none"
        user_content = (
            f"Site: {target}\n"
            f"Newly appeared findings:\n{new_text}\n\n"
            f"Resolved findings:\n{resolved_text}"
        )
        message = client.messages.create(
            model=MODEL,
            max_tokens=200,
            system=SYSTEM_PROMPT_MONITORING,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(block.text for block in message.content if hasattr(block, "text")).strip()
        if text:
            return text, "ai"
        return _rule_based_monitoring_digest(target, new_findings, resolved_findings), "rule-based"
    except Exception:
        return _rule_based_monitoring_digest(target, new_findings, resolved_findings), "rule-based"
