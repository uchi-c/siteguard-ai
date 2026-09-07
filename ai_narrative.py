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
from scanner import ScanResult

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
        lines.append(f"- [{f.severity.upper()}] {f.title}: {f.detail}")
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
