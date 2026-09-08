"""
Active vulnerability DETECTION probes -- reflected XSS, error-based SQLi,
SSTI, path traversal, OS command injection, open redirect, and a tiny
fixed-list weak-credential check. This is NOT an exploitation framework:
nothing here extracts, modifies, or exfiltrates data beyond the minimum
needed to confirm each vulnerability class exists (e.g. traversal reads
/etc/passwd or win.ini -- standard, non-sensitive confirmation files, never
/etc/shadow or anything requiring elevated access; command injection only
ever runs a harmless `echo <marker>`, never a destructive or data-reading
command). Same detection-only philosophy a professional DAST tool's scan
phase uses.

This is fundamentally different from scanner.py's passive checks and is
gated hard, at multiple independent layers (see app.py):
  - Only reachable via an authenticated /admin session.
  - Requires the operator to type the exact target hostname to confirm
    authorization for THAT SPECIFIC target before each run.
  - Refuses to run at all unless ACTIVE_TESTING_ENABLED=1 is set on the
    server -- a deployment-level kill switch, off by default.
  - Every run is logged (target, hostname, timestamp) to an audit table.

Sending unsolicited attack traffic -- even non-destructive detection
probes -- to a system you don't have explicit authorization to test is a
criminal offense in most jurisdictions (e.g. the US Computer Fraud and
Abuse Act) regardless of intent. This module exists for authorized
engagements only: pentests you were hired for, or your own infrastructure.
"""
from __future__ import annotations

import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import requests

from scanner import TIMEOUT, USER_AGENT, UnsafeTargetError, _normalize_url, _resolve_and_validate_host

MAX_INJECTION_POINTS = 15

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",   # MySQL
    "warning: mysql",
    "unclosed quotation mark after the character string",  # MSSQL
    "microsoft ole db provider for sql server",
    "postgresql query failed",
    "pg_query()",
    "sqlite3.operationalerror",
    "sqlite error",
    "ora-01756",                               # Oracle
    "quoted string not properly terminated",
]

# (payload, expected-evaluated-result) -- classic universal SSTI probes.
# Math, not a real command: if a template engine evaluates it, "49" shows
# up in the response where it otherwise wouldn't.
SSTI_PROBES = [
    ("{{7*7}}", "49"),   # Jinja2/Twig-style
    ("${7*7}", "49"),    # Freemarker/EL-style
]

TRAVERSAL_PROBES = [
    "../../../../../../../../etc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
]

OPEN_REDIRECT_PARAM_HINTS = ("redirect", "url", "next", "return", "continue", "dest", "target")
# .invalid is IANA-reserved to never resolve (RFC 2606) -- confirms the
# redirect target without ever actually contacting anything.
OPEN_REDIRECT_TEST_HOST = "siteguard-redirect-probe.invalid"

# "echo <marker>" only -- confirms command execution without touching the
# filesystem, network, or anything else on the target.
CMDI_PAYLOAD_TEMPLATES = ["; echo {marker}", "| echo {marker}", "`echo {marker}`", "$(echo {marker})"]

# Deliberately tiny -- a spot-check for egregiously weak defaults, not a
# wordlist attack. The cap is enforced in code, not just by list length.
WEAK_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
]
MAX_CREDENTIAL_ATTEMPTS = 3
LOGIN_PATHS = ["/admin", "/login", "/wp-login.php", "/admin/login", "/administrator"]


@dataclass
class ActiveFinding:
    check: str          # "reflected-xss" | "sqli-error-based" | "ssti" |
                         # "path-traversal" | "command-injection" |
                         # "open-redirect" | "weak-credentials"
    severity: str
    title: str
    detail: str
    location: str


@dataclass
class ActiveScanResult:
    target: str
    scanned_at: str
    findings: list = field(default_factory=list)
    injection_points_tested: int = 0
    error: str | None = None


def _with_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))


STATIC_ASSET_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot", ".ico", ".map",
)


def _discover_injection_points(base_url: str) -> list[dict]:
    """Passive: parse forms and same-origin links found on the homepage,
    plus the base URL's own query string. No requests beyond the one GET
    already needed to read the page.

    Forms are collected FIRST. Ordering matters here because the total is
    capped at MAX_INJECTION_POINTS: a real page can easily have 30+
    cache-busting `?ver=1.2.3` links on its own stylesheets/scripts (very
    common on WordPress) alongside a single real search form. Collecting
    links before forms let those cache-busters fill every slot before the
    form's actual input parameter was ever considered -- the scan would
    "run" and find nothing, on a page that had an obvious, classic
    reflected-XSS test target (a search box) sitting right there. Static-
    asset links are filtered out entirely for the same reason: a `?ver=`
    query string on a .css/.js/image/font request is essentially always a
    cache-buster, never a real input, so testing it just burns probe
    budget on a link that was never going to reflect anything.
    """
    points = []
    seen = set()

    def add(url, param):
        key = (url, param)
        if key not in seen:
            seen.add(key)
            points.append({"url": url, "param": param})

    try:
        r = requests.get(base_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    except requests.RequestException:
        r = None

    if r is not None:
        for form_match in re.finditer(r"<form\b[^>]*>(.*?)</form>", r.text, re.I | re.S):
            form_html = form_match.group(0)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.I)
            if method_match and method_match.group(1).lower() != "get":
                continue  # skip POST forms -- don't submit unknown data to them
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.I)
            action = urljoin(base_url, action_match.group(1)) if action_match else base_url
            for input_match in re.finditer(r'<input\b[^>]*name=["\']([^"\']+)["\']', form_html, re.I):
                add(action, input_match.group(1))

    for param in parse_qs(urlparse(base_url).query):
        add(base_url, param)

    if r is not None:
        origin = urlparse(base_url).netloc
        for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+)["\']', r.text, re.I):
            link = urljoin(base_url, m.group(1))
            parsed = urlparse(link)
            if parsed.netloc != origin:
                continue
            if parsed.path.lower().endswith(STATIC_ASSET_EXTENSIONS):
                continue
            for param in parse_qs(parsed.query):
                add(link, param)

    return points[:MAX_INJECTION_POINTS]


def _test_reflected_xss(point: dict) -> ActiveFinding | None:
    marker = f"sgaiprobe{secrets.token_hex(4)}"
    probe_value = f"<{marker}>"
    test_url = _with_param(point["url"], point["param"], probe_value)
    try:
        r = requests.get(test_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    except requests.RequestException:
        return None
    if probe_value in r.text:
        return ActiveFinding(
            check="reflected-xss", severity="high",
            title=f"Reflected, unescaped input in parameter '{point['param']}'",
            detail=(f"A harmless test marker injected into '{point['param']}' was "
                     f"reflected back in the response without HTML-encoding. A real "
                     f"attacker could use this to inject scripts that run in victims' "
                     f"browsers (session theft, defacement, credential phishing)."),
            location=test_url,
        )
    return None


def _test_sqli(point: dict) -> ActiveFinding | None:
    baseline_url = _with_param(point["url"], point["param"], "sgaiprobe1")
    probe_url = _with_param(point["url"], point["param"], "sgaiprobe1'")
    try:
        baseline = requests.get(baseline_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        time.sleep(0.1)
        probe = requests.get(probe_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    except requests.RequestException:
        return None
    probe_lower, baseline_lower = probe.text.lower(), baseline.text.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig in probe_lower and sig not in baseline_lower:
            return ActiveFinding(
                check="sqli-error-based", severity="critical",
                title=f"Possible SQL injection in parameter '{point['param']}'",
                detail=(f"Injecting a single quote into '{point['param']}' produced a "
                         f"database error ('{sig}') absent with a normal value, "
                         f"suggesting unsanitized input reaches a SQL query directly. "
                         f"This can allow full database compromise."),
                location=probe_url,
            )
    return None


def _test_ssti(point: dict) -> ActiveFinding | None:
    for payload, expected in SSTI_PROBES:
        baseline_url = _with_param(point["url"], point["param"], "sgaibaseline1")
        probe_url = _with_param(point["url"], point["param"], payload)
        try:
            baseline = requests.get(baseline_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
            time.sleep(0.1)
            probe = requests.get(probe_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if expected in probe.text and expected not in baseline.text:
            return ActiveFinding(
                check="ssti", severity="critical",
                title=f"Possible server-side template injection in parameter '{point['param']}'",
                detail=(f"Injecting '{payload}' into '{point['param']}' caused the "
                         f"evaluated result ('{expected}') to appear in the response -- "
                         f"absent with a plain value -- suggesting the input is passed "
                         f"into a template engine and evaluated. Often escalates to full "
                         f"remote code execution."),
                location=probe_url,
            )
    return None


def _test_traversal(point: dict) -> ActiveFinding | None:
    for payload in TRAVERSAL_PROBES:
        test_url = _with_param(point["url"], point["param"], payload)
        try:
            r = requests.get(test_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        text = r.text
        if ("root:" in text and ":0:0:" in text) or "[extensions]" in text:
            return ActiveFinding(
                check="path-traversal", severity="critical",
                title=f"Possible path traversal in parameter '{point['param']}'",
                detail=(f"Injecting '{payload}' into '{point['param']}' returned what "
                         f"looks like the contents of a system file, suggesting the "
                         f"parameter is used to read files from disk without validating "
                         f"the path. Can expose configuration, source code, or "
                         f"credentials stored elsewhere on the server."),
                location=test_url,
            )
    return None


def _test_command_injection(point: dict) -> ActiveFinding | None:
    marker = f"sgaicmdi{secrets.token_hex(4)}"
    for template in CMDI_PAYLOAD_TEMPLATES:
        payload = template.format(marker=marker)
        test_url = _with_param(point["url"], point["param"], payload)
        try:
            r = requests.get(test_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        # Any endpoint that reflects its input verbatim (a "you searched
        # for X" message, a redirect's fallback link) will contain the
        # marker too, since the marker is embedded in the raw payload --
        # that's not evidence of execution. Only count it when the marker
        # appears WITHOUT the full raw payload also being present, which
        # is what "a shell actually ran echo and returned just its
        # output" looks like, as opposed to plain reflection.
        if marker in r.text and payload not in r.text:
            return ActiveFinding(
                check="command-injection", severity="critical",
                title=f"Possible OS command injection in parameter '{point['param']}'",
                detail=(f"Injecting a shell metacharacter sequence into '{point['param']}' "
                         f"caused an injected 'echo' command's output to appear in the "
                         f"response, suggesting the input reaches a shell command "
                         f"unsanitized. Typically a full remote-code-execution vulnerability."),
                location=test_url,
            )
        time.sleep(0.1)
    return None


def _test_open_redirect(point: dict) -> ActiveFinding | None:
    if not any(hint in point["param"].lower() for hint in OPEN_REDIRECT_PARAM_HINTS):
        return None  # only worth testing params that look like they control a redirect
    probe_target = f"https://{OPEN_REDIRECT_TEST_HOST}/"
    test_url = _with_param(point["url"], point["param"], probe_target)
    try:
        r = requests.get(test_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False)
    except requests.RequestException:
        return None
    location = r.headers.get("Location", "")
    if r.status_code in (301, 302, 303, 307, 308) and OPEN_REDIRECT_TEST_HOST in location:
        return ActiveFinding(
            check="open-redirect", severity="medium",
            title=f"Possible open redirect via parameter '{point['param']}'",
            detail=(f"Setting '{point['param']}' to an external URL made the server "
                     f"redirect there directly, without validating it's an internal or "
                     f"allow-listed destination. Commonly abused for phishing -- a link "
                     f"on your real domain that silently sends visitors elsewhere."),
            location=test_url,
        )
    return None


def _guess_field(form_html: str, candidates: list[str]) -> str | None:
    names = re.findall(r'<input\b[^>]*name=["\']([^"\']+)["\']', form_html, re.I)
    for name in names:
        if any(c in name.lower() for c in candidates):
            return name
    return None


def _test_weak_credentials(base_url: str) -> list[ActiveFinding]:
    findings = []
    attempts = 0
    for path in LOGIN_PATHS:
        if attempts >= MAX_CREDENTIAL_ATTEMPTS:
            break
        login_url = base_url + path
        try:
            r = requests.get(login_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        if r.status_code != 200 or "password" not in r.text.lower():
            continue

        form_html = r.text
        user_field = _guess_field(form_html, ["user", "email", "login"])
        pass_field = _guess_field(form_html, ["pass"])
        if not user_field or not pass_field:
            continue
        action_match = re.search(r'<form\b[^>]*action=["\']([^"\']*)["\']', form_html, re.I)
        action = urljoin(login_url, action_match.group(1)) if action_match else login_url

        for username, password in WEAK_CREDENTIALS:
            if attempts >= MAX_CREDENTIAL_ATTEMPTS:
                break
            attempts += 1
            try:
                resp = requests.post(action, data={user_field: username, pass_field: password},
                                      headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT,
                                      allow_redirects=False)
            except requests.RequestException:
                continue
            # Heuristic (redirect away from a "login"-looking URL) -- not
            # fully reliable, deliberately conservative to avoid false
            # positives. Flagged as needing manual confirmation in the UI.
            location = resp.headers.get("Location", "")
            if resp.status_code in (301, 302, 303) and "login" not in location.lower():
                findings.append(ActiveFinding(
                    check="weak-credentials", severity="critical",
                    title=f"Default credentials may be accepted at {path}",
                    detail=(f"The login form at {path} appears to accept the well-known "
                             f"default credential '{username}'/'{password}' (heuristic: "
                             f"redirected away from the login page). Confirm manually -- "
                             f"this detection method has a real false-positive rate."),
                    location=login_url,
                ))
                break  # confirmed weak creds here -- no need to keep probing this form
    return findings


def run_active_scan(target: str) -> ActiveScanResult:
    url = _normalize_url(target)
    hostname = urlparse(url).hostname or target
    result = ActiveScanResult(target=url, scanned_at=datetime.now(timezone.utc).isoformat())

    try:
        _resolve_and_validate_host(hostname)  # same SSRF guard as the passive scanner
    except UnsafeTargetError as e:
        result.error = str(e)
        return result

    points = _discover_injection_points(url)
    result.injection_points_tested = len(points)

    checks = [
        _test_reflected_xss,
        _test_sqli,
        _test_ssti,
        _test_traversal,
        _test_command_injection,
        _test_open_redirect,
    ]
    for point in points:
        for check in checks:
            finding = check(point)
            if finding:
                result.findings.append(finding)
            time.sleep(0.1)

    result.findings.extend(_test_weak_credentials(url))

    return result
