"""
Active vulnerability DETECTION probes -- reflected XSS, error-based SQLi,
and a tiny fixed-list weak-credential check. This is NOT an exploitation
framework: nothing here extracts, modifies, or exfiltrates data. Payloads
are harmless markers/probes designed only to confirm a vulnerability class
exists, the same way a professional DAST tool's detection phase works.

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
    check: str          # "reflected-xss" | "sqli-error-based" | "weak-credentials"
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

    for point in points:
        xss = _test_reflected_xss(point)
        if xss:
            result.findings.append(xss)
        time.sleep(0.1)
        sqli = _test_sqli(point)
        if sqli:
            result.findings.append(sqli)
        time.sleep(0.1)

    result.findings.extend(_test_weak_credentials(url))

    return result
