"""
Passive security scanner.

Everything here is PASSIVE / non-intrusive: plain HTTP(S) GET requests to
public URLs and a TLS handshake, exactly what a normal browser visit does.
No port scanning, no auth bypass attempts, no exploitation. This keeps the
tool legal to run against a prospect's public marketing site without
needing prior written authorization (the same category of check that
securityheaders.com or Mozilla Observatory run publicly) -- but it should
still only be pointed at sites you own or a client has asked you to check.
"""
from __future__ import annotations

import hashlib
import ipaddress
import os
import re
import secrets
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

try:
    import dns.resolver
    _HAVE_DNS = True
except ImportError:  # pragma: no cover
    _HAVE_DNS = False

USER_AGENT = "SiteGuardAI-Scanner/1.0 (+passive security scan; contact via report)"
TIMEOUT = 8
MAX_REDIRECTS = 5

# Visitors control the scan target, so it must never be usable to make this
# server issue requests to internal/private infrastructure (cloud metadata
# endpoints, localhost, RFC1918 ranges, etc). Set to "1" only for local
# demoing against test_target.py, which serves on localhost.
ALLOW_PRIVATE_TARGETS = os.environ.get("SITEGUARD_ALLOW_PRIVATE_TARGETS") == "1"

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}

SENSITIVE_PATHS = [
    "/.env",
    "/.git/config",
    "/.git/HEAD",
    "/wp-config.php.bak",
    "/wp-config.php~",
    "/.DS_Store",
    "/config.php.bak",
    "/backup.zip",
    "/.aws/credentials",
    "/server-status",
    "/phpinfo.php",
    "/.htpasswd",
    "/id_rsa",
    "/debug",
]

OUTDATED_JS_SIGNATURES = [
    (re.compile(r"jquery[-.](1\.[0-9]|2\.[01])\.", re.I), "jQuery < 2.2 (multiple known XSS CVEs)"),
    (re.compile(r"bootstrap[-.](2\.|3\.[0-3])", re.I), "Bootstrap < 3.4 (known XSS issues)"),
]


@dataclass
class Finding:
    id: str
    title: str
    severity: str  # critical | high | medium | low | info
    detail: str
    recommendation: str


@dataclass
class ScanResult:
    target: str
    scanned_at: str
    findings: list = field(default_factory=list)
    reachable: bool = True
    error: str | None = None

    def add(self, id, title, severity, detail, recommendation):
        self.findings.append(Finding(id, title, severity, detail, recommendation))

    @property
    def score(self) -> int:
        """0-100, 100 = no issues found."""
        penalty = sum(SEVERITY_WEIGHT[f.severity] for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    def counts(self) -> dict:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self.findings:
            out[f.severity] += 1
        return out


def _normalize_url(target: str) -> str:
    target = target.strip()
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    return target.rstrip("/")


class UnsafeTargetError(Exception):
    """Raised when a scan target resolves to a private/internal address."""


def _resolve_and_validate_host(hostname: str) -> None:
    if ALLOW_PRIVATE_TARGETS:
        return
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise UnsafeTargetError(f"Could not resolve '{hostname}': {e}")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise UnsafeTargetError(
                f"Refusing to scan '{hostname}': resolves to a private/internal "
                f"address ({ip}). Only public websites can be scanned."
            )


def _check_headers(resp: requests.Response, result: ScanResult):
    headers = {k.lower(): v for k, v in resp.headers.items()}

    checks = [
        ("strict-transport-security", "hsts-missing", "Missing HSTS header", "high",
         "Site does not force HTTPS via Strict-Transport-Security, so users can be "
         "downgraded to plain HTTP by a network attacker.",
         "Add `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`."),
        ("content-security-policy", "csp-missing", "Missing Content-Security-Policy", "medium",
         "No CSP header found. This removes a key defense against injected/XSS scripts.",
         "Define a Content-Security-Policy restricting script/style/frame sources."),
        ("x-frame-options", "xfo-missing", "Missing X-Frame-Options", "medium",
         "Page can likely be embedded in an iframe on another site, enabling clickjacking.",
         "Add `X-Frame-Options: DENY` or a `frame-ancestors` CSP directive."),
        ("x-content-type-options", "xcto-missing", "Missing X-Content-Type-Options", "low",
         "Browsers may MIME-sniff responses, which can enable certain injection attacks.",
         "Add `X-Content-Type-Options: nosniff`."),
        ("referrer-policy", "referrer-missing", "Missing Referrer-Policy", "low",
         "Full URLs (which can include tokens/IDs) may leak to third parties via the Referer header.",
         "Add `Referrer-Policy: strict-origin-when-cross-origin` or stricter."),
        ("permissions-policy", "permissions-missing", "Missing Permissions-Policy", "info",
         "No policy restricting browser features (camera, mic, geolocation, etc.) for embedded content.",
         "Add a `Permissions-Policy` header scoping powerful browser APIs."),
    ]
    for header_name, fid, title, sev, detail, rec in checks:
        if header_name not in headers:
            result.add(fid, title, sev, detail, rec)

    server = headers.get("server")
    if server and re.search(r"\d+\.\d+", server):
        result.add("server-banner", "Server version disclosed", "low",
                    f"Server header reveals version info: '{server}'. This helps attackers "
                    f"match known CVEs to your exact software version.",
                    "Suppress or generalize the Server header (e.g. via reverse proxy config).")

    xpb = headers.get("x-powered-by")
    if xpb:
        result.add("xpoweredby", "X-Powered-By header disclosed", "low",
                    f"'{xpb}' reveals backend technology/version.",
                    "Remove the X-Powered-By header in server/framework config.")

    set_cookie = resp.raw.headers.get_all("Set-Cookie") if hasattr(resp.raw.headers, "get_all") else resp.headers.get("Set-Cookie")
    cookies = set_cookie if isinstance(set_cookie, list) else ([set_cookie] if set_cookie else [])
    for c in cookies:
        cl = c.lower()
        missing = [flag for flag in ("secure", "httponly") if flag not in cl]
        if missing:
            name = c.split("=")[0]
            result.add(f"cookie-{name}", f"Cookie '{name}' missing {', '.join(missing)}", "medium",
                       f"Cookie set without {', '.join(m.title() for m in missing)} flag(s), "
                       f"increasing session-hijacking / XSS-theft risk.",
                       "Set Secure and HttpOnly (and SameSite=Lax/Strict) on all session cookies.")


def _check_tls(hostname: str, result: ScanResult):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()

                if proto in ("TLSv1", "TLSv1.1"):
                    result.add("tls-outdated", f"Outdated TLS protocol in use ({proto})", "critical",
                               f"Server negotiated {proto}, which is deprecated and vulnerable to "
                               f"known downgrade/decryption attacks.",
                               "Disable TLS 1.0/1.1; require TLS 1.2 minimum (prefer TLS 1.3).")

                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    if days_left < 0:
                        result.add("tls-expired", "TLS certificate has expired", "critical",
                                   f"Certificate expired {abs(days_left)} day(s) ago.",
                                   "Renew the TLS certificate immediately.")
                    elif days_left < 14:
                        result.add("tls-expiring", "TLS certificate expiring soon", "high",
                                   f"Certificate expires in {days_left} day(s).",
                                   "Renew now and set up auto-renewal (e.g. Let's Encrypt certbot).")
    except ssl.SSLCertVerificationError as e:
        result.add("tls-invalid", "TLS certificate is invalid/untrusted", "critical",
                   f"Certificate verification failed: {e}", "Install a valid certificate from a trusted CA.")
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        result.add("tls-unreachable", "Could not establish TLS connection on port 443", "info",
                   f"{e}", "Confirm HTTPS is enabled and reachable on port 443.")


def _check_dns_email_security(hostname: str, result: ScanResult):
    if not _HAVE_DNS:
        return
    try:
        ipaddress.ip_address(hostname)
        return  # scanning a bare IP -- no domain to check SPF/DMARC against
    except ValueError:
        pass
    root = ".".join(hostname.split(".")[-2:]) if hostname.count(".") >= 1 else hostname
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT

    def txt_records(name):
        try:
            return [b"".join(r.strings).decode(errors="ignore") for r in resolver.resolve(name, "TXT")]
        except Exception:
            return []

    spf = [t for t in txt_records(root) if t.lower().startswith("v=spf1")]
    if not spf:
        result.add("spf-missing", "No SPF record found", "medium",
                   f"'{root}' has no SPF TXT record, making it easier to spoof emails "
                   f"appearing to come from this domain.",
                   "Publish an SPF TXT record listing authorized mail senders.")

    dmarc = txt_records(f"_dmarc.{root}")
    if not dmarc:
        result.add("dmarc-missing", "No DMARC record found", "medium",
                   f"'{root}' has no DMARC policy, so spoofed emails aren't rejected/quarantined "
                   f"even if SPF/DKIM exist.",
                   "Publish a DMARC TXT record at _dmarc.<domain>, starting with p=quarantine.")


def _check_sensitive_paths(base_url: str, result: ScanResult):
    # Some hosts (e.g. SPA platforms like Vercel with a catch-all rewrite)
    # return 200 with the same index page for *any* path, including
    # nonexistent ones. Probe a random path first to learn what a "not
    # found" response looks like here, so we only flag a sensitive path
    # when its response actually differs from that baseline.
    baseline_status = None
    baseline_hash = None
    baseline_etag = None
    try:
        probe_path = f"/__siteguard_baseline_{secrets.token_hex(8)}"
        br = requests.get(base_url + probe_path, headers={"User-Agent": USER_AGENT},
                           timeout=TIMEOUT, allow_redirects=False)
        baseline_status = br.status_code
        baseline_hash = hashlib.sha256(br.content).hexdigest()
        baseline_etag = br.headers.get("ETag")
    except requests.RequestException:
        pass  # fall back to flagging on bare 200, as before
    time.sleep(0.05)

    for path in SENSITIVE_PATHS:
        try:
            r = requests.get(base_url + path, headers={"User-Agent": USER_AGENT},
                              timeout=TIMEOUT, allow_redirects=False)
            if r.status_code != 200 or len(r.content) == 0:
                continue
            body_hash = hashlib.sha256(r.content).hexdigest()
            etag = r.headers.get("ETag")
            matches_baseline = (
                baseline_status is not None
                and r.status_code == baseline_status
                and body_hash == baseline_hash
                and etag == baseline_etag
            )
            if not matches_baseline:
                result.add(f"exposed-{path}", f"Potentially exposed file: {path}", "high",
                           f"GET {path} returned HTTP 200. If this is the real file (not a custom "
                           f"404 page), sensitive data may be publicly accessible.",
                           f"Block access to {path} at the web server/proxy level and confirm it "
                           f"isn't deployed to the public webroot at all.")
        except requests.RequestException:
            continue
        time.sleep(0.05)  # be polite


def _check_mixed_content_and_js(base_url: str, html: str, result: ScanResult):
    if base_url.startswith("https://"):
        http_srcs = re.findall(r'(?:src|href)=["\']http://[^"\']+', html, re.I)
        if http_srcs:
            result.add("mixed-content", "Mixed content detected", "medium",
                       f"{len(http_srcs)} resource(s) loaded over plain HTTP on an HTTPS page "
                       f"(e.g. {http_srcs[0]}).",
                       "Serve all page resources (scripts, images, styles) over HTTPS.")

    for pattern, note in OUTDATED_JS_SIGNATURES:
        if pattern.search(html):
            result.add(f"outdated-js-{note[:12]}", "Outdated JS library detected", "medium",
                       note, "Upgrade the flagged library to its latest stable release.")


def run_scan(target: str) -> ScanResult:
    url = _normalize_url(target)
    hostname = urlparse(url).hostname or target
    result = ScanResult(target=url, scanned_at=datetime.now(timezone.utc).isoformat())

    try:
        _resolve_and_validate_host(hostname)
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False)
        hops = 0
        while resp.is_redirect and hops < MAX_REDIRECTS:
            location = resp.headers.get("Location")
            if not location:
                break
            url = urljoin(resp.url, location)
            hostname = urlparse(url).hostname
            if not hostname:
                break
            _resolve_and_validate_host(hostname)
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, allow_redirects=False)
            hops += 1
    except (requests.RequestException, UnsafeTargetError) as e:
        result.reachable = False
        result.error = str(e)
        return result

    _check_headers(resp, result)
    if url.startswith("https://"):
        _check_tls(hostname, result)
    else:
        result.add("no-https", "Site does not use HTTPS", "critical",
                   "The site was reached over plain HTTP.",
                   "Obtain a TLS certificate (e.g. free via Let's Encrypt) and redirect all HTTP to HTTPS.")

    _check_dns_email_security(hostname, result)
    _check_sensitive_paths(url, result)
    _check_mixed_content_and_js(url, resp.text, result)

    return result
