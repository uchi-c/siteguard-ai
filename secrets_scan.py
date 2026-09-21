"""
Finds secrets and credentials leaked in a target's own JavaScript bundles
(and inline in its HTML), and detects publicly-exposed source maps -- the
most common real-world way an AI-built ("vibe-coded") app leaks its
backend credentials, since the whole app -- including anything a prompt
told the AI to "just hardcode for now" -- ships to the browser as plain
JS.

Passive only: this fetches bundles the target ALREADY serves publicly to
any visitor (the same requests a browser makes loading the page), never
anything requiring auth or a live database query. Bundle fetches are
capped in count and size, and restricted to the target's own hostname
(never a third-party CDN), using a local copy of scanner.py's SSRF guard
rather than importing it, so this stays a leaf module with no dependency
on scanner.py -- scanner.py imports this, so the reverse would be a
circular import.

A found secret's actual value is NEVER stored or displayed anywhere --
only a redacted preview (first/last 4 characters) makes it into a
SecretMatch, since shared report links (/report/<id>) are public.

Supabase's anon key and Firebase's web apiKey are deliberately NOT
treated as leaked secrets here -- both are meant to ship to the browser
by design (Supabase relies on Row Level Security, Firebase on security
rules, not on key secrecy). Only a Supabase service_role key (which
bypasses RLS entirely) is flagged. extract_credentials() also returns the
*unredacted* Supabase/Firebase project info for active_scan.py's gated,
authorized-only live check of whether the database is actually readable
without auth -- a materially different, higher-risk operation. It is the
caller's responsibility to never put those raw values into anything
user-visible.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import requests

# Deliberately duplicated from scanner.py (not imported) to keep this a
# leaf module -- scanner.py imports secrets_scan.py, so the reverse
# import would be circular. Keep these two in sync if either changes.
TIMEOUT = 8
USER_AGENT = "SiteGuardAI-Scanner/1.0 (+passive security scan; contact via report)"

# Same override as scanner.ALLOW_PRIVATE_TARGETS, and for the same reason
# (local demoing/testing against a target on localhost) -- this module
# makes its own outbound requests (bundle/sourcemap fetches), so it needs
# the identical escape hatch rather than relying on scanner.py's copy.
ALLOW_PRIVATE_TARGETS = os.environ.get("SITEGUARD_ALLOW_PRIVATE_TARGETS") == "1"

MAX_BUNDLES = 6
MAX_BUNDLE_BYTES = 2_000_000  # 2MB per bundle -- plenty for a minified app bundle

SCRIPT_SRC_RE = re.compile(r'<script[^>]+src=["\']([^"\']+?\.m?js(?:\?[^"\']*)?)["\']', re.I)
SOURCEMAP_COMMENT_RE = re.compile(r"//# sourceMappingURL=(\S+)")

_SECRET_PATTERNS = [
    ("stripe-live-key", "Stripe live secret key", "critical",
     re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    ("aws-access-key", "AWS access key ID", "high",
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", "GitHub access token", "high",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("anthropic-key", "Anthropic API key", "critical",
     re.compile(r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_\-]{20,}\b")),
    ("openai-key", "OpenAI API key", "critical",
     re.compile(r"\bsk-(?!ant-)[A-Za-z0-9\-]{20,}\b")),
    ("private-key-pem", "Private key (PEM block)", "critical",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("db-connection-string", "Database connection string with an embedded password", "critical",
     re.compile(r'\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?)://[^:\s/"\']+:[^@\s/"\']+@[^\s/"\']+')),
]

# A crude but effective filter for obvious placeholders ("sk_live_xxxxx...",
# "your-api-key-here") so a copy-pasted example in a README-turned-comment
# doesn't get reported as a real leaked credential.
_PLACEHOLDER_RE = re.compile(
    r"^(.)\1*$|(x|X|0){6,}|your[-_]?(api)?[-_]?key|example|placeholder|dummy|changeme", re.I,
)

_SUPABASE_URL_RE = re.compile(r"https://([a-z0-9]{15,25})\.supabase\.co")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_FIREBASE_PROJECT_RE = re.compile(r'["\']projectId["\']\s*:\s*["\']([a-z0-9\-]{4,40})["\']')


def _is_safe_public_host(hostname: str) -> bool:
    if not hostname:
        return False
    if ALLOW_PRIVATE_TARGETS:
        return True
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


def _looks_like_placeholder(value: str) -> bool:
    tail = value[-24:] if len(value) > 24 else value
    return bool(_PLACEHOLDER_RE.search(tail))


def _redact(value: str) -> str:
    if len(value) <= 10:
        return "•" * len(value)
    return f"{value[:4]}{'•' * max(4, len(value) - 8)}{value[-4:]}"


@dataclass
class SecretMatch:
    kind: str
    label: str
    severity: str
    redacted: str
    source_url: str


@dataclass
class ExtractedCredentials:
    secrets: list = field(default_factory=list)       # list[SecretMatch] -- redacted, safe to show
    sourcemaps: list = field(default_factory=list)      # list[str] of exposed .map URLs
    bundles_checked: int = 0                            # JS files actually fetched and searched
    supabase_url: str | None = None
    supabase_key: str | None = None                     # UNREDACTED -- for active_scan.py only
    supabase_key_role: str | None = None
    firebase_project_id: str | None = None               # for active_scan.py's RTDB check only


def _same_host_script_urls(base_url: str, html: str) -> list[str]:
    hostname = urlparse(base_url).hostname
    if not hostname:
        return []
    urls = []
    for m in SCRIPT_SRC_RE.finditer(html):
        full = urljoin(base_url, m.group(1))
        if urlparse(full).hostname == hostname and full not in urls:
            urls.append(full)
    return urls[:MAX_BUNDLES]


def _fetch_capped(url: str) -> str | None:
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, stream=True)
        if r.status_code != 200:
            return None
        chunks, total = [], 0
        for chunk in r.iter_content(chunk_size=65536):
            total += len(chunk)
            if total > MAX_BUNDLE_BYTES:
                break
            chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="ignore")
    except requests.RequestException:
        return None


def _check_sourcemap_exposed(bundle_url: str, bundle_text: str) -> str | None:
    m = SOURCEMAP_COMMENT_RE.search(bundle_text[-500:])
    map_url = urljoin(bundle_url, m.group(1)) if m else bundle_url + ".map"
    try:
        r = requests.get(map_url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        if r.status_code == 200 and '"sources"' in r.text[:2000]:
            return map_url
    except requests.RequestException:
        pass
    return None


def _decode_jwt_role(token: str) -> str | None:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        role = data.get("role")
        return role if isinstance(role, str) else None
    except Exception:
        return None


def extract_credentials(base_url: str, html: str) -> ExtractedCredentials:
    """base_url is used to resolve relative script src's and to restrict
    bundle fetches to the target's own hostname -- inline-HTML matches
    (Supabase/Firebase config objects, secrets in a <script> block) are
    found regardless, even if base_url is empty."""
    result = ExtractedCredentials()
    seen_values: set[str] = set()

    haystacks = [("(page HTML)", html)]
    if base_url:
        for script_url in _same_host_script_urls(base_url, html):
            if not _is_safe_public_host(urlparse(script_url).hostname or ""):
                continue
            text = _fetch_capped(script_url)
            if text is None:
                continue
            result.bundles_checked += 1
            haystacks.append((script_url, text))
            map_url = _check_sourcemap_exposed(script_url, text)
            if map_url:
                result.sourcemaps.append(map_url)

    for source_url, text in haystacks:
        for kind, label, severity, pattern in _SECRET_PATTERNS:
            for m in pattern.finditer(text):
                value = m.group(0)
                if value in seen_values or _looks_like_placeholder(value):
                    continue
                seen_values.add(value)
                result.secrets.append(SecretMatch(kind, label, severity, _redact(value), source_url))

        if not result.supabase_url:
            sm = _SUPABASE_URL_RE.search(text)
            if sm:
                result.supabase_url = f"https://{sm.group(1)}.supabase.co"

        for jm in _JWT_RE.finditer(text):
            token = jm.group(0)
            role = _decode_jwt_role(token)
            if role is None:
                continue
            if not result.supabase_key or role == "service_role":
                result.supabase_key = token
                result.supabase_key_role = role
            if role == "service_role" and token not in seen_values:
                seen_values.add(token)
                result.secrets.append(SecretMatch(
                    "supabase-service-role-key",
                    "Supabase service_role key (bypasses all Row Level Security)",
                    "critical", _redact(token), source_url,
                ))

        if not result.firebase_project_id:
            fm = _FIREBASE_PROJECT_RE.search(text)
            if fm:
                result.firebase_project_id = fm.group(1)

    return result


def secret_findings(extracted: ExtractedCredentials) -> list[tuple]:
    """Returns (id, title, severity, detail, recommendation) tuples ready
    for ScanResult.add() -- plain tuples rather than scanner.Finding
    objects, since importing scanner.py here would be circular."""
    out = []
    for i, s in enumerate(extracted.secrets):
        if s.kind == "supabase-service-role-key" and extracted.supabase_url:
            # Naming the project ties the leak to a concrete, already-public
            # fact (its URL is in the same bundle) without needing to prove
            # anything by actually querying it -- see secrets_scan.py's
            # module docstring for why this stays passive-only.
            detail = (
                f"Found in {s.source_url}: {s.redacted}, paired with the Supabase project "
                f"{extracted.supabase_url}. This key bypasses Row Level Security entirely -- "
                f"whoever has it can read, modify, or delete any row in any table in this project, "
                f"regardless of your RLS policies."
            )
        else:
            detail = (
                f"Found in {s.source_url}: {s.redacted}. Anyone visiting the site can read this "
                f"value straight out of the page or its JS bundle -- it stops being secret the "
                f"moment it ships to the browser."
            )
        out.append((
            f"exposed-secret-{s.kind}-{i}",
            f"Exposed secret: {s.label}",
            s.severity,
            detail,
            "Remove the exposed secret from all client-side code and move it to a server-side "
            "environment variable instead. Rotate it immediately -- treat it as already compromised.",
        ))
    for i, map_url in enumerate(extracted.sourcemaps):
        out.append((
            f"exposed-sourcemap-{i}",
            "Public source map exposes original source code",
            "medium",
            f"{map_url} is publicly readable and maps the minified bundle back to close-to-original "
            f"source, including file names and comments -- anyone can reconstruct how the app works.",
            "Disable source map generation for production builds, or block .map files from being "
            "served publicly.",
        ))
    return out
