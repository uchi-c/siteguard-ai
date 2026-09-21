import base64
import json

import requests

import secrets_scan

# Fake credentials are assembled at runtime rather than written as literals:
# GitHub's push protection (correctly) blocks any commit containing a string
# that matches a real key format, even an obviously made-up one.
_SK = "sk" + "_" + "live" + "_"
_ANT = "sk" + "-" + "ant" + "-"
FAKE_STRIPE_TAIL = "4eC39HqLyjWDarjtT1zdp7dcABCDEF"
FAKE_STRIPE_KEY = _SK + FAKE_STRIPE_TAIL
FAKE_ANTHROPIC_KEY = _ANT + "api03-" + "4eC39HqLyjWDarjtT1zdp7dcABCDEFGH"
FAKE_AWS_KEY = "AKIA" + "ABCDEFGHIJKLMNOP"


def _make_jwt(role):
    """A JWT-shaped string with a real, decodable payload -- not a real
    credential (the signature segment is nonsense)."""
    def b64(obj):
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64({'role': role, 'iss': 'supabase'})}.fakesignaturefakesignaturefakesig"


# --- Small pure helpers -------------------------------------------------------

def test_redact_short_value_is_fully_masked():
    assert secrets_scan._redact("short") == "•••••"


def test_redact_long_value_keeps_only_first_and_last_four():
    value = _SK + "abcdefghijklmnopqrstuvwxyz"
    redacted = secrets_scan._redact(value)
    assert redacted.startswith("sk_l")
    assert redacted.endswith("wxyz")
    assert "•" in redacted
    assert value not in redacted


def test_looks_like_placeholder_detects_repeated_characters():
    assert secrets_scan._looks_like_placeholder("XXXXXXXXXXXXXXXXXXXXXXXX") is True


def test_looks_like_placeholder_detects_example_wording():
    assert secrets_scan._looks_like_placeholder(_SK + "your-api-key-goes-here") is True


def test_looks_like_placeholder_false_for_a_random_looking_value():
    assert secrets_scan._looks_like_placeholder(_SK + "4eC39HqLyjWDarjtT1zdp7dc") is False


def test_decode_jwt_role_returns_the_role_claim():
    assert secrets_scan._decode_jwt_role(_make_jwt("service_role")) == "service_role"
    assert secrets_scan._decode_jwt_role(_make_jwt("anon")) == "anon"


def test_decode_jwt_role_returns_none_for_garbage():
    assert secrets_scan._decode_jwt_role("not.a.jwt") is None
    assert secrets_scan._decode_jwt_role("only-one-part") is None


# --- extract_credentials: inline HTML only (no network) ----------------------

def test_finds_a_stripe_secret_key_inline_and_never_stores_the_full_value():
    key = FAKE_STRIPE_KEY
    extracted = secrets_scan.extract_credentials("", f'<script>const k = "{key}";</script>')
    assert len(extracted.secrets) == 1
    match = extracted.secrets[0]
    assert match.kind == "stripe-live-key"
    assert match.severity == "critical"
    assert key not in match.redacted
    assert match.redacted.startswith("sk_l")


def test_ignores_a_placeholder_looking_key():
    extracted = secrets_scan.extract_credentials(
        "", f'<script>const k = "{_SK + "x" * 24}";</script>',
    )
    assert extracted.secrets == []


def test_finds_an_anthropic_key_and_does_not_double_report_it_as_openai():
    key = FAKE_ANTHROPIC_KEY
    extracted = secrets_scan.extract_credentials("", f'<script>const k = "{key}";</script>')
    assert [s.kind for s in extracted.secrets] == ["anthropic-key"]


def test_finds_a_database_connection_string_with_a_password():
    extracted = secrets_scan.extract_credentials(
        "", '<script>const db = "postgresql://appuser:hunter2hunter2@db.internal.test:5432/app";</script>',
    )
    assert [s.kind for s in extracted.secrets] == ["db-connection-string"]


def test_flags_a_service_role_jwt_but_not_the_normal_anon_key():
    anon, service = _make_jwt("anon"), _make_jwt("service_role")
    extracted = secrets_scan.extract_credentials(
        "", f'<script>const a = "{anon}"; const s = "{service}";</script>',
    )
    assert [s.kind for s in extracted.secrets] == ["supabase-service-role-key"]
    assert extracted.supabase_key_role == "service_role"


def test_an_anon_key_alone_is_not_a_finding_at_all():
    extracted = secrets_scan.extract_credentials(
        "", f'<script>const a = "{_make_jwt("anon")}";</script>',
    )
    assert extracted.secrets == []
    assert secrets_scan.secret_findings(extracted) == []


def test_captures_supabase_url_and_firebase_project_id_without_flagging_them():
    html = (
        '<script>const url = "https://abcdefghijklmno.supabase.co";'
        'const config = {"projectId": "my-vibe-app-1234"};</script>'
    )
    extracted = secrets_scan.extract_credentials("", html)
    assert extracted.supabase_url == "https://abcdefghijklmno.supabase.co"
    assert extracted.firebase_project_id == "my-vibe-app-1234"
    assert secrets_scan.secret_findings(extracted) == []


def test_the_same_secret_seen_twice_is_reported_once():
    key = FAKE_STRIPE_KEY
    extracted = secrets_scan.extract_credentials("", f'<script>a="{key}"; b="{key}";</script>')
    assert len(extracted.secrets) == 1


# --- secret_findings ----------------------------------------------------------

def test_service_role_finding_names_the_supabase_project():
    html = (
        '<script>const url = "https://abcdefghijklmno.supabase.co"; '
        f'const key = "{_make_jwt("service_role")}";</script>'
    )
    findings = secrets_scan.secret_findings(secrets_scan.extract_credentials("", html))
    assert len(findings) == 1
    finding_id, title, severity, detail, recommendation = findings[0]
    assert severity == "critical"
    assert "abcdefghijklmno.supabase.co" in detail
    assert "Row Level Security" in detail
    assert "Rotate" in recommendation


def test_a_public_source_map_becomes_a_medium_finding():
    extracted = secrets_scan.ExtractedCredentials(sourcemaps=["https://example.test/app.js.map"])
    findings = secrets_scan.secret_findings(extracted)
    assert len(findings) == 1
    finding_id, title, severity, detail, recommendation = findings[0]
    assert finding_id == "exposed-sourcemap-0"
    assert severity == "medium"
    assert "app.js.map" in detail


# --- Real bundle + source map fetches against a local server -----------------

def test_fetches_the_bundle_and_finds_the_secret_and_source_map(leaky_bundle_target_url, allow_private):
    html = requests.get(leaky_bundle_target_url).text
    extracted = secrets_scan.extract_credentials(leaky_bundle_target_url, html)

    assert [s.kind for s in extracted.secrets] == ["aws-access-key"]
    assert extracted.secrets[0].source_url == f"{leaky_bundle_target_url}/static/app.js"
    assert FAKE_AWS_KEY not in extracted.secrets[0].redacted
    assert extracted.sourcemaps == [f"{leaky_bundle_target_url}/static/app.js.map"]


def test_never_fetches_bundles_from_another_host(leaky_bundle_target_url, allow_private, monkeypatch):
    fetched = []
    monkeypatch.setattr(secrets_scan, "_fetch_capped", lambda url: fetched.append(url) or "")

    secrets_scan.extract_credentials(
        leaky_bundle_target_url,
        '<script src="https://cdn.other-host.test/lib.js"></script>'
        '<script src="/static/app.js"></script>',
    )

    assert fetched == [f"{leaky_bundle_target_url}/static/app.js"]


def test_refuses_to_fetch_a_bundle_on_a_private_address_by_default(leaky_bundle_target_url):
    # No allow_private fixture: the local test server's 127.0.0.1 must be
    # rejected by this module's own SSRF guard, exactly as scanner.py does.
    html = requests.get(leaky_bundle_target_url).text
    extracted = secrets_scan.extract_credentials(leaky_bundle_target_url, html)
    assert extracted.secrets == []
    assert extracted.sourcemaps == []
