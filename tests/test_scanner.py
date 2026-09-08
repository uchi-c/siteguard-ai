import pytest

import scanner
from scanner import Finding, ScanResult, UnsafeTargetError


def _result_with_findings(*severities):
    findings = [Finding(f"id{i}", "title", sev, "detail", "fix") for i, sev in enumerate(severities)]
    return ScanResult(target="https://x.test", scanned_at="t", findings=findings, reachable=True, error=None)


# --- URL normalization -------------------------------------------------

def test_normalize_url_adds_https_scheme():
    assert scanner._normalize_url("example.com") == "https://example.com"


def test_normalize_url_keeps_existing_scheme():
    assert scanner._normalize_url("http://example.com/") == "http://example.com"


def test_normalize_url_strips_trailing_slash():
    assert scanner._normalize_url("https://example.com/") == "https://example.com"


# --- Grading -------------------------------------------------------------

def test_grade_perfect_score_with_no_findings():
    r = _result_with_findings()
    assert (r.score, r.grade) == (100, "A")


def test_grade_one_low_finding_still_a():
    r = _result_with_findings("low")
    assert (r.score, r.grade) == (97, "A")


def test_grade_one_critical_is_b():
    r = _result_with_findings("critical")
    assert (r.score, r.grade) == (75, "B")


def test_grade_two_criticals_is_d():
    r = _result_with_findings("critical", "critical")
    assert (r.score, r.grade) == (50, "D")


def test_grade_three_criticals_is_f():
    r = _result_with_findings("critical", "critical", "critical")
    assert (r.score, r.grade) == (25, "F")


def test_score_floors_at_zero():
    r = _result_with_findings(*(["critical"] * 10))
    assert r.score == 0
    assert r.grade == "F"


def test_counts_tallies_by_severity():
    r = _result_with_findings("critical", "high", "high", "medium", "low", "info")
    assert r.counts() == {"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 1}


# --- SSRF guard ------------------------------------------------------------

@pytest.mark.parametrize("host", [
    "127.0.0.1",       # loopback
    "10.0.0.5",        # RFC1918
    "192.168.1.1",     # RFC1918
    "169.254.169.254", # link-local / cloud metadata
    "::1",             # IPv6 loopback
])
def test_resolve_and_validate_host_blocks_private_and_reserved(host):
    with pytest.raises(UnsafeTargetError):
        scanner._resolve_and_validate_host(host)


def test_resolve_and_validate_host_allows_public_ip():
    scanner._resolve_and_validate_host("8.8.8.8")  # must not raise


def test_resolve_and_validate_host_respects_allow_private_env(monkeypatch):
    monkeypatch.setattr(scanner, "ALLOW_PRIVATE_TARGETS", True)
    scanner._resolve_and_validate_host("127.0.0.1")  # must not raise when explicitly allowed


def test_resolve_and_validate_host_unresolvable_hostname_raises():
    with pytest.raises(UnsafeTargetError):
        scanner._resolve_and_validate_host("this-should-never-resolve.invalid")


def test_run_scan_blocks_ssrf_target_before_any_request():
    result = scanner.run_scan("127.0.0.1")
    assert result.reachable is False
    assert "private/internal" in result.error


# --- Full pipeline against real local servers ------------------------------

def test_run_scan_against_known_bad_target(test_target_url, allow_private):
    result = scanner.run_scan(test_target_url)
    assert result.reachable is True

    finding_ids = {f.id for f in result.findings}
    assert "hsts-missing" in finding_ids
    assert "csp-missing" in finding_ids
    assert "no-https" in finding_ids
    assert "server-banner" in finding_ids
    assert "xpoweredby" in finding_ids
    assert any(fid.startswith("cookie-") for fid in finding_ids)
    assert "exposed-/.env" in finding_ids
    assert any(fid.startswith("outdated-js-") for fid in finding_ids)
    assert result.grade == "F"


def test_run_scan_spa_fallback_has_no_false_positive_exposures(spa_target_url, allow_private):
    """Regression test: a catch-all SPA rewrite (Vercel-style) used to make
    every sensitive path look "exposed" since they all returned the same
    200 shell. The baseline-comparison fix should suppress all of that."""
    result = scanner.run_scan(spa_target_url)
    assert result.reachable is True
    exposed = [f for f in result.findings if f.id.startswith("exposed-")]
    assert exposed == []


# --- OWASP Top 10 mapping ---------------------------------------------------

@pytest.mark.parametrize("finding_id,expected_category", [
    ("hsts-missing", "A02"),
    ("csp-missing", "A05"),
    ("no-https", "A02"),
    ("spf-missing", "A05"),
    ("cookie-session", "A07"),
    ("exposed-/.env", "A05"),
    ("outdated-js-jQuery < 2.", "A06"),
])
def test_owasp_for_finding_id_maps_known_findings(finding_id, expected_category):
    assert scanner._owasp_for_finding_id(finding_id) == expected_category


def test_owasp_for_finding_id_unknown_returns_none():
    assert scanner._owasp_for_finding_id("some-future-check-id") is None


def test_scanresult_add_populates_owasp_fields():
    result = ScanResult(target="x", scanned_at="t", findings=[], reachable=True, error=None)
    result.add("hsts-missing", "Missing HSTS header", "high", "detail", "fix")
    f = result.findings[0]
    assert f.owasp == "A02:2021 - Cryptographic Failures"
    assert f.owasp_url == "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"


def test_scanresult_add_leaves_owasp_blank_for_unmapped_finding():
    result = ScanResult(target="x", scanned_at="t", findings=[], reachable=True, error=None)
    result.add("totally-custom-id", "Something new", "low", "detail", "fix")
    f = result.findings[0]
    assert f.owasp == ""
    assert f.owasp_url == ""


# --- Passive WAF detection ---------------------------------------------------

def test_run_scan_detects_cloudflare(cloudflare_target_url, allow_private):
    result = scanner.run_scan(cloudflare_target_url)
    assert result.reachable is True
    waf_findings = [f for f in result.findings if f.id == "waf-detected"]
    assert len(waf_findings) == 1
    assert "Cloudflare" in waf_findings[0].title
    assert waf_findings[0].severity == "info"  # must not affect the grade


def test_run_scan_no_waf_finding_when_absent(test_target_url, allow_private):
    result = scanner.run_scan(test_target_url)
    assert all(f.id != "waf-detected" for f in result.findings)
