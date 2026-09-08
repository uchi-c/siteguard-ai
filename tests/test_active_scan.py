import active_scan


def test_with_param_replaces_existing_value():
    result = active_scan._with_param("http://x.test/?q=old&other=1", "q", "new")
    assert "q=new" in result
    assert "other=1" in result


def test_with_param_adds_missing_param():
    result = active_scan._with_param("http://x.test/search", "term", "hello")
    assert "term=hello" in result


def test_run_active_scan_blocks_ssrf_target():
    result = active_scan.run_active_scan("127.0.0.1")
    assert result.error is not None
    assert "private/internal" in result.error
    assert result.findings == []


def test_discover_injection_points_finds_link_and_form_params(vulnerable_target_url, allow_private):
    points = active_scan._discover_injection_points(vulnerable_target_url)
    params = {p["param"] for p in points}
    assert "q" in params
    assert "term" in params


def test_run_active_scan_detects_reflected_xss(vulnerable_target_url, allow_private):
    result = active_scan.run_active_scan(vulnerable_target_url)
    xss = [f for f in result.findings if f.check == "reflected-xss"]
    assert any("'q'" in f.title for f in xss) or any("q" in f.location for f in xss)


def test_run_active_scan_detects_sqli(vulnerable_target_url, allow_private):
    result = active_scan.run_active_scan(vulnerable_target_url)
    sqli = [f for f in result.findings if f.check == "sqli-error-based"]
    assert len(sqli) >= 1
    assert sqli[0].severity == "critical"


def test_run_active_scan_detects_weak_credentials(vulnerable_target_url, allow_private):
    result = active_scan.run_active_scan(vulnerable_target_url)
    weak = [f for f in result.findings if f.check == "weak-credentials"]
    assert len(weak) == 1
    assert "admin" in weak[0].detail


def test_run_active_scan_no_findings_against_a_clean_target(test_target_url, allow_private):
    """test_target.py has no query-string params, no GET forms, and no
    /admin route -- none of the three active checks should fire."""
    result = active_scan.run_active_scan(test_target_url)
    assert result.findings == []
