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


def test_discovery_falls_back_to_js_rendering_when_html_crawl_finds_nothing(monkeypatch, allow_private):
    """Regression test for the SPA discovery gap (surfaced against a real
    site, uruu.enterprises): a page with zero forms/query-string links in
    its raw HTML must trigger the headless-browser fallback rather than
    silently reporting 0 injection points."""
    monkeypatch.setattr(active_scan, "discover_injection_points_js",
                         lambda base_url: [{"url": base_url + "/api/signup", "param": "email"}])

    # An unreachable target means the raw-HTML crawl finds nothing on its own.
    points = active_scan._discover_injection_points("http://127.0.0.1:1/spa-like")
    assert points == [{"url": "http://127.0.0.1:1/spa-like/api/signup", "param": "email"}]


def test_discovery_skips_js_fallback_when_html_crawl_finds_points(monkeypatch, wordpress_like_target_url):
    """The (much more expensive) JS fallback should never run when the fast
    regex crawl already found real points."""
    calls = []
    monkeypatch.setattr(active_scan, "discover_injection_points_js",
                         lambda base_url: calls.append(base_url) or [])

    points = active_scan._discover_injection_points(wordpress_like_target_url)
    assert points  # the wordpress fixture's search form should still be found
    assert calls == []


def test_run_active_scan_detects_reflected_xss(vulnerable_scan_result):
    xss = [f for f in vulnerable_scan_result.findings if f.check == "reflected-xss"]
    assert any("'q'" in f.title for f in xss) or any("q" in f.location for f in xss)


def test_run_active_scan_detects_sqli(vulnerable_scan_result):
    sqli = [f for f in vulnerable_scan_result.findings if f.check == "sqli-error-based"]
    assert len(sqli) >= 1
    assert sqli[0].severity == "critical"


def test_run_active_scan_detects_weak_credentials(vulnerable_scan_result):
    weak = [f for f in vulnerable_scan_result.findings if f.check == "weak-credentials"]
    assert len(weak) == 1
    assert "admin" in weak[0].detail


def test_run_active_scan_detects_ssti(vulnerable_scan_result):
    ssti = [f for f in vulnerable_scan_result.findings if f.check == "ssti"]
    assert len(ssti) >= 1
    assert ssti[0].severity == "critical"
    assert "tpl" in ssti[0].title


def test_run_active_scan_detects_path_traversal(vulnerable_scan_result):
    traversal = [f for f in vulnerable_scan_result.findings if f.check == "path-traversal"]
    assert len(traversal) == 1
    assert "path" in traversal[0].title


def test_run_active_scan_detects_command_injection(vulnerable_scan_result):
    cmdi = [f for f in vulnerable_scan_result.findings if f.check == "command-injection"]
    assert len(cmdi) == 1
    assert "cmd" in cmdi[0].title


def test_run_active_scan_detects_open_redirect(vulnerable_scan_result):
    redirects = [f for f in vulnerable_scan_result.findings if f.check == "open-redirect"]
    assert len(redirects) == 1
    assert "redirect" in redirects[0].title
    assert redirects[0].severity == "medium"


def test_open_redirect_only_tested_on_redirect_looking_params():
    """A param named 'q' shouldn't even trigger a probe -- avoids wasting
    a request on params that were never going to be a redirect target."""
    result = active_scan._test_open_redirect({"url": "http://x.test/", "param": "q"})
    assert result is None


def test_run_active_scan_no_findings_against_a_clean_target(test_target_url, allow_private):
    """test_target.py has no query-string params, no GET forms, and no
    /admin route -- none of the active checks should fire."""
    result = active_scan.run_active_scan(test_target_url)
    assert result.findings == []


def test_discover_injection_points_prioritizes_forms_over_asset_noise(wordpress_like_target_url, allow_private):
    """Regression test for a real bug found manually: a page with 20
    `?ver=` cache-busting links on its own stylesheets, plus one real GET
    search form. Discovery used to collect link-based points before
    form-based ones, so with MAX_INJECTION_POINTS capping the total, the
    cache-busters filled every slot and the search form's actual
    parameter -- the obvious, classic test target -- was silently
    dropped. Forms must now win a slot regardless of how much static-
    asset noise precedes them on the page."""
    points = active_scan._discover_injection_points(wordpress_like_target_url)
    assert any(p["param"] == "s" for p in points), f"search form param missing: {points}"
    # And the noise shouldn't even make it in -- static assets are filtered.
    assert not any(p["url"].endswith(".css") for p in points)
