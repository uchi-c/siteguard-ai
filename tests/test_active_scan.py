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
                         lambda base_url, test_post_forms=False: [{"url": base_url + "/api/signup", "param": "email"}])

    # An unreachable target means the raw-HTML crawl finds nothing on its own.
    points = active_scan._discover_injection_points("http://127.0.0.1:1/spa-like")
    assert points == [{"url": "http://127.0.0.1:1/spa-like/api/signup", "param": "email"}]


def test_discovery_skips_js_fallback_when_html_crawl_finds_points(monkeypatch, wordpress_like_target_url):
    """The (much more expensive) JS fallback should never run when the fast
    regex crawl already found real points."""
    calls = []
    monkeypatch.setattr(active_scan, "discover_injection_points_js",
                         lambda base_url, test_post_forms=False: calls.append(base_url) or [])

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


# --- POST-form testing (opt-in, real side effects) ---------------------------

def test_field_placeholder_fills_recognizable_types():
    assert "@" in active_scan._field_placeholder("email", "email")
    assert active_scan._field_placeholder("q", "text") == "sgaiplaceholder1"


def test_field_placeholder_consistent_for_matching_field_names():
    """A password + confirm-password pair must get the SAME placeholder,
    or a form that checks they match would reject the submission and no
    check downstream would ever see a real response."""
    pw = active_scan._field_placeholder("password", "password")
    confirm = active_scan._field_placeholder("confirm_password", "password")
    assert pw == confirm


def test_location_label_and_field_label_for_post_vs_get():
    get_point = {"url": "http://x.test/", "param": "q"}
    post_point = {"url": "http://x.test/contact", "param": "message", "method": "post", "fields": {}}
    assert active_scan._field_label(get_point) == "parameter 'q'"
    assert active_scan._field_label(post_point) == "POST field 'message'"
    assert active_scan._location_label(post_point, "x") == "http://x.test/contact (POST field 'message')"


def test_discover_post_points_captures_hidden_value_and_skips_checkbox(vulnerable_post_target_url):
    import requests
    html = requests.get(vulnerable_post_target_url).text
    points = active_scan._discover_post_points(vulnerable_post_target_url, html)

    params = {p["param"] for p in points}
    assert "message" in params
    assert "subscribe" not in params  # checkbox -- never a good injection target, and never submitted

    message_point = next(p for p in points if p["param"] == "message")
    assert message_point["method"] == "post"
    assert message_point["fields"]["csrf_token"] == "fixed-token-abc"  # real value, not a placeholder
    assert "subscribe" not in message_point["fields"]
    assert "message" not in message_point["fields"]  # the field under test isn't in "other fields"


def test_discover_post_points_caps_at_max_post_injection_points(monkeypatch):
    monkeypatch.setattr(active_scan, "MAX_POST_INJECTION_POINTS", 1)
    html = '<form method="post" action="/x"><input name="a"><input name="b"></form>'
    points = active_scan._discover_post_points("http://x.test/", html)
    assert len(points) == 1


def test_discover_injection_points_includes_post_when_enabled(vulnerable_post_target_url, allow_private):
    points = active_scan._discover_injection_points(vulnerable_post_target_url, test_post_forms=True)
    assert any(p.get("method") == "post" and p["param"] == "message" for p in points)


def test_discover_injection_points_excludes_post_by_default(vulnerable_post_target_url, allow_private):
    points = active_scan._discover_injection_points(vulnerable_post_target_url)
    assert not any(p.get("method") == "post" for p in points)


def test_run_active_scan_detects_xss_in_post_form_when_enabled(vulnerable_post_target_url, allow_private):
    result = active_scan.run_active_scan(vulnerable_post_target_url, test_post_forms=True)
    xss = [f for f in result.findings if f.check == "reflected-xss"]
    assert xss, f"expected a POST-field XSS finding, got: {[(f.check, f.title) for f in result.findings]}"
    assert "message" in xss[0].title
    assert "(POST field" in xss[0].location


def test_run_active_scan_skips_post_form_by_default(vulnerable_post_target_url, allow_private):
    result = active_scan.run_active_scan(vulnerable_post_target_url)
    assert result.injection_points_tested == 0
    assert result.findings == []
