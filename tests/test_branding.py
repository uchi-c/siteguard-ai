import branding


def test_defaults_when_nothing_set(monkeypatch):
    for var in ("BRAND_CONTACT_EMAIL", "BRAND_CONTACT_URL", "BRAND_AUDIT_CTA"):
        monkeypatch.delenv(var, raising=False)
    b = branding.get_branding()
    assert b["contact_email"] == ""
    assert b["contact_url"] == ""
    assert b["audit_cta"] == branding.DEFAULT_AUDIT_CTA


def test_reads_env_vars_and_strips_whitespace(monkeypatch):
    monkeypatch.setenv("BRAND_CONTACT_EMAIL", "  audits@siteguard.test ")
    monkeypatch.setenv("BRAND_CONTACT_URL", "https://fiverr.example/siteguard")
    monkeypatch.setenv("BRAND_AUDIT_CTA", "Custom pitch.")
    b = branding.get_branding()
    assert b == {
        "contact_email": "audits@siteguard.test",
        "contact_url": "https://fiverr.example/siteguard",
        "audit_cta": "Custom pitch.",
    }


def test_blank_cta_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("BRAND_AUDIT_CTA", "   ")
    assert branding.get_branding()["audit_cta"] == branding.DEFAULT_AUDIT_CTA
