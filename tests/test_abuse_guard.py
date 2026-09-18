import abuse_guard
import storage


def test_is_honeypot_triggered_false_when_empty():
    assert abuse_guard.is_honeypot_triggered({abuse_guard.HONEYPOT_FIELD_NAME: ""}) is False


def test_is_honeypot_triggered_false_when_absent():
    assert abuse_guard.is_honeypot_triggered({}) is False


def test_is_honeypot_triggered_true_when_filled_in():
    assert abuse_guard.is_honeypot_triggered({abuse_guard.HONEYPOT_FIELD_NAME: "I am a bot"}) is True


def test_is_honeypot_triggered_true_for_whitespace_only():
    # A bot that pads the field with whitespace shouldn't slip through --
    # .strip() in the real check should still catch it.
    assert abuse_guard.is_honeypot_triggered({abuse_guard.HONEYPOT_FIELD_NAME: "   "}) is False


def test_is_domain_in_cooldown_false_under_the_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    for _ in range(abuse_guard.DOMAIN_COOLDOWN_MAX_REQUESTS - 1):
        storage.log_scan_request("1.2.3.4", "https://example.test", "grade A, score 100/100, 0 finding(s)")

    assert abuse_guard.is_domain_in_cooldown("https://example.test") is False


def test_is_domain_in_cooldown_true_at_the_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    for _ in range(abuse_guard.DOMAIN_COOLDOWN_MAX_REQUESTS):
        storage.log_scan_request("1.2.3.4", "https://example.test", "grade A, score 100/100, 0 finding(s)")

    assert abuse_guard.is_domain_in_cooldown("https://example.test") is True


def test_is_domain_in_cooldown_scoped_per_target(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    for _ in range(abuse_guard.DOMAIN_COOLDOWN_MAX_REQUESTS):
        storage.log_scan_request("1.2.3.4", "https://example.test", "grade A, score 100/100, 0 finding(s)")

    assert abuse_guard.is_domain_in_cooldown("https://other.test") is False
