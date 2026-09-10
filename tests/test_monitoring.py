from unittest.mock import MagicMock

import monitoring
import storage
from scanner import Finding, ScanResult


def test_diff_findings_detects_new_and_resolved():
    old = [Finding("a", "A", "high", "d", "f"), Finding("b", "B", "medium", "d", "f")]
    new = [Finding("a", "A", "high", "d", "f"), Finding("c", "C", "critical", "d", "f")]
    newly_appeared, resolved = monitoring._diff_findings(old, new)
    assert [f.id for f in newly_appeared] == ["c"]
    assert [f.id for f in resolved] == ["b"]


def test_diff_findings_no_change():
    same = [Finding("a", "A", "high", "d", "f")]
    newly_appeared, resolved = monitoring._diff_findings(same, same)
    assert newly_appeared == []
    assert resolved == []


def test_diff_findings_first_ever_check_has_no_old_findings():
    new = [Finding("a", "A", "high", "d", "f")]
    newly_appeared, resolved = monitoring._diff_findings([], new)
    assert [f.id for f in newly_appeared] == ["a"]
    assert resolved == []


def test_run_monitoring_check_saves_new_scan_and_records_diff(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    target_id = storage.add_monitored_target("https://example.test")

    call_count = {"n": 0}

    def fake_run_scan(target):
        call_count["n"] += 1
        # First call (inside this test's setup) returns one finding; the
        # monitored check itself is the only call here, so this always
        # returns the "new" state -- old_findings comes from last_scan_id,
        # which is None on a target's first-ever check.
        return ScanResult(
            target=target, scanned_at="t",
            findings=[Finding("hsts", "Missing HSTS header", "high", "detail", "fix")],
            reachable=True, error=None,
        )

    monkeypatch.setattr(monitoring, "run_scan", fake_run_scan)

    results = monitoring.run_monitoring_check()

    assert len(results) == 1
    assert results[0]["status"] == "checked"
    assert results[0]["new_findings"] == 1  # first-ever check: everything is "new"
    assert results[0]["resolved_findings"] == 0

    updated = storage.list_monitored_targets()[0]
    assert updated["id"] == target_id
    assert updated["last_scan_id"] == results[0]["scan_id"]
    assert updated["last_new_count"] == 1
    assert updated["last_checked_at"] is not None


def test_run_monitoring_check_diffs_against_previous_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    target_id = storage.add_monitored_target("https://example.test")
    old_result = ScanResult(
        target="https://example.test", scanned_at="t",
        findings=[Finding("hsts", "Missing HSTS header", "high", "detail", "fix")],
        reachable=True, error=None,
    )
    old_scan_id = storage.save_scan(old_result, "n", "rule-based")
    storage.record_monitor_check(target_id, old_scan_id, new_count=1, resolved_count=0, digest="")

    def fake_run_scan(target):
        # hsts is now fixed, but a new CSP finding appeared.
        return ScanResult(
            target=target, scanned_at="t2",
            findings=[Finding("csp-missing", "Missing CSP header", "medium", "detail", "fix")],
            reachable=True, error=None,
        )

    monkeypatch.setattr(monitoring, "run_scan", fake_run_scan)

    results = monitoring.run_monitoring_check()
    assert results[0]["new_findings"] == 1
    assert results[0]["resolved_findings"] == 1

    updated = storage.list_monitored_targets()[0]
    assert updated["last_new_count"] == 1
    assert updated["last_resolved_count"] == 1
    assert updated["last_digest"]  # something changed -> a digest was generated


def test_run_monitoring_check_no_digest_when_nothing_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    target_id = storage.add_monitored_target("https://example.test")
    same_finding = Finding("hsts", "Missing HSTS header", "high", "detail", "fix")
    old_result = ScanResult(target="https://example.test", scanned_at="t", findings=[same_finding], reachable=True, error=None)
    old_scan_id = storage.save_scan(old_result, "n", "rule-based")
    storage.record_monitor_check(target_id, old_scan_id, new_count=1, resolved_count=0, digest="")

    monkeypatch.setattr(monitoring, "run_scan", lambda target: ScanResult(
        target=target, scanned_at="t2", findings=[same_finding], reachable=True, error=None,
    ))

    results = monitoring.run_monitoring_check()
    assert results[0]["new_findings"] == 0
    assert results[0]["resolved_findings"] == 0
    assert storage.list_monitored_targets()[0]["last_digest"] == ""


def test_run_monitoring_check_unreachable_target_records_error(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    storage.add_monitored_target("https://example.test")

    monkeypatch.setattr(monitoring, "run_scan", lambda target: ScanResult(
        target=target, scanned_at="t", findings=[], reachable=False, error="connection refused",
    ))

    results = monitoring.run_monitoring_check()
    assert results[0]["status"] == "error"
    assert results[0]["error"] == "connection refused"


def test_run_monitoring_check_one_bad_target_does_not_block_the_rest(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    storage.add_monitored_target("https://bad.test")
    storage.add_monitored_target("https://good.test")

    def fake_run_scan(target):
        if target == "https://bad.test":
            raise RuntimeError("boom")
        return ScanResult(target=target, scanned_at="t", findings=[], reachable=True, error=None)

    monkeypatch.setattr(monitoring, "run_scan", fake_run_scan)

    results = monitoring.run_monitoring_check()
    statuses = {r["target"]: r["status"] for r in results}
    assert statuses == {"https://bad.test": "error", "https://good.test": "checked"}


def test_run_monitoring_check_with_no_monitored_targets_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    assert monitoring.run_monitoring_check() == []


# --- Operator alert email (never sent to a client) ---------------------------

def test_alert_email_sent_when_configured_and_something_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(monitoring, "MONITORING_ALERT_EMAIL", "operator@shadowroot.test")

    storage.add_monitored_target("https://example.test")
    monkeypatch.setattr(monitoring, "run_scan", lambda target: ScanResult(
        target=target, scanned_at="t",
        findings=[Finding("hsts", "Missing HSTS header", "high", "detail", "fix")],
        reachable=True, error=None,
    ))

    sent = MagicMock(return_value=True)
    monkeypatch.setattr(monitoring, "send_plain_email", sent)

    monitoring.run_monitoring_check()

    sent.assert_called_once()
    to_email, subject, body = sent.call_args[0]
    assert to_email == "operator@shadowroot.test"
    assert "example.test" in body


def test_alert_email_not_sent_when_nothing_changed(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    monkeypatch.setattr(monitoring, "MONITORING_ALERT_EMAIL", "operator@shadowroot.test")
    # No monitored targets at all -- nothing to change, nothing to email.

    sent = MagicMock()
    monkeypatch.setattr(monitoring, "send_plain_email", sent)

    monitoring.run_monitoring_check()
    sent.assert_not_called()


def test_alert_email_not_sent_when_not_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(monitoring, "MONITORING_ALERT_EMAIL", "")

    storage.add_monitored_target("https://example.test")
    monkeypatch.setattr(monitoring, "run_scan", lambda target: ScanResult(
        target=target, scanned_at="t",
        findings=[Finding("hsts", "Missing HSTS header", "high", "detail", "fix")],
        reachable=True, error=None,
    ))

    sent = MagicMock()
    monkeypatch.setattr(monitoring, "send_plain_email", sent)

    monitoring.run_monitoring_check()
    sent.assert_not_called()
