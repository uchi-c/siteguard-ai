from contextlib import closing
from datetime import datetime, timedelta, timezone

import pytest

import followups
import storage


def _insert_lead(lead_id, hours_ago, status="new", email="prospect@test.com", target="https://example.test"):
    created_at = (datetime.now(timezone.utc) - timedelta(hours=hours_ago)).isoformat()
    with closing(storage._connect()) as conn:
        conn.execute(
            "INSERT INTO leads (id, created_at, email, target, grade, score, status, notes) "
            "VALUES (?, ?, ?, ?, 'C', 63, ?, '')",
            (lead_id, created_at, email, target, status),
        )
        conn.commit()


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))


@pytest.fixture(autouse=True)
def _stub_message(monkeypatch):
    monkeypatch.setattr(followups, "generate_followup_message", lambda *a: ("following up...", "rule-based"))


def test_due_lead_gets_followup_sent(monkeypatch):
    _insert_lead("lead-1", hours_ago=49, status="new")
    sent = []
    monkeypatch.setattr(followups, "send_followup_email", lambda *a: (sent.append(a) or True))

    results = followups.run_followup_check()

    assert len(results) == 1
    assert results[0] == {"lead_id": "lead-1", "email": "prospect@test.com", "status": "sent"}
    assert sent == [("prospect@test.com", "https://example.test", "following up...")]
    assert storage.has_lead_followup_been_sent("lead-1") is True


def test_lead_not_yet_due_is_skipped(monkeypatch):
    _insert_lead("lead-1", hours_ago=10, status="new")
    monkeypatch.setattr(followups, "send_followup_email", lambda *a: True)

    assert followups.run_followup_check() == []
    assert storage.has_lead_followup_been_sent("lead-1") is False


@pytest.mark.parametrize("status", ["quoted", "won", "lost"])
def test_lead_outside_eligible_status_is_skipped(monkeypatch, status):
    _insert_lead("lead-1", hours_ago=72, status=status)
    monkeypatch.setattr(followups, "send_followup_email", lambda *a: True)

    assert followups.run_followup_check() == []


def test_already_sent_lead_is_not_sent_twice(monkeypatch):
    _insert_lead("lead-1", hours_ago=72, status="new")
    storage.record_lead_followup_sent("lead-1", "old message", "rule-based")

    calls = []
    monkeypatch.setattr(followups, "send_followup_email", lambda *a: (calls.append(a) or True))

    assert followups.run_followup_check() == []
    assert calls == []


def test_skipped_send_is_not_recorded_so_it_retries_later(monkeypatch):
    _insert_lead("lead-1", hours_ago=72, status="new")
    monkeypatch.setattr(followups, "send_followup_email", lambda *a: False)

    results = followups.run_followup_check()

    assert results[0]["status"] == "skipped: SMTP not configured"
    assert storage.has_lead_followup_been_sent("lead-1") is False


def test_one_bad_lead_does_not_block_the_rest(monkeypatch):
    _insert_lead("lead-bad", hours_ago=72, status="new", email="bad@test.com")
    _insert_lead("lead-good", hours_ago=72, status="new", email="good@test.com")

    def fake_send(to_email, target, message):
        if to_email == "bad@test.com":
            raise RuntimeError("smtp exploded")
        return True

    monkeypatch.setattr(followups, "send_followup_email", fake_send)

    results = followups.run_followup_check()

    statuses = {r["email"]: r["status"] for r in results}
    assert statuses["good@test.com"] == "sent"
    assert "smtp exploded" in statuses["bad@test.com"]
    assert storage.has_lead_followup_been_sent("lead-good") is True
    assert storage.has_lead_followup_been_sent("lead-bad") is False


def test_top_finding_matched_from_most_recent_scan_of_same_target(monkeypatch):
    from scanner import Finding, ScanResult

    result = ScanResult(
        target="https://example.test", scanned_at="t",
        findings=[Finding("hsts", "Missing HSTS header", "high", "detail", "fix")],
        reachable=True, error=None,
    )
    storage.save_scan(result, "narrative", "rule-based")
    _insert_lead("lead-1", hours_ago=72, status="new")

    captured = {}

    def fake_generate(target, top_title, top_detail, days_since):
        captured["top_title"] = top_title
        captured["days_since"] = days_since
        return "following up...", "rule-based"

    monkeypatch.setattr(followups, "generate_followup_message", fake_generate)
    monkeypatch.setattr(followups, "send_followup_email", lambda *a: True)

    followups.run_followup_check()

    assert captured["top_title"] == "Missing HSTS header"
    assert captured["days_since"] == 3
