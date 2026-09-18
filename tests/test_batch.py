import pytest

import batch
import storage
from scanner import Finding, ScanResult


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """batch.py now logs every target through storage.log_scan_request --
    redirect it to a temp DB so these tests never touch the real scans.db."""
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))


def test_run_job_marks_items_done(monkeypatch):
    def fake_run_scan(target):
        return ScanResult(
            target=target, scanned_at="t",
            findings=[Finding("x", "Test finding", "high", "detail", "fix")],
            reachable=True, error=None,
        )

    monkeypatch.setattr(batch, "run_scan", fake_run_scan)
    monkeypatch.setattr(batch, "generate_narrative", lambda r: ("summary", "rule-based"))
    monkeypatch.setattr(batch, "generate_outreach_message", lambda *a: ("outreach text", "rule-based"))
    monkeypatch.setattr(batch, "save_scan", lambda *a: "fake-scan-id")

    job_id = "test-job-done"
    batch.create_job(job_id, ["site-a.test", "site-b.test"])
    batch.run_job(job_id, "127.0.0.1")

    job = batch.get_job(job_id)
    assert job["finished"] is True
    assert job["done_count"] == 2
    for item in job["items"]:
        assert item["status"] == "done"
        assert item["scan_id"] == "fake-scan-id"
        assert item["outreach"] == "outreach text"
        assert item["grade"] == "B"  # 100 - 15 (one "high")

    logged = storage.list_scan_requests()
    assert len(logged) == 2
    assert all(e["source_ip"] == "127.0.0.1" for e in logged)


def test_run_job_records_unreachable_target(monkeypatch):
    def fake_run_scan(target):
        return ScanResult(target=target, scanned_at="t", findings=[], reachable=False, error="boom")

    monkeypatch.setattr(batch, "run_scan", fake_run_scan)

    job_id = "test-job-unreachable"
    batch.create_job(job_id, ["bad.test"])
    batch.run_job(job_id, "127.0.0.1")

    job = batch.get_job(job_id)
    assert job["finished"] is True
    assert job["items"][0]["status"] == "error"
    assert job["items"][0]["error"] == "boom"


def test_run_job_survives_unexpected_exception(monkeypatch):
    def boom(target):
        raise RuntimeError("network exploded")

    monkeypatch.setattr(batch, "run_scan", boom)

    job_id = "test-job-exception"
    batch.create_job(job_id, ["bad.test"])
    batch.run_job(job_id, "127.0.0.1")  # must not raise, and must still finish

    job = batch.get_job(job_id)
    assert job["finished"] is True
    assert job["items"][0]["status"] == "error"
    assert "network exploded" in job["items"][0]["error"]


def test_one_bad_target_does_not_block_the_rest(monkeypatch):
    def fake_run_scan(target):
        if target == "bad.test":
            raise RuntimeError("boom")
        return ScanResult(target=target, scanned_at="t", findings=[], reachable=True, error=None)

    monkeypatch.setattr(batch, "run_scan", fake_run_scan)
    monkeypatch.setattr(batch, "generate_narrative", lambda r: ("summary", "rule-based"))
    monkeypatch.setattr(batch, "generate_outreach_message", lambda *a: ("outreach", "rule-based"))
    monkeypatch.setattr(batch, "save_scan", lambda *a: "id-123")

    job_id = "test-job-mixed"
    batch.create_job(job_id, ["good-a.test", "bad.test", "good-b.test"])
    batch.run_job(job_id, "127.0.0.1")

    job = batch.get_job(job_id)
    assert job["finished"] is True
    assert job["done_count"] == 3
    statuses = {i["target"]: i["status"] for i in job["items"]}
    assert statuses == {"good-a.test": "done", "bad.test": "error", "good-b.test": "done"}


def test_get_job_returns_none_for_unknown_id():
    assert batch.get_job("no-such-job") is None


def test_scan_one_blocked_by_domain_cooldown(monkeypatch):
    monkeypatch.setattr(batch, "is_domain_in_cooldown", lambda target: True)

    def fail_if_called(target):
        raise AssertionError("run_scan should not be called when the target is in cooldown")

    monkeypatch.setattr(batch, "run_scan", fail_if_called)

    job_id = "test-job-cooldown"
    batch.create_job(job_id, ["cooled-down.test"])
    batch.run_job(job_id, "127.0.0.1")

    job = batch.get_job(job_id)
    assert job["items"][0]["status"] == "error"
    assert "already scanned recently" in job["items"][0]["error"]

    logged = storage.list_scan_requests()
    assert len(logged) == 1
    assert logged[0]["result_summary"] == "blocked: domain cooldown"
