import time

import pytest

import storage
from scanner import Finding, ScanResult


def test_save_and_load_scan_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    result = ScanResult(
        target="https://example.test", scanned_at="2026-01-01T00:00:00+00:00",
        findings=[Finding("hsts-missing", "Missing HSTS header", "high", "detail", "fix")],
        reachable=True, error=None,
    )
    scan_id = storage.save_scan(result, "a narrative", "rule-based")

    loaded = storage.load_scan(scan_id)
    assert loaded is not None
    loaded_result, narrative, source = loaded
    assert loaded_result.target == "https://example.test"
    assert loaded_result.score == 85  # 100 - 15 (one "high")
    assert loaded_result.grade == "B"
    assert len(loaded_result.findings) == 1
    assert loaded_result.findings[0].id == "hsts-missing"
    assert narrative == "a narrative"
    assert source == "rule-based"


def test_load_scan_missing_id_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    assert storage.load_scan("does-not-exist") is None


def test_scan_ids_are_unique_and_url_safe(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    result = ScanResult(target="https://x.test", scanned_at="t", findings=[], reachable=True, error=None)
    ids = {storage.save_scan(result, "n", "rule-based") for _ in range(10)}
    assert len(ids) == 10
    for scan_id in ids:
        assert all(c.isalnum() or c in "-_" for c in scan_id)


def test_list_recent_scans_orders_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    r1 = ScanResult(target="https://a.test", scanned_at="t1", findings=[], reachable=True, error=None)
    r2 = ScanResult(target="https://b.test", scanned_at="t2", findings=[], reachable=True, error=None)

    storage.save_scan(r1, "n1", "rule-based")
    time.sleep(0.01)  # ensure a distinct created_at ordering
    storage.save_scan(r2, "n2", "rule-based")

    recent = storage.list_recent_scans()
    assert [s["target"] for s in recent] == ["https://b.test", "https://a.test"]
    assert recent[0]["grade"] == "A"
    assert recent[0]["score"] == 100


# --- Leads (save/list/update/import) -----------------------------------------

def test_save_and_list_lead(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    lead_id = storage.save_lead("prospect@test.com", "https://example.test", "C", 63)

    leads = storage.list_leads()
    assert len(leads) == 1
    assert leads[0]["id"] == lead_id
    assert leads[0]["email"] == "prospect@test.com"
    assert leads[0]["target"] == "https://example.test"
    assert leads[0]["grade"] == "C"
    assert leads[0]["score"] == 63
    assert leads[0]["status"] == "new"  # default until worked
    assert leads[0]["notes"] == ""


def test_list_leads_orders_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    storage.save_lead("a@test.com", "https://a.test", "A", 95)
    time.sleep(0.01)
    storage.save_lead("b@test.com", "https://b.test", "B", 80)

    leads = storage.list_leads()
    assert [l["email"] for l in leads] == ["b@test.com", "a@test.com"]


def test_update_lead_changes_status_and_notes(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    lead_id = storage.save_lead("prospect@test.com", "https://example.test", "C", 63)

    updated = storage.update_lead(lead_id, "contacted", "Called, left voicemail")
    assert updated is True

    leads = storage.list_leads()
    assert leads[0]["status"] == "contacted"
    assert leads[0]["notes"] == "Called, left voicemail"


def test_update_lead_rejects_unknown_status(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    lead_id = storage.save_lead("prospect@test.com", "https://example.test", "C", 63)
    with pytest.raises(ValueError):
        storage.update_lead(lead_id, "not-a-real-status", "")


def test_update_lead_returns_false_for_unknown_id(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    assert storage.update_lead("no-such-lead", "contacted", "") is False


def test_import_leads_csv_once_migrates_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    csv_path = tmp_path / "leads.csv"
    csv_path.write_text(
        "timestamp_utc,email,target,grade,score\n"
        "2026-01-01T00:00:00+00:00,old@test.com,https://old.test,B,82\n",
        encoding="utf-8",
    )

    imported = storage.import_leads_csv_once(str(csv_path))
    assert imported == 1

    leads = storage.list_leads()
    assert len(leads) == 1
    assert leads[0]["email"] == "old@test.com"
    assert leads[0]["target"] == "https://old.test"
    assert leads[0]["grade"] == "B"
    assert leads[0]["score"] == 82
    assert leads[0]["status"] == "new"


def test_import_leads_csv_once_is_a_no_op_the_second_time(tmp_path, monkeypatch):
    """Must never re-import or duplicate -- called unconditionally on every
    /admin load."""
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    csv_path = tmp_path / "leads.csv"
    csv_path.write_text(
        "timestamp_utc,email,target,grade,score\nold@test.com,https://old.test,old@test.com,B,82\n",
        encoding="utf-8",
    )

    storage.import_leads_csv_once(str(csv_path))
    second_run = storage.import_leads_csv_once(str(csv_path))
    assert second_run == 0
    assert len(storage.list_leads()) == 1


def test_import_leads_csv_once_skips_when_table_already_has_leads(tmp_path, monkeypatch):
    """A lead saved through the new tracker (not imported from CSV) must
    also block a later import -- the guard is "table has any rows", not
    "an import already ran"."""
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    storage.save_lead("new@test.com", "https://new.test", "A", 95)

    csv_path = tmp_path / "leads.csv"
    csv_path.write_text(
        "timestamp_utc,email,target,grade,score\n"
        "2026-01-01T00:00:00+00:00,old@test.com,https://old.test,B,82\n",
        encoding="utf-8",
    )
    imported = storage.import_leads_csv_once(str(csv_path))
    assert imported == 0
    assert len(storage.list_leads()) == 1


def test_import_leads_csv_once_returns_zero_when_file_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    assert storage.import_leads_csv_once(str(tmp_path / "does-not-exist.csv")) == 0


# --- Monitored targets --------------------------------------------------------

def test_add_and_list_monitored_target(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id = storage.add_monitored_target("https://example.test")

    targets = storage.list_monitored_targets()
    assert len(targets) == 1
    assert targets[0]["id"] == target_id
    assert targets[0]["target"] == "https://example.test"
    assert targets[0]["last_checked_at"] is None
    assert targets[0]["last_scan_id"] is None
    assert targets[0]["last_new_count"] == 0
    assert targets[0]["last_resolved_count"] == 0


def test_add_monitored_target_is_idempotent(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    first_id = storage.add_monitored_target("https://example.test")
    second_id = storage.add_monitored_target("https://example.test")
    assert first_id == second_id
    assert len(storage.list_monitored_targets()) == 1


def test_is_monitored(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    assert storage.is_monitored("https://example.test") is False
    storage.add_monitored_target("https://example.test")
    assert storage.is_monitored("https://example.test") is True


def test_remove_monitored_target(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id = storage.add_monitored_target("https://example.test")
    assert storage.remove_monitored_target(target_id) is True
    assert storage.list_monitored_targets() == []
    assert storage.is_monitored("https://example.test") is False


def test_remove_monitored_target_returns_false_for_unknown_id(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    assert storage.remove_monitored_target("no-such-id") is False


def test_record_monitor_check_updates_row(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id = storage.add_monitored_target("https://example.test")

    result = ScanResult(target="https://example.test", scanned_at="t", findings=[], reachable=True, error=None)
    scan_id = storage.save_scan(result, "narrative", "rule-based")

    storage.record_monitor_check(target_id, scan_id, new_count=2, resolved_count=1, digest="2 new, 1 resolved")

    targets = storage.list_monitored_targets()
    assert targets[0]["last_scan_id"] == scan_id
    assert targets[0]["last_new_count"] == 2
    assert targets[0]["last_resolved_count"] == 1
    assert targets[0]["last_digest"] == "2 new, 1 resolved"
    assert targets[0]["last_checked_at"] is not None


def test_list_monitored_targets_orders_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    storage.add_monitored_target("https://a.test")
    time.sleep(0.01)
    storage.add_monitored_target("https://b.test")

    targets = storage.list_monitored_targets()
    assert [t["target"] for t in targets] == ["https://b.test", "https://a.test"]


# --- Scan request log (abuse visibility + per-domain cooldown) --------------

def test_log_and_list_scan_requests(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    storage.log_scan_request("1.2.3.4", "https://example.test", "grade A, score 100/100, 0 finding(s)")

    entries = storage.list_scan_requests()
    assert len(entries) == 1
    assert entries[0]["source_ip"] == "1.2.3.4"
    assert entries[0]["target"] == "https://example.test"
    assert entries[0]["result_summary"] == "grade A, score 100/100, 0 finding(s)"
    assert entries[0]["created_at"]


def test_list_scan_requests_orders_newest_first(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    storage.log_scan_request("1.1.1.1", "https://a.test", "first")
    time.sleep(0.01)
    storage.log_scan_request("2.2.2.2", "https://b.test", "second")

    entries = storage.list_scan_requests()
    assert [e["target"] for e in entries] == ["https://b.test", "https://a.test"]


def test_count_recent_scan_requests_only_counts_within_window(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    assert storage.count_recent_scan_requests("https://example.test", 60) == 0

    for _ in range(3):
        storage.log_scan_request("1.2.3.4", "https://example.test", "grade A, score 100/100, 0 finding(s)")
    storage.log_scan_request("1.2.3.4", "https://other.test", "grade A, score 100/100, 0 finding(s)")

    assert storage.count_recent_scan_requests("https://example.test", 60) == 3
    assert storage.count_recent_scan_requests("https://other.test", 60) == 1


def test_count_recent_scan_requests_excludes_entries_outside_window(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))

    old_time = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    from contextlib import closing
    with closing(storage._connect()) as conn:
        conn.execute(
            "INSERT INTO scan_requests (created_at, source_ip, target, result_summary) VALUES (?, ?, ?, ?)",
            (old_time, "1.2.3.4", "https://stale.test", "grade A, score 100/100, 0 finding(s)"),
        )
        conn.commit()

    assert storage.count_recent_scan_requests("https://stale.test", 60) == 0
