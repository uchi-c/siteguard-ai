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
