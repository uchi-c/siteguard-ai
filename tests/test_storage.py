import time

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
