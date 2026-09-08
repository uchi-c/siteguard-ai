import active_scan_job
from active_scan import ActiveFinding, ActiveScanResult


def test_run_job_marks_finished_with_no_findings(monkeypatch):
    monkeypatch.setattr(
        active_scan_job, "run_active_scan",
        lambda target: ActiveScanResult(
            target=target, scanned_at="t", findings=[], injection_points_tested=3,
        ),
    )

    job_id = "job-clean"
    active_scan_job.create_job(job_id, "https://example.test")
    active_scan_job.run_job(job_id, "https://example.test")

    job = active_scan_job.get_job(job_id)
    assert job["finished"] is True
    assert job["result"]["injection_points_tested"] == 3
    assert job["result"]["findings"] == []
    assert job["result"]["error"] is None


def test_run_job_serializes_findings_as_dicts(monkeypatch):
    finding = ActiveFinding(
        check="reflected-xss", severity="high", title="XSS in 'q'",
        detail="detail text", location="https://example.test/?q=probe",
    )
    monkeypatch.setattr(
        active_scan_job, "run_active_scan",
        lambda target: ActiveScanResult(
            target=target, scanned_at="t", findings=[finding], injection_points_tested=1,
        ),
    )

    job_id = "job-with-finding"
    active_scan_job.create_job(job_id, "https://example.test")
    active_scan_job.run_job(job_id, "https://example.test")

    job = active_scan_job.get_job(job_id)
    assert job["result"]["findings"] == [{
        "check": "reflected-xss", "severity": "high", "title": "XSS in 'q'",
        "detail": "detail text", "location": "https://example.test/?q=probe",
    }]


def test_run_job_records_scan_error(monkeypatch):
    monkeypatch.setattr(
        active_scan_job, "run_active_scan",
        lambda target: ActiveScanResult(
            target=target, scanned_at="t", findings=[], error="blocked: private target",
        ),
    )

    job_id = "job-blocked"
    active_scan_job.create_job(job_id, "https://example.test")
    active_scan_job.run_job(job_id, "https://example.test")

    job = active_scan_job.get_job(job_id)
    assert job["finished"] is True
    assert job["result"]["error"] == "blocked: private target"


def test_run_job_does_nothing_if_job_was_never_created(monkeypatch):
    monkeypatch.setattr(
        active_scan_job, "run_active_scan",
        lambda target: ActiveScanResult(target=target, scanned_at="t", findings=[]),
    )
    active_scan_job.run_job("never-created", "https://example.test")  # must not raise
    assert active_scan_job.get_job("never-created") is None


def test_get_job_returns_none_for_unknown_id():
    assert active_scan_job.get_job("no-such-job") is None
