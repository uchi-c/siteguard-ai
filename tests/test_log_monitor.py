import gzip
import json
from unittest.mock import MagicMock

import log_monitor
import storage


def _cf_ndjson(rows: list[dict], compress: bool = True) -> bytes:
    body = "\n".join(json.dumps(r) for r in rows).encode("utf-8")
    return gzip.compress(body) if compress else body


def _target_with_ingest(client_email=""):
    target_id = storage.add_monitored_target("https://example.test")
    if client_email:
        storage.set_monitored_target_config(target_id, "weekly", client_email)
    token = storage.enable_log_ingest(target_id)
    return target_id, token


# --- record_events: validation --------------------------------------------

def test_unknown_token_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    result = log_monitor.record_events("no-such-token", [{"type": "http_404"}], "1.2.3.4")
    assert result == {"accepted": False, "error": "unknown or disabled token"}


def test_disabled_token_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()
    storage.disable_log_ingest(target_id)

    result = log_monitor.record_events(token, [{"type": "http_404"}], "1.2.3.4")
    assert result["accepted"] is False


def test_a_single_event_dict_is_accepted_not_just_a_list(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()

    result = log_monitor.record_events(token, {"type": "http_404"}, "1.2.3.4")

    assert result["stored"] == 1
    assert len(storage.list_recent_log_events(target_id)) == 1


def test_events_beyond_the_cap_are_dropped_and_flagged_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()
    events = [{"type": "http_404"}] * (log_monitor.MAX_EVENTS_PER_REQUEST + 5)

    result = log_monitor.record_events(token, events, "1.2.3.4")

    assert result["stored"] == log_monitor.MAX_EVENTS_PER_REQUEST
    assert result["truncated"] is True


def test_an_unknown_event_type_is_skipped_not_stored(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()

    result = log_monitor.record_events(token, [{"type": "totally_made_up"}], "1.2.3.4")

    assert result["stored"] == 0
    assert result["skipped"] == 1
    assert storage.list_recent_log_events(target_id) == []


def test_a_non_dict_event_in_the_list_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()

    result = log_monitor.record_events(token, ["not a dict", {"type": "http_404"}], "1.2.3.4")

    assert result["stored"] == 1
    assert result["skipped"] == 1


def test_missing_ip_falls_back_to_the_request_source_ip(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()

    log_monitor.record_events(token, [{"type": "http_404"}], "9.8.7.6")

    assert storage.list_recent_log_events(target_id)[0]["source_ip"] == "9.8.7.6"


def test_client_supplied_ip_is_preferred_over_the_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()

    log_monitor.record_events(token, [{"type": "http_404", "ip": "1.1.1.1"}], "9.8.7.6")

    assert storage.list_recent_log_events(target_id)[0]["source_ip"] == "1.1.1.1"


def test_long_message_and_path_are_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()

    log_monitor.record_events(token, [{
        "type": "error", "message": "x" * 2000, "path": "y" * 2000,
    }], "1.2.3.4")

    stored = storage.list_recent_log_events(target_id)[0]
    assert len(stored["message"]) == log_monitor.MAX_MESSAGE_LENGTH
    assert len(stored["path"]) == log_monitor.MAX_PATH_LENGTH


def test_invalid_occurred_at_is_dropped_not_stored_as_garbage(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()

    log_monitor.record_events(token, [{"type": "http_404", "occurred_at": "not-a-date"}], "1.2.3.4")

    stored = storage.list_recent_log_events(target_id)[0]
    assert stored["occurred_at"] != "not-a-date"  # fell back to received time


# --- Rules: brute force / scanning / critical error -------------------------

def test_brute_force_rule_fires_at_the_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)

    events = [{"type": "login_failure", "ip": "1.2.3.4"}] * log_monitor.BRUTE_FORCE_THRESHOLD
    result = log_monitor.record_events(token, events, "1.2.3.4")

    assert "brute-force" in result["alerts"]
    sent.assert_called_once()
    assert sent.call_args[0][0] == "client@business.test"


def test_brute_force_rule_does_not_fire_below_the_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)

    events = [{"type": "login_failure", "ip": "1.2.3.4"}] * (log_monitor.BRUTE_FORCE_THRESHOLD - 1)
    result = log_monitor.record_events(token, events, "1.2.3.4")

    assert result["alerts"] == []
    sent.assert_not_called()


def test_brute_force_alert_fires_once_even_if_threshold_is_crossed_repeatedly(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)

    # Twice the threshold, all in one request -- must alert once, not twice.
    events = [{"type": "login_failure", "ip": "1.2.3.4"}] * (log_monitor.BRUTE_FORCE_THRESHOLD * 2)
    log_monitor.record_events(token, events, "1.2.3.4")

    sent.assert_called_once()


def test_brute_force_rule_is_scoped_per_source_ip(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)

    events = (
        [{"type": "login_failure", "ip": "1.1.1.1"}] * (log_monitor.BRUTE_FORCE_THRESHOLD - 1)
        + [{"type": "login_failure", "ip": "2.2.2.2"}] * (log_monitor.BRUTE_FORCE_THRESHOLD - 1)
    )
    result = log_monitor.record_events(token, events, "1.2.3.4")

    assert result["alerts"] == []  # neither IP alone crossed the threshold


def test_scanning_rule_fires_at_the_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)

    events = [{"type": "http_404", "ip": "1.2.3.4"}] * log_monitor.SCAN_THRESHOLD
    result = log_monitor.record_events(token, events, "1.2.3.4")

    assert "scanning" in result["alerts"]
    sent.assert_called_once()


def test_critical_error_alerts_immediately_with_no_threshold(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)

    result = log_monitor.record_events(
        token, [{"type": "error", "severity": "critical", "message": "DB connection pool exhausted"}],
        "1.2.3.4",
    )

    assert "critical-error" in result["alerts"]
    sent.assert_called_once()
    assert "DB connection pool exhausted" in sent.call_args[0][2]


def test_non_critical_error_does_not_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)

    result = log_monitor.record_events(
        token, [{"type": "error", "severity": "warning", "message": "slow query"}], "1.2.3.4",
    )

    assert result["alerts"] == []
    sent.assert_not_called()


def test_no_alert_email_sent_when_no_client_email_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest(client_email="")  # left blank
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)

    events = [{"type": "login_failure", "ip": "1.2.3.4"}] * log_monitor.BRUTE_FORCE_THRESHOLD
    result = log_monitor.record_events(token, events, "1.2.3.4")

    # The rule still "fires" (it's real signal worth showing in /admin) --
    # only the email send is skipped without a destination.
    assert "brute-force" in result["alerts"]
    sent.assert_not_called()


def test_alert_email_failure_never_raises_out_of_record_events(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    monkeypatch.setattr(log_monitor, "send_log_alert_email", lambda *a: (_ for _ in ()).throw(RuntimeError("smtp down")))

    events = [{"type": "login_failure", "ip": "1.2.3.4"}] * log_monitor.BRUTE_FORCE_THRESHOLD
    result = log_monitor.record_events(token, events, "1.2.3.4")  # must not raise

    assert "brute-force" in result["alerts"]


# --- record_cloudflare_batch -------------------------------------------------

def test_cloudflare_unknown_token_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    result = log_monitor.record_cloudflare_batch("no-such-token", _cf_ndjson([{"EdgeResponseStatus": 404}]), "1.1.1.1")
    assert result == {"accepted": False, "error": "unknown or disabled token"}


def test_cloudflare_gzip_validation_payload_is_acknowledged_without_storing(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()
    body = gzip.compress(log_monitor.CLOUDFLARE_VALIDATION_PAYLOAD.encode("utf-8"))

    result = log_monitor.record_cloudflare_batch(token, body, "10.0.0.1")

    assert result == {"accepted": True, "validation": True, "stored": 0, "skipped": 0, "alerts": []}
    assert storage.list_recent_log_events(target_id) == []


def test_cloudflare_404_rows_feed_the_scanning_rule(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)
    rows = [{"EdgeResponseStatus": 404, "ClientIP": "5.6.7.8", "ClientRequestURI": "/wp-admin"}] * log_monitor.SCAN_THRESHOLD

    result = log_monitor.record_cloudflare_batch(token, _cf_ndjson(rows), "10.0.0.1")

    assert "scanning" in result["alerts"]
    stored = storage.list_recent_log_events(target_id)
    assert all(e["event_type"] == "http_404" for e in stored)


def test_cloudflare_5xx_rows_feed_the_critical_error_rule(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest("client@business.test")
    sent = MagicMock(return_value=True)
    monkeypatch.setattr(log_monitor, "send_log_alert_email", sent)
    rows = [{
        "EdgeResponseStatus": 502, "ClientIP": "5.6.7.8",
        "ClientRequestURI": "/checkout", "ClientRequestMethod": "POST",
    }]

    result = log_monitor.record_cloudflare_batch(token, _cf_ndjson(rows), "10.0.0.1")

    assert "critical-error" in result["alerts"]
    sent.assert_called_once()
    assert "502" in sent.call_args[0][2]


def test_cloudflare_2xx_rows_are_not_stored(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()
    rows = [{"EdgeResponseStatus": 200, "ClientIP": "5.6.7.8", "ClientRequestURI": "/"}] * 5

    result = log_monitor.record_cloudflare_batch(token, _cf_ndjson(rows), "10.0.0.1")

    assert result["stored"] == 0
    assert storage.list_recent_log_events(target_id) == []


def test_cloudflare_uses_the_client_ip_field_not_the_posting_source_ip(tmp_path, monkeypatch):
    # The POST to /ingest/cloudflare/<token> comes from Cloudflare's own
    # infrastructure, not the attacker -- fallback_ip must never leak in
    # when the row already carries a real ClientIP.
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()
    rows = [{"EdgeResponseStatus": 404, "ClientIP": "9.9.9.9", "ClientRequestURI": "/x"}]

    log_monitor.record_cloudflare_batch(token, _cf_ndjson(rows), "203.0.113.1")

    assert storage.list_recent_log_events(target_id)[0]["source_ip"] == "9.9.9.9"


def test_cloudflare_malformed_json_line_is_skipped_not_fatal(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()
    body = b'not json\n' + json.dumps({"EdgeResponseStatus": 404, "ClientIP": "1.2.3.4"}).encode()

    result = log_monitor.record_cloudflare_batch(token, gzip.compress(body), "10.0.0.1")

    assert result["stored"] == 1
    assert result["skipped"] == 1


def test_cloudflare_batch_works_uncompressed_too(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "scans.db"))
    target_id, token = _target_with_ingest()
    rows = [{"EdgeResponseStatus": 404, "ClientIP": "1.2.3.4", "ClientRequestURI": "/y"}]

    result = log_monitor.record_cloudflare_batch(token, _cf_ndjson(rows, compress=False), "10.0.0.1")

    assert result["stored"] == 1
