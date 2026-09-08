"""
emailer.py always goes through smtplib.SMTP, which is mocked in every test
here -- these tests must never send a real email. That's a deliberate
line: sending mail is a real-world side effect with a real recipient, not
something a test suite should ever actually do.
"""
from unittest.mock import MagicMock, patch

import emailer


def test_is_configured_false_without_credentials(monkeypatch):
    monkeypatch.setattr(emailer, "SMTP_USERNAME", "")
    monkeypatch.setattr(emailer, "SMTP_PASSWORD", "")
    assert emailer.is_configured() is False


def test_is_configured_true_with_credentials(monkeypatch):
    monkeypatch.setattr(emailer, "SMTP_USERNAME", "bot@example.test")
    monkeypatch.setattr(emailer, "SMTP_PASSWORD", "app-password")
    assert emailer.is_configured() is True


def test_send_report_email_skips_when_not_configured(monkeypatch):
    monkeypatch.setattr(emailer, "SMTP_USERNAME", "")
    monkeypatch.setattr(emailer, "SMTP_PASSWORD", "")
    with patch("smtplib.SMTP") as smtp_cls:
        result = emailer.send_report_email(
            "lead@example.test", "example.test", "B", 82, "https://x.test/report/abc",
        )
        assert result is False
        smtp_cls.assert_not_called()


def test_send_report_email_sends_via_smtp_when_configured(monkeypatch):
    monkeypatch.setattr(emailer, "SMTP_USERNAME", "bot@example.test")
    monkeypatch.setattr(emailer, "SMTP_PASSWORD", "app-password")
    monkeypatch.setattr(emailer, "SMTP_FROM", "bot@example.test")

    mock_server = MagicMock()
    mock_server.__enter__.return_value = mock_server
    with patch("smtplib.SMTP", return_value=mock_server) as smtp_cls:
        result = emailer.send_report_email(
            "lead@example.test", "example.test", "B", 82, "https://x.test/report/abc",
            pdf_bytes=b"%PDF-fake",
        )

    assert result is True
    smtp_cls.assert_called_once_with(emailer.SMTP_HOST, emailer.SMTP_PORT, timeout=15)
    mock_server.starttls.assert_called_once()
    mock_server.login.assert_called_once_with("bot@example.test", "app-password")
    mock_server.send_message.assert_called_once()
    sent_msg = mock_server.send_message.call_args[0][0]
    assert sent_msg["To"] == "lead@example.test"
    assert "example.test" in sent_msg["Subject"]
    assert sent_msg.is_multipart()  # has the PDF attachment


def test_send_report_email_without_pdf_still_sends(monkeypatch):
    monkeypatch.setattr(emailer, "SMTP_USERNAME", "bot@example.test")
    monkeypatch.setattr(emailer, "SMTP_PASSWORD", "app-password")

    mock_server = MagicMock()
    mock_server.__enter__.return_value = mock_server
    with patch("smtplib.SMTP", return_value=mock_server):
        result = emailer.send_report_email(
            "lead@example.test", "example.test", "B", 82, "https://x.test/report/abc",
        )
    assert result is True


def test_send_report_email_returns_false_on_smtp_error(monkeypatch):
    monkeypatch.setattr(emailer, "SMTP_USERNAME", "bot@example.test")
    monkeypatch.setattr(emailer, "SMTP_PASSWORD", "app-password")

    with patch("smtplib.SMTP", side_effect=OSError("connection refused")):
        result = emailer.send_report_email(
            "lead@example.test", "example.test", "B", 82, "https://x.test/report/abc",
        )
    assert result is False
