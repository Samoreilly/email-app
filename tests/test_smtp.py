"""End-to-end through a real SMTP socket."""

import smtplib

import pytest

from app.relay import auth
from app.relay.server import RelayController, RelayHandler


@pytest.fixture
def smtp_server(monkeypatch):
    monkeypatch.setattr(auth, "authenticate", lambda *a, **k: "mx.relay.test; spf=none")
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    c = RelayController(RelayHandler(), hostname="127.0.0.1", port=port)
    c.start()
    yield port
    c.stop()


def test_smtp_inbound_and_open_relay_refusal(smtp_server, account, transport):
    with smtplib.SMTP("127.0.0.1", smtp_server) as s:
        s.ehlo("mx.contact.net")
        with pytest.raises(smtplib.SMTPRecipientsRefused):
            s.sendmail("bob@contact.net", ["victim@gmail.com"], b"Subject: x\r\n\r\nspam\r\n")
    with smtplib.SMTP("127.0.0.1", smtp_server) as s:
        s.sendmail(
            "bob@contact.net",
            ["alice@example.org"],
            b"From: Bob <bob@contact.net>\r\nTo: alice@example.org\r\nSubject: hi\r\n"
            b"Message-ID: <a@contact.net>\r\n\r\nhello\r\n",
        )
    assert transport.sent[-1][1] == ["customer@gmail.com"]
