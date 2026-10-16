import email
from email import policy

import pytest
from sqlalchemy import select

from app.mailer import RcptResult
from app.models import Contact, DeliveryLog, MessageIdMap, Suppression
from app.relay.inbound import Envelope
from app.relay.pipeline import process
from app.relay.routing import Refused, classify


def inbound_raw(frm="Bob Smith <bob@contact.net>", to="alice@example.org", msgid="<orig-1@contact.net>", extra=""):
    return (
        f"From: {frm}\r\nTo: {to}\r\nSubject: Quote request\r\n"
        f"Message-ID: {msgid}\r\nDate: Thu, 15 Oct 2026 10:00:00 +0000\r\n"
        f"DKIM-Signature: v=1; a=rsa-sha256; d=contact.net; s=x; b=abc\r\n{extra}"
        "Content-Type: text/plain; charset=utf-8\r\n\r\nHi Alice,\r\nCan you quote?\r\n"
    ).encode()


def parse(data: bytes):
    return email.message_from_bytes(data, policy=policy.default)


async def test_unknown_recipient_is_refused(session, account):
    with pytest.raises(Refused) as e:
        classify(session, "someone@gmail.com")
    assert e.value.code == 550  # never an open relay
    with pytest.raises(Refused):
        classify(session, "nobody@example.org")
    with pytest.raises(Refused):
        classify(session, "r-doesnotexist@relay.test")


async def test_inbound_rewrites_from_to_reverse_alias(session, account, transport, dns):
    out = await process(session, inbound_raw(), Envelope("bob@contact.net", ["alice@example.org"]), transport, dns)
    assert out.code == 250, out
    mail_from, rcpts, data = transport.sent[0]
    assert rcpts == ["customer@gmail.com"]
    assert mail_from.startswith("bounce+") and mail_from.endswith("@relay.test")
    m = parse(data)
    contact = session.scalar(select(Contact))
    assert contact.email == "bob@contact.net"
    assert m["From"].addresses[0].addr_spec == contact.reverse_alias
    assert "bob at contact.net" in m["From"].addresses[0].display_name
    assert m["To"].addresses[0].addr_spec == "alice@example.org"
    assert m["Message-ID"] == "<orig-1@contact.net>"
    assert data.startswith(b"DKIM-Signature:")
    assert b"d=relay.test" in data.split(b"\r\n\r\n")[0]
    assert len(m.get_all("DKIM-Signature")) == 1  # original (now broken) signature removed
    assert "ARC-Seal" in m
    assert "Authentication-Results" in m
    assert m.get_content().startswith("Hi Alice")
    log = session.scalar(select(DeliveryLog))
    assert (log.direction, log.status) == ("in", "delivered")


async def test_inbound_cc_and_reply_to_become_aliases(session, account, transport, dns):
    raw = inbound_raw(extra="Cc: Carol <carol@other.net>, alice@example.org\r\nReply-To: sales@contact.net\r\n")
    await process(session, raw, Envelope("bob@contact.net", ["alice@example.org"]), transport, dns)
    m = parse(transport.sent[0][2])
    cc = [a.addr_spec for a in m["Cc"].addresses]
    assert "alice@example.org" in cc
    assert all(a.endswith("@relay.test") or a == "alice@example.org" for a in cc)
    assert m["Reply-To"].addresses[0].addr_spec.startswith("r-")
    assert session.scalar(select(Contact).where(Contact.email == "carol@other.net"))


async def test_inbound_temp_failure_returns_451(session, account, transport, dns):
    transport.fail["customer@gmail.com"] = RcptResult(421, "try later")
    out = await process(session, inbound_raw(), Envelope("bob@contact.net", ["alice@example.org"]), transport, dns)
    assert out.code == 451  # sender's server keeps the message and retries


def gmail_reply(contact, extra="", frm="Cust <customer@gmail.com>", msgid="<CAgmail123@mail.gmail.com>"):
    return (
        f"From: {frm}\r\nTo: {contact.reverse_alias}\r\nSubject: Re: Quote request\r\n"
        f"Message-ID: {msgid}\r\nDate: Thu, 15 Oct 2026 11:00:00 +0000\r\n"
        "In-Reply-To: <orig-1@contact.net>\r\nReferences: <orig-1@contact.net>\r\n"
        f"X-Gm-Message-State: abc\r\nReceived: by 2002:a05 with SMTP id x; Thu\r\n{extra}"
        "Content-Type: text/plain; charset=utf-8\r\n\r\n"
        f"Sure, it's 100 EUR.\r\n\r\nOn Thu, Bob <{contact.reverse_alias}> wrote:\r\n> Can you quote?\r\n"
    ).encode()


async def _make_contact(session, account, transport, dns):
    await process(session, inbound_raw(), Envelope("bob@contact.net", ["alice@example.org"]), transport, dns)
    transport.sent.clear()
    return session.scalar(select(Contact).where(Contact.email == "bob@contact.net"))


async def test_reply_goes_out_as_custom_domain(session, account, transport, dns, gmail_key):
    contact = await _make_contact(session, account, transport, dns)
    raw = gmail_key(gmail_reply(contact))
    out = await process(session, raw, Envelope("customer@gmail.com", [contact.reverse_alias]), transport, dns)
    assert out.code == 250, out
    mail_from, rcpts, data = transport.sent[0]
    assert rcpts == ["bob@contact.net"]
    assert mail_from.endswith("@example.org")
    assert b"gmail" not in data.lower()  # nothing leaks the Gmail address or Gmail ids
    assert contact.reverse_alias.encode() not in data  # alias replaced in the quote too
    m = parse(data)
    assert m["From"].addresses[0].addr_spec == "alice@example.org"
    assert m["From"].addresses[0].display_name == "Alice Example"
    assert m["To"].addresses[0].addr_spec == "bob@contact.net"
    assert m["In-Reply-To"] == "<orig-1@contact.net>"
    assert m["Message-ID"].endswith("@example.org>")
    assert "X-Gm-Message-State" not in m
    assert b"d=example.org" in data.split(b"\r\n\r\n")[0]
    assert "bob@contact.net" in m.get_content()
    row = session.scalar(select(MessageIdMap))
    assert row.private_id == "<CAgmail123@mail.gmail.com>" and row.public_id == m["Message-ID"]


async def test_thread_ids_map_back_on_next_inbound(session, account, transport, dns, gmail_key):
    contact = await _make_contact(session, account, transport, dns)
    raw = gmail_key(gmail_reply(contact))
    await process(session, raw, Envelope("customer@gmail.com", [contact.reverse_alias]), transport, dns)
    public_id = parse(transport.sent[0][2])["Message-ID"]
    transport.sent.clear()
    raw2 = inbound_raw(msgid="<orig-2@contact.net>", extra=f"In-Reply-To: {public_id}\r\nReferences: <orig-1@contact.net> {public_id}\r\n")
    await process(session, raw2, Envelope("bob@contact.net", ["alice@example.org"]), transport, dns)
    m = parse(transport.sent[0][2])
    assert m["In-Reply-To"] == "<CAgmail123@mail.gmail.com>"


async def test_reply_from_wrong_sender_is_rejected(session, account, transport, dns, gmail_key):
    contact = await _make_contact(session, account, transport, dns)
    raw = gmail_key(gmail_reply(contact, frm="Mallory <mallory@gmail.com>"))
    out = await process(session, raw, Envelope("mallory@gmail.com", [contact.reverse_alias]), transport, dns)
    assert out.code == 550
    assert transport.sent == []


async def test_reply_without_valid_dkim_is_rejected(session, account, transport, dns):
    contact = await _make_contact(session, account, transport, dns)
    out = await process(session, gmail_reply(contact), Envelope("customer@gmail.com", [contact.reverse_alias]), transport, dns)
    assert out.code == 550 and "DKIM" in out.message
    assert transport.sent == []


async def test_reply_blocked_when_plan_inactive(session, account, transport, dns):
    from datetime import timedelta

    from app.db import utcnow

    contact = await _make_contact(session, account, transport, dns)
    account.trial_ends_at = utcnow() - timedelta(days=1)
    session.commit()
    with pytest.raises(Refused) as e:
        classify(session, contact.reverse_alias)
    assert "billing" in e.value.message


async def test_daily_limit(session, account, transport, dns, gmail_key, monkeypatch):
    monkeypatch.setenv("DAILY_SEND_LIMIT", "1")
    from app import config
    config.get_settings.cache_clear()
    contact = await _make_contact(session, account, transport, dns)
    env = Envelope("customer@gmail.com", [contact.reverse_alias])
    assert (await process(session, gmail_key(gmail_reply(contact)), env, transport, dns)).code == 250
    out = await process(session, gmail_key(gmail_reply(contact, msgid="<CA2@mail.gmail.com>")), env, transport, dns)
    assert out.code == 550 and "limit" in out.message


async def test_hard_bounce_suppresses(session, account, transport, dns, gmail_key):
    contact = await _make_contact(session, account, transport, dns)
    transport.fail["bob@contact.net"] = RcptResult(550, "5.1.1 user unknown")
    out = await process(session, gmail_key(gmail_reply(contact)), Envelope("customer@gmail.com", [contact.reverse_alias]), transport, dns)
    assert out.code == 550
    assert session.scalar(select(Suppression).where(Suppression.email == "bob@contact.net"))


async def test_async_dsn_bounce(session, account, transport, dns, gmail_key):
    contact = await _make_contact(session, account, transport, dns)
    await process(session, gmail_key(gmail_reply(contact)), Envelope("customer@gmail.com", [contact.reverse_alias]), transport, dns)
    bounce_to = transport.sent[0][0]
    dsn = (
        "From: MAILER-DAEMON@contact.net\r\nTo: " + bounce_to + "\r\nSubject: Undelivered\r\n"
        'MIME-Version: 1.0\r\nContent-Type: multipart/report; report-type=delivery-status; boundary="b"\r\n\r\n'
        "--b\r\nContent-Type: text/plain\r\n\r\nfailed\r\n"
        "--b\r\nContent-Type: message/delivery-status\r\n\r\nReporting-MTA: dns; mx.contact.net\r\n\r\n"
        "Final-Recipient: rfc822; bob@contact.net\r\nAction: failed\r\nStatus: 5.1.1\r\n\r\n--b--\r\n"
    ).encode()
    out = await process(session, dsn, Envelope("", [bounce_to]), transport, dns)
    assert out.code == 250
    assert session.scalar(select(Suppression).where(Suppression.email == "bob@contact.net"))
    assert session.scalar(select(DeliveryLog).where(DeliveryLog.status == "bounced"))


async def test_forged_bounce_ref_ignored(session, account, transport, dns):
    from app.relay.bounces import parse_bounce_ref
    assert parse_bounce_ref("12-aaaaaaaa") is None


async def test_reply_all_self_copy_dropped(session, account, transport, dns, gmail_key):
    raw = gmail_key(
        b"From: Cust <customer@gmail.com>\r\nTo: alice@example.org\r\nSubject: x\r\n"
        b"Message-ID: <CAx@mail.gmail.com>\r\nDate: Thu, 15 Oct 2026 11:00:00 +0000\r\n\r\nhi\r\n"
    )
    out = await process(session, raw, Envelope("customer@gmail.com", ["alice@example.org"]), transport, dns)
    assert out.code == 250 and out.status == "dropped"
    assert transport.sent == []


async def test_compose_sends_and_copies_to_gmail(session, account, transport):
    from app.relay.outbound import compose
    from app.models import Address

    addr = session.scalar(select(Address))
    out = await compose(session, account, addr, "new@client.com", "New Client", "Hello", "Body text", transport)
    assert out.code == 250, out
    (f1, r1, d1), (f2, r2, d2) = transport.sent
    assert r1 == ["new@client.com"] and r2 == ["customer@gmail.com"]
    m1, m2 = parse(d1), parse(d2)
    assert m1["Message-ID"] == m2["Message-ID"]
    assert m2["Reply-To"].addresses[0].addr_spec.startswith("r-")
    contact = session.scalar(select(Contact).where(Contact.email == "new@client.com"))
    assert contact.origin == "manual"
