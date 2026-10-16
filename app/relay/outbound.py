"""Outbound: the customer replies in Gmail; we send it as you@yourdomain.com.

Security model: a reverse alias only relays mail that (1) has a From address
equal to the account's registered Gmail address and (2) carries a valid DKIM
signature from that address's domain. Anything else is refused, so the relay
can't be abused by someone who learns an alias.
"""

import asyncio
import email
import logging
import re
from email import policy
from email.message import EmailMessage
from email.utils import formatdate

from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import utcnow
from app.mailer import DeliveryResult, Transport
from app.models import Address, Contact, User
from app.relay import auth, keys
from app.relay.bounces import bounce_address
from app.relay.contacts import (
    LimitExceeded,
    check_send_limit,
    contact_by_reverse_alias,
    get_or_create_contact,
    is_suppressed,
    log_delivery,
    lookup_ids,
    map_private_ids,
)
from app.relay.inbound import Envelope, Outcome, contact_display_name
from app.relay.message import (
    RawMessage,
    format_address,
    format_address_list,
    make_msgid,
    normalize_mailbox,
    parse_address,
    parse_addresses,
    parse_msgids,
)

log = logging.getLogger(__name__)

# Headers that describe the Gmail side of the trip.
_STRIP_EXACT = {
    "received", "x-received", "dkim-signature", "authentication-results", "return-path",
    "delivered-to", "sender", "received-spf", "bcc", "disposition-notification-to",
    "return-receipt-to", "x-originating-ip",
}  # fmt: skip
_STRIP_PREFIX = ("x-gm-", "x-google-", "x-gmail-", "arc-")


def _strip(name: str) -> bool:
    return name in _STRIP_EXACT or name.startswith(_STRIP_PREFIX)


def _replace_ci(text: str, replacements: dict[str, str]) -> str:
    for old, new in replacements.items():
        text = re.sub(re.escape(old), new.replace("\\", r"\\"), text, flags=re.IGNORECASE)
    return text


def rewrite_body(raw: bytes, replacements: dict[str, str]) -> bytes:
    """Replace addresses in text parts (e.g. the "On ..., X <r-..> wrote:"
    quote line, or a signature with the Gmail address). Signed/encrypted mail
    is left alone; on any parsing trouble the original is returned."""
    try:
        msg = email.message_from_bytes(raw, policy=policy.default)
        if msg.get_content_type() in ("multipart/signed", "multipart/encrypted"):
            return raw
        changed = False
        for part in msg.walk():
            if part.is_multipart() or part.get_content_disposition() == "attachment":
                continue
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            text = part.get_content()
            new = _replace_ci(text, replacements)
            if new != text:
                cte = (part.get("Content-Transfer-Encoding") or "").lower()
                part.set_content(
                    new,
                    subtype=ctype.split("/")[1],
                    charset="utf-8",
                    cte="base64" if cte == "base64" else "quoted-printable",
                )
                changed = True
        if not changed:
            return raw
        return msg.as_bytes(policy=policy.SMTP)
    except Exception as exc:
        log.info("body rewrite skipped: %s", exc)
        return raw


def _apply_outcome(result: DeliveryResult, entries: dict[str, object], db: Session) -> Outcome:
    from app.relay.contacts import suppress

    for rcpt, r in result.results.items():
        entry = entries.get(rcpt)
        if r.ok:
            entry.status = "delivered"
        else:
            entry.status = "rejected" if r.permanent else "deferred"
            entry.detail = f"{r.code} {r.message}"[:500]
            if r.permanent and re.search(r"\b5\.1\.[0-9]\b", r.message):
                suppress(db, rcpt, "bounce", f"{r.code} {r.message}")
    if result.all_ok:
        return Outcome(250, "2.0.0 Sent", "delivered")
    if result.any_ok:
        return Outcome(250, "2.0.0 Sent to some recipients; see your dashboard log", "delivered")
    if result.all_permanent_fail:
        first = next(iter(result.results.values()))
        return Outcome(550, f"5.0.0 The recipient's server refused it: {first.code} {first.message[:200]}", "rejected")  # fmt: skip
    return Outcome(451, "4.4.0 Temporary delivery failure, will retry", "deferred")


async def _sign_and_send(
    db: Session,
    msg: RawMessage,
    user: User,
    address: Address,
    contacts: list[Contact],
    direction: str,
    transport: Transport,
    size: int,
) -> Outcome:
    domain = address.domain
    data = auth.sign_message(msg, domain.name, domain.dkim_selector, keys.domain_private_key(domain))
    entries = {}
    for c in contacts:
        entries[c.email] = log_delivery(
            db, user, direction, "pending", address=address.email, contact=c.email, size=size
        )
        c.last_used_at = utcnow()
    first = next(iter(entries.values()))
    result = await transport.send(
        bounce_address(first.id, domain.name), [c.email for c in contacts], data
    )
    return _apply_outcome(result, entries, db)


async def relay_reply(
    db: Session,
    raw: bytes,
    env: Envelope,
    user: User,
    contacts: list[Contact],
    transport: Transport,
    dnsfunc: auth.DnsFunc = None,
) -> Outcome:
    s = get_settings()
    msg = RawMessage.parse(raw)

    # --- sender verification -----------------------------------------------
    _, from_addr = parse_address(msg.get("From"))
    if normalize_mailbox(from_addr) != normalize_mailbox(user.email):
        log_delivery(db, user, "out", "rejected", detail="Sender is not the account's Gmail address")
        return Outcome(550, "5.7.1 Sender not allowed to use this alias", "rejected")
    if s.require_dkim_on_replies:
        ok = await asyncio.to_thread(auth.has_aligned_dkim_pass, raw, from_addr, dnsfunc)
        if not ok:
            log_delivery(db, user, "out", "rejected", detail="DKIM check failed on reply")
            return Outcome(550, "5.7.1 Sender authentication (DKIM) failed", "rejected")

    address = contacts[0].address
    if any(c.address.domain.user_id != user.id for c in contacts):
        return Outcome(550, "5.7.1 Recipients belong to different accounts", "rejected")
    if not address.domain.sending_ready:
        log_delivery(db, user, "out", "rejected", address=address.email, detail="DKIM record not verified")
        return Outcome(550, f"5.7.1 {address.domain.name} isn't verified for sending yet; finish DNS setup in your dashboard", "rejected")  # fmt: skip

    live = []
    for c in contacts:
        sup = is_suppressed(db, c.email)
        if sup:
            log_delivery(db, user, "out", "rejected", address=address.email, contact=c.email,
                         detail=f"Recipient suppressed ({sup.reason})")  # fmt: skip
        else:
            live.append(c)
    if not live:
        return Outcome(550, "5.1.1 Recipient previously bounced or complained; not sending", "rejected")
    try:
        check_send_limit(db, user, len(live))
    except LimitExceeded as exc:
        log_delivery(db, user, "out", "rejected", address=address.email, detail=str(exc))
        return Outcome(550, f"5.7.1 {exc}", "rejected")

    # --- body: swap reverse aliases for real addresses ---------------------
    replacements = {c.reverse_alias: c.email for c in contacts}
    replacements[user.email] = address.email
    raw = rewrite_body(raw, replacements)
    msg = RawMessage.parse(raw)

    # --- headers -----------------------------------------------------------
    gmail_name, _ = parse_address(msg.get("From"))
    msg.remove_matching(_strip)
    msg.set("From", format_address(address.display_name or gmail_name, address.email))

    def real(items):
        out = []
        for name, addr in items:
            if normalize_mailbox(addr) == normalize_mailbox(user.email):
                continue
            c = contact_by_reverse_alias(db, addr)
            if c is not None and c.address.domain.user_id == user.id:
                out.append((c.name, c.email))
            elif c is None:
                out.append((name, addr))
        return out

    for h in ("To", "Cc"):
        if msg.has(h):
            items = real(parse_addresses(msg.get(h)))
            if items:
                msg.set(h, format_address_list(items))
            else:
                msg.remove(h)
    if not msg.has("To"):
        msg.set("To", format_address_list([(c.name, c.email) for c in live]))
    if msg.has("Reply-To"):
        items = real(parse_addresses(msg.get("Reply-To")))
        if items:
            msg.set("Reply-To", format_address_list(items))
        else:
            msg.remove("Reply-To")

    private_id = (parse_msgids(msg.get("Message-ID")) or [make_msgid("mail.gmail.com")])[0]
    public_id = map_private_ids(db, user, [private_id], address.domain.name)[private_id]
    msg.set("Message-ID", public_id)
    refs = parse_msgids(msg.get("In-Reply-To")) + parse_msgids(msg.get("References"))
    mapping = lookup_ids(db, user, refs, to_public=True)
    for h in ("In-Reply-To", "References"):
        v = msg.get(h)
        if v and mapping:
            for priv, pub in mapping.items():
                v = v.replace(priv, pub)
            msg.set(h, v)

    # Anything left that still mentions the Gmail address.
    for i, (name, field) in enumerate(msg.headers):
        if user.email.encode() in field.lower():
            value = field.decode("utf-8", "replace").split(":", 1)[1].strip()
            msg.headers[i] = (name, f"{name}: {_replace_ci(value, {user.email: address.email})}\r\n".encode())

    msg.prepend("Received", f"by {s.smtp_hostname} with ESMTPSA; {formatdate()}")
    return await _sign_and_send(db, msg, user, address, live, "out", transport, len(raw))


async def compose(
    db: Session,
    user: User,
    address: Address,
    to_email: str,
    to_name: str,
    subject: str,
    body: str,
    transport: Transport,
) -> Outcome:
    """Send a brand-new message from the web compose page, and put a copy in
    the customer's Gmail that they can reply to (via the reverse alias)."""
    if not user.can_send:
        return Outcome(550, "Your plan isn't active. Subscribe on the Billing page to send.", "rejected")
    if not address.domain.sending_ready:
        return Outcome(550, f"Finish DNS setup for {address.domain.name} first.", "rejected")
    if is_suppressed(db, to_email):
        return Outcome(550, f"{to_email} previously bounced or complained, so we won't send to it.", "rejected")  # fmt: skip
    try:
        check_send_limit(db, user, 1)
        contact, _ = get_or_create_contact(db, address, to_email, to_name, origin="manual")
    except LimitExceeded as exc:
        return Outcome(550, str(exc), "rejected")

    msgid = make_msgid(address.domain.name)
    em = EmailMessage()
    em["From"] = format_address(address.display_name, address.email)
    em["To"] = format_address(contact.name, contact.email)
    em["Subject"] = subject
    em["Date"] = formatdate()
    em["Message-ID"] = msgid
    em.set_content(body)
    outcome = await _sign_and_send(
        db, RawMessage.parse(em.as_bytes(policy=policy.SMTP)), user, address, [contact],
        "compose", transport, len(body),
    )  # fmt: skip
    if outcome.status != "delivered":
        return outcome

    # Copy for the customer's Gmail. Same Message-ID, so the contact's answer
    # threads with it; Reply-To is the reverse alias so replying works.
    copy = EmailMessage()
    copy["From"] = format_address(address.display_name, address.email)
    copy["To"] = format_address(contact_display_name(contact.name, contact.email), contact.reverse_alias)
    copy["Reply-To"] = format_address(contact_display_name(contact.name, contact.email), contact.reverse_alias)
    copy["Subject"] = subject
    copy["Date"] = em["Date"]
    copy["Message-ID"] = msgid
    copy.set_content(body)
    # Signed with the customer's own domain key so it passes DMARC at Gmail.
    domain = address.domain
    data = auth.sign_message(
        RawMessage.parse(copy.as_bytes(policy=policy.SMTP)),
        domain.name, domain.dkim_selector, keys.domain_private_key(domain),
    )  # fmt: skip
    await transport.send(f"bounce+sys@{get_settings().relay_domain}", [user.email], data)
    return outcome
