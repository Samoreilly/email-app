"""Inbound: a contact writes to you@yourdomain.com; we deliver it to Gmail.

The message reaches Gmail "from" a per-contact reverse alias on our relay
domain, so hitting Reply in any Gmail app sends the reply back through us.
"""

import asyncio
import logging
from dataclasses import dataclass

from email.utils import formatdate
from sqlalchemy.orm import Session

from app.config import get_settings
from app.mailer import Transport
from app.models import Address, Domain, User
from app.relay import auth, keys
from app.relay.contacts import get_or_create_contact, log_delivery, lookup_ids
from app.relay.message import (
    RawMessage,
    domain_of,
    format_address,
    format_address_list,
    normalize_mailbox,
    parse_address,
    parse_addresses,
    parse_msgids,
)

log = logging.getLogger(__name__)

MAX_HOPS = 40


@dataclass
class Envelope:
    mail_from: str
    rcpts: list[str]
    peer_ip: str | None = None
    helo: str | None = None


@dataclass
class Outcome:
    code: int
    message: str
    status: str  # delivered / deferred / rejected / dropped / accepted

    @property
    def smtp(self) -> str:
        return f"{self.code} {self.message}"


def contact_display_name(name: str, email: str) -> str:
    """'Jane Doe - jane at example.com': shows who it's from without putting a
    second, spoofable-looking address in the display name."""
    shown = email.replace("@", " at ")
    return f"{name} - {shown}" if name else shown


def _user_domains(user: User) -> set[str]:
    return {d.name for d in user.domains}


async def relay_inbound(
    db: Session,
    raw: bytes,
    env: Envelope,
    user: User,
    domain: Domain,
    address: Address | None,
    rcpt: str,
    transport: Transport,
    dnsfunc: auth.DnsFunc = None,
) -> Outcome:
    s = get_settings()
    msg = RawMessage.parse(raw)

    if len(msg.get_all("Received")) > MAX_HOPS:
        return Outcome(554, "5.4.6 Mail loop detected", "rejected")

    results = await asyncio.to_thread(
        auth.authenticate, raw, s.smtp_hostname, env.peer_ip, env.helo, env.mail_from, dnsfunc
    )
    if s.enforce_inbound_dmarc_reject and auth.dmarc_reject(results):
        log_delivery(db, user, "in", "rejected", address=rcpt, detail="DMARC failed (p=reject)")
        return Outcome(550, "5.7.1 Message rejected: sender's DMARC policy is reject", "rejected")

    from_name, from_addr = parse_address(msg.get("From"))
    if not from_addr:
        from_addr = env.mail_from.lower()
    if not from_addr or "@" not in from_addr:
        # Null sender (a bounce) with no usable From: deliver as from the relay.
        from_addr = f"mailer-daemon@{s.relay_domain}"

    # A reply-all from the customer's own Gmail also lands on their custom
    # address. They already have it in Sent, so drop the copy.
    if normalize_mailbox(from_addr) == normalize_mailbox(user.email):
        dkim_ok = await asyncio.to_thread(auth.has_aligned_dkim_pass, raw, from_addr, dnsfunc)
        if dkim_ok:
            log_delivery(db, user, "in", "dropped", address=rcpt, detail="Copy of your own reply")
            return Outcome(250, "2.0.0 OK", "dropped")

    if address is None:  # catch-all or postmaster@: create the address record.
        local = rcpt.rpartition("@")[0]
        address = Address(domain=domain, local_part=local)
        db.add(address)
        db.flush()

    contact, created = get_or_create_contact(db, address, from_addr, from_name)
    if contact.blocked:
        log_delivery(db, user, "in", "dropped", address=address.email, contact=from_addr,
                     detail="Sender is blocked")  # fmt: skip
        return Outcome(250, "2.0.0 OK", "dropped")

    own = _user_domains(user)

    def alias_for(name: str, addr: str) -> tuple[str, str]:
        d = domain_of(addr)
        if d in own or d == s.relay_domain.lower() or normalize_mailbox(addr) == normalize_mailbox(user.email):
            return name, addr
        c, _ = get_or_create_contact(db, address, addr, name)
        return contact_display_name(name, addr), c.reverse_alias

    # --- rewrite headers --------------------------------------------------
    msg.set("From", format_address(contact_display_name(from_name, from_addr), contact.reverse_alias))
    if msg.has("Reply-To"):
        msg.set("Reply-To", format_address_list([alias_for(n, a) for n, a in parse_addresses(msg.get("Reply-To"))]))
    for h in ("To", "Cc"):
        if msg.has(h):
            msg.set(h, format_address_list([alias_for(n, a) for n, a in parse_addresses(msg.get(h))]))

    # Threads: map ids we published back to the ids Gmail knows.
    ids = parse_msgids(msg.get("In-Reply-To")) + parse_msgids(msg.get("References"))
    mapping = lookup_ids(db, user, ids, to_public=False)
    if mapping:
        for h in ("In-Reply-To", "References"):
            v = msg.get(h)
            if v:
                for pub, priv in mapping.items():
                    v = v.replace(pub, priv)
                msg.set(h, v)

    # The original signatures no longer verify after our changes; ARC carries
    # the original results forward instead.
    msg.remove("DKIM-Signature")
    msg.remove("Sender")
    msg.remove("Return-Path")
    msg.remove("Delivered-To")
    msg.remove_matching(lambda n: n == "authentication-results" or n == "x-original-to")
    lu = msg.get("List-Unsubscribe")
    if lu and "mailto:" in lu.lower():
        # A mailto: unsubscribe would be sent straight from Gmail and leak the
        # Gmail address. Keep only http(s) links.
        https = [p for p in lu.split(",") if "http" in p.lower()]
        if https:
            msg.set("List-Unsubscribe", ",".join(p.strip() for p in https))
        else:
            msg.remove("List-Unsubscribe")
            msg.remove("List-Unsubscribe-Post")

    msg.prepend("Authentication-Results", results)
    msg.prepend(
        "Received",
        f"from {env.helo or 'unknown'} ({env.peer_ip or 'unknown'}) by {s.smtp_hostname} "
        f"with ESMTP for <{address.email}>; {formatdate()}",
    )

    pem = keys.relay_private_key()
    data = auth.sign_message(msg, s.relay_domain, s.relay_dkim_selector, pem, arc_srv_id=s.smtp_hostname)

    entry = log_delivery(db, user, "in", "pending", address=address.email, contact=from_addr, size=len(raw))
    from app.relay.bounces import bounce_address

    result = await transport.send(bounce_address(entry.id, s.relay_domain), [user.email], data)
    r = result.results[user.email]
    if r.ok:
        entry.status = "delivered"
        return Outcome(250, "2.0.0 Delivered", "delivered")
    entry.detail = f"{r.code} {r.message}"[:500]
    if r.permanent:
        entry.status = "rejected"
        return Outcome(550, "5.0.0 Delivery to the final mailbox failed", "rejected")
    entry.status = "deferred"
    return Outcome(451, "4.4.0 Temporary failure forwarding, try again later", "deferred")
