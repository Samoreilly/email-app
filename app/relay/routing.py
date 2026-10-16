"""Decide what each envelope recipient is. Anything we don't recognise is
refused: this server must never act as an open relay."""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Address, Contact, Domain, User
from app.relay.contacts import contact_by_reverse_alias
from app.relay.message import domain_of, local_of

OPERATOR_LOCALS = {"postmaster", "abuse"}


@dataclass
class Route:
    kind: str  # "inbound" | "reply" | "bounce" | "operator"
    rcpt: str
    user: User | None = None
    address: Address | None = None  # inbound
    domain: Domain | None = None  # inbound (catch-all may not have an address yet)
    contact: Contact | None = None  # reply
    bounce_ref: str = ""


class Refused(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message

    @property
    def smtp(self) -> str:
        return f"{self.code} {self.message}"


def classify(db: Session, rcpt: str) -> Route:
    s = get_settings()
    rcpt = rcpt.strip().lower()
    local, domain = local_of(rcpt), domain_of(rcpt)
    if not local or not domain:
        raise Refused(501, "5.1.3 Bad recipient address syntax")

    if local.startswith("bounce+"):
        if domain == s.relay_domain.lower() or _customer_domain(db, domain):
            return Route("bounce", rcpt, bounce_ref=local.removeprefix("bounce+"))
        raise Refused(550, "5.7.1 Relaying denied")

    if domain == s.relay_domain.lower():
        if local in OPERATOR_LOCALS:
            return Route("operator", rcpt)
        contact = contact_by_reverse_alias(db, rcpt)
        if contact is None:
            raise Refused(550, "5.1.1 No such alias")
        user = contact.address.domain.user
        if not contact.address.enabled:
            raise Refused(550, "5.2.1 This address is disabled in your dashboard")
        if not user.can_send:
            raise Refused(
                550,
                f"5.7.1 Your {s.app_name} plan is not active, so replies are paused. "
                f"Visit {s.base_url}/billing",
            )
        return Route("reply", rcpt, user=user, contact=contact, address=contact.address)

    dom = _customer_domain(db, domain)
    if dom is None:
        raise Refused(550, "5.7.1 Relaying denied")
    user = dom.user
    address = db.scalar(
        select(Address).where(Address.domain_id == dom.id, Address.local_part == local)
    )
    if address is not None and not address.enabled:
        raise Refused(550, "5.1.1 Mailbox unavailable")
    if address is None and not (dom.catch_all or local in OPERATOR_LOCALS):
        raise Refused(550, "5.1.1 No such user here")
    if not user.can_receive:
        raise Refused(550, "5.2.1 Mailbox disabled")
    return Route("inbound", rcpt, user=user, address=address, domain=dom)


def _customer_domain(db: Session, name: str) -> Domain | None:
    return db.scalar(select(Domain).where(Domain.name == name, Domain.verified_at.is_not(None)))
