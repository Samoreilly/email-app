"""Contacts (reverse aliases), suppression and limits, shared by the relay and
the web dashboard."""

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import utcnow
from app.models import Address, Contact, DeliveryLog, Domain, MessageIdMap, Suppression, User


class LimitExceeded(Exception):
    pass


def get_or_create_contact(
    db: Session, address: Address, email: str, name: str = "", origin: str = "inbound"
) -> tuple[Contact, bool]:
    email = email.strip().lower()
    contact = db.scalar(
        select(Contact).where(Contact.address_id == address.id, Contact.email == email)
    )
    if contact:
        if name and not contact.name:
            contact.name = name[:200]
        return contact, False
    if origin == "manual":
        check_new_contact_limit(db, address.domain.user)
    contact = Contact(address=address, email=email, name=name[:200], origin=origin)
    db.add(contact)
    db.flush()
    return contact, True


def contact_by_token(db: Session, token: str) -> Contact | None:
    return db.scalar(select(Contact).where(Contact.token == token.lower()))


def contact_by_reverse_alias(db: Session, addr: str) -> Contact | None:
    local, _, domain = addr.lower().rpartition("@")
    if domain != get_settings().relay_domain.lower() or not local.startswith("r-"):
        return None
    return contact_by_token(db, local[2:])


def is_suppressed(db: Session, email: str) -> Suppression | None:
    return db.scalar(select(Suppression).where(Suppression.email == email.lower()))


def suppress(db: Session, email: str, reason: str, detail: str = "") -> None:
    email = email.strip().lower()
    if not email or is_suppressed(db, email):
        return
    db.add(Suppression(email=email, reason=reason, detail=detail[:500]))
    db.flush()


def sent_last_24h(db: Session, user: User) -> int:
    since = utcnow() - timedelta(hours=24)
    return db.scalar(
        select(func.count(DeliveryLog.id)).where(
            DeliveryLog.user_id == user.id,
            DeliveryLog.direction.in_(("out", "compose")),
            DeliveryLog.status == "delivered",
            DeliveryLog.created_at >= since,
        )
    )


def daily_limit(user: User) -> int:
    return user.daily_send_limit or get_settings().daily_send_limit


def check_send_limit(db: Session, user: User, n_recipients: int) -> None:
    s = get_settings()
    if n_recipients > s.max_recipients_per_message:
        raise LimitExceeded(
            f"Too many recipients ({n_recipients}); the limit is {s.max_recipients_per_message} "
            "per message. Bulk sending isn't allowed."
        )
    if sent_last_24h(db, user) + n_recipients > daily_limit(user):
        raise LimitExceeded(
            f"Daily sending limit of {daily_limit(user)} messages reached. "
            "Contact support if you need more."
        )


def check_new_contact_limit(db: Session, user: User) -> None:
    since = utcnow() - timedelta(hours=24)
    n = db.scalar(
        select(func.count(Contact.id))
        .join(Address)
        .join(Domain)
        .where(Domain.user_id == user.id, Contact.origin == "manual", Contact.created_at >= since)
    )
    if n >= get_settings().daily_new_contact_limit:
        raise LimitExceeded(
            "You've added the maximum number of new contacts for today. Try again tomorrow."
        )


def map_private_ids(db: Session, user: User, ids: list[str], domain: str) -> dict[str, str]:
    """Return {private_id: public_id}, creating public ids where needed."""
    out = {}
    for pid in ids:
        row = db.scalar(
            select(MessageIdMap).where(
                MessageIdMap.user_id == user.id, MessageIdMap.private_id == pid
            )
        )
        if row is None:
            from app.relay.message import make_msgid

            row = MessageIdMap(user_id=user.id, private_id=pid, public_id=make_msgid(domain))
            db.add(row)
            db.flush()
        out[pid] = row.public_id
    return out


def lookup_ids(db: Session, user: User, ids: list[str], *, to_public: bool) -> dict[str, str]:
    """Translate whichever ids we have a mapping for."""
    if not ids:
        return {}
    src = MessageIdMap.private_id if to_public else MessageIdMap.public_id
    rows = db.scalars(select(MessageIdMap).where(MessageIdMap.user_id == user.id, src.in_(ids)))
    return {
        (r.private_id if to_public else r.public_id): (r.public_id if to_public else r.private_id)
        for r in rows
    }


def log_delivery(db: Session, user: User | None, direction: str, status: str, **kw) -> DeliveryLog:
    row = DeliveryLog(user_id=user.id if user else None, direction=direction, status=status, **kw)
    if row.detail:
        row.detail = row.detail[:500]
    db.add(row)
    db.flush()
    return row
