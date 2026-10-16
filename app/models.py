"""Database tables.

Privacy rule: nothing here stores message bodies or subjects. We keep only the
routing metadata needed to relay mail and keep threads intact.
"""

import secrets
from datetime import datetime, timedelta

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.config import get_settings
from app.db import Base, utcnow

ACTIVE_SUB_STATUSES = {"active", "trialing", "past_due"}


def new_token(nbytes: int = 16) -> str:
    return secrets.token_urlsafe(nbytes)


def new_alias_token() -> str:
    # Lowercase base32-ish, safe in a local part and not case sensitive.
    alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(14))


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    # The customer's Gmail address: where mail is forwarded and the only
    # address allowed to send replies through their reverse aliases.
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    trial_ends_at: Mapped[datetime] = mapped_column(DateTime)
    suspended: Mapped[bool] = mapped_column(Boolean, default=False)
    suspended_reason: Mapped[str] = mapped_column(String(500), default="")
    daily_send_limit: Mapped[int | None] = mapped_column(Integer)

    stripe_customer_id: Mapped[str | None] = mapped_column(String(64), index=True)
    stripe_subscription_id: Mapped[str | None] = mapped_column(String(64), index=True)
    subscription_status: Mapped[str | None] = mapped_column(String(32))
    subscription_period_end: Mapped[datetime | None] = mapped_column(DateTime)

    domains: Mapped[list["Domain"]] = relationship(
        back_populates="user", cascade="all, delete-orphan", order_by="Domain.name"
    )

    @property
    def is_admin(self) -> bool:
        return self.email.lower() in get_settings().admin_email_set

    @property
    def subscribed(self) -> bool:
        return self.subscription_status in ACTIVE_SUB_STATUSES

    @property
    def in_trial(self) -> bool:
        return not self.subscribed and utcnow() < self.trial_ends_at

    @property
    def trial_days_left(self) -> int:
        return max(0, (self.trial_ends_at - utcnow()).days)

    @property
    def plan_active(self) -> bool:
        return self.subscribed or self.in_trial

    @property
    def can_send(self) -> bool:
        return bool(self.email_verified_at) and not self.suspended and self.plan_active

    @property
    def can_receive(self) -> bool:
        """Inbound keeps flowing for a short grace period after the plan ends,
        so a forgotten card doesn't silently bounce someone's business mail."""
        if not self.email_verified_at or self.suspended:
            return False
        if self.plan_active:
            return True
        grace = timedelta(days=get_settings().inbound_grace_days)
        ended = self.trial_ends_at
        if self.subscription_period_end and self.subscription_period_end > ended:
            ended = self.subscription_period_end
        return utcnow() < ended + grace

    @property
    def max_domains(self) -> int:
        return 100 if self.subscribed else get_settings().trial_max_domains


class Domain(Base):
    __tablename__ = "domains"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    verification_token: Mapped[str] = mapped_column(String(64), default=lambda: new_token(18))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime)
    mx_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    spf_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    dkim_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    dmarc_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime)
    dkim_selector: Mapped[str] = mapped_column(String(63))
    # Encrypted PEM (see app.crypto).
    dkim_private_key: Mapped[str] = mapped_column(Text)
    dkim_public_record: Mapped[str] = mapped_column(Text)
    catch_all: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user: Mapped[User] = relationship(back_populates="domains")
    addresses: Mapped[list["Address"]] = relationship(
        back_populates="domain", cascade="all, delete-orphan", order_by="Address.local_part"
    )

    @property
    def receiving_ready(self) -> bool:
        return self.verified_at is not None

    @property
    def sending_ready(self) -> bool:
        return self.verified_at is not None and self.dkim_ok


class Address(Base):
    __tablename__ = "addresses"
    __table_args__ = (UniqueConstraint("domain_id", "local_part"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    domain_id: Mapped[int] = mapped_column(ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    local_part: Mapped[str] = mapped_column(String(64))
    display_name: Mapped[str] = mapped_column(String(200), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    domain: Mapped[Domain] = relationship(back_populates="addresses")
    contacts: Mapped[list["Contact"]] = relationship(
        back_populates="address", cascade="all, delete-orphan"
    )

    @property
    def email(self) -> str:
        return f"{self.local_part}@{self.domain.name}"


class Contact(Base):
    """A person the customer corresponds with, and their reverse alias.

    Mail from `email` to `address` reaches Gmail as coming from the reverse
    alias; replies to the reverse alias go out as `address` to `email`.
    """

    __tablename__ = "contacts"
    __table_args__ = (UniqueConstraint("address_id", "email"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    address_id: Mapped[int] = mapped_column(
        ForeignKey("addresses.id", ondelete="CASCADE"), index=True
    )
    email: Mapped[str] = mapped_column(String(320))
    name: Mapped[str] = mapped_column(String(200), default="")
    token: Mapped[str] = mapped_column(String(32), unique=True, index=True, default=new_alias_token)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False)
    # "inbound" (they emailed us first) or "manual" (customer added / composed).
    origin: Mapped[str] = mapped_column(String(16), default="inbound")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime)

    address: Mapped[Address] = relationship(back_populates="contacts")

    @property
    def reverse_alias(self) -> str:
        return f"r-{self.token}@{get_settings().relay_domain}"


class MessageIdMap(Base):
    """Maps Message-IDs Gmail generates to the ones we publish, so the
    customer's Gmail address never leaks and threads still line up."""

    __tablename__ = "message_ids"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    private_id: Mapped[str] = mapped_column(String(998), index=True)
    public_id: Mapped[str] = mapped_column(String(998), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class DeliveryLog(Base):
    """Metadata-only record of each relayed message."""

    __tablename__ = "delivery_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # "in" (contact -> Gmail), "out" (Gmail reply -> contact), "compose".
    direction: Mapped[str] = mapped_column(String(16))
    address: Mapped[str] = mapped_column(String(320), default="")
    contact: Mapped[str] = mapped_column(String(320), default="")
    status: Mapped[str] = mapped_column(String(16))  # delivered/rejected/deferred/bounced/dropped
    detail: Mapped[str] = mapped_column(String(500), default="")
    size: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class Suppression(Base):
    """Recipients we will not send to (hard bounces, spam complaints)."""

    __tablename__ = "suppressions"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    reason: Mapped[str] = mapped_column(String(32))  # bounce / complaint / manual
    detail: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class WaitlistEntry(Base):
    __tablename__ = "waitlist"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    current_setup: Mapped[str] = mapped_column(String(64), default="")
    domain_count: Mapped[str] = mapped_column(String(16), default="")
    source: Mapped[str] = mapped_column(String(200), default="")
    consent_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    confirm_token: Mapped[str] = mapped_column(String(64), default=lambda: new_token(18))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class StripeEvent(Base):
    """Processed webhook event ids, for idempotency."""

    __tablename__ = "stripe_events"

    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    type: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
