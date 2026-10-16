"""Stripe billing: one yearly price, quantity = number of domains.

Flow: free trial (no card) -> Stripe Checkout -> webhooks keep the user's
subscription status in sync. Customers manage cards, invoices and
cancellation in the Stripe customer portal.
"""

import calendar
import json
import logging
from datetime import UTC, datetime, timedelta

import stripe
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import utcnow
from app.models import StripeEvent, User

log = logging.getLogger(__name__)


class BillingError(Exception):
    pass


def client() -> stripe.StripeClient:
    s = get_settings()
    if not s.billing_enabled:
        raise BillingError("Billing isn't configured yet.")
    return stripe.StripeClient(s.stripe_secret_key)


def _ts(dt: datetime) -> int:
    return calendar.timegm(dt.utctimetuple())


def _from_ts(ts: int | None) -> datetime | None:
    return datetime.fromtimestamp(ts, UTC).replace(tzinfo=None) if ts else None


def _d(obj) -> dict:
    return obj.to_dict() if hasattr(obj, "to_dict") else dict(obj)


def ensure_customer(db: Session, user: User) -> str:
    if user.stripe_customer_id:
        return user.stripe_customer_id
    cust = client().v1.customers.create(
        params={"email": user.email, "name": user.name or None, "metadata": {"user_id": str(user.id)}}
    )
    user.stripe_customer_id = cust.id
    db.commit()
    return cust.id


def billable_quantity(user: User) -> int:
    return max(1, len(user.domains))


def create_checkout_session(db: Session, user: User) -> str:
    s = get_settings()
    customer = ensure_customer(db, user)
    sub_data: dict = {"metadata": {"user_id": str(user.id)}}
    # Keep the remainder of the free trial: Stripe won't charge until it ends.
    if user.trial_ends_at - utcnow() > timedelta(days=2):
        sub_data["trial_end"] = _ts(user.trial_ends_at)
    params = {
        "mode": "subscription",
        "customer": customer,
        "client_reference_id": str(user.id),
        "line_items": [{"price": s.stripe_price_id, "quantity": billable_quantity(user)}],
        "subscription_data": sub_data,
        "allow_promotion_codes": True,
        "billing_address_collection": "auto",
        "success_url": f"{s.base_url}/billing?checkout=success",
        "cancel_url": f"{s.base_url}/billing?checkout=cancelled",
    }
    if s.stripe_automatic_tax:
        params["automatic_tax"] = {"enabled": True}
        params["customer_update"] = {"address": "auto", "name": "auto"}
        params["tax_id_collection"] = {"enabled": True}
    session = client().v1.checkout.sessions.create(params=params)
    return session.url


def create_portal_session(db: Session, user: User) -> str:
    customer = ensure_customer(db, user)
    portal = client().v1.billing_portal.sessions.create(
        params={"customer": customer, "return_url": f"{get_settings().base_url}/billing"}
    )
    return portal.url


def sync_quantity(user: User) -> None:
    """Called after a domain is added/removed: bill per domain."""
    if not (get_settings().billing_enabled and user.stripe_subscription_id and user.subscribed):
        return
    try:
        c = client()
        sub = _d(c.v1.subscriptions.retrieve(user.stripe_subscription_id))
        item = sub["items"]["data"][0]
        qty = billable_quantity(user)
        if item.get("quantity") != qty:
            c.v1.subscription_items.update(
                item["id"], params={"quantity": qty, "proration_behavior": "create_prorations"}
            )
    except Exception:
        log.exception("could not sync subscription quantity for user %s", user.id)


def _user_for(db: Session, obj: dict) -> User | None:
    meta_uid = (obj.get("metadata") or {}).get("user_id") or obj.get("client_reference_id")
    if meta_uid and str(meta_uid).isdigit():
        user = db.get(User, int(meta_uid))
        if user:
            return user
    cust = obj.get("customer")
    if isinstance(cust, dict):
        cust = cust.get("id")
    if cust:
        return db.scalar(select(User).where(User.stripe_customer_id == cust))
    return None


def apply_subscription(db: Session, sub: dict) -> None:
    user = _user_for(db, sub)
    if user is None:
        log.warning("subscription %s for unknown customer %s", sub.get("id"), sub.get("customer"))
        return
    # A customer can only have one live subscription with us; ignore events
    # for an older, cancelled one.
    if user.stripe_subscription_id and user.stripe_subscription_id != sub["id"] and sub["status"] in (
        "canceled", "incomplete_expired"
    ):
        return
    user.stripe_subscription_id = sub["id"]
    if not user.stripe_customer_id and isinstance(sub.get("customer"), str):
        user.stripe_customer_id = sub["customer"]
    user.subscription_status = sub["status"]
    items = (sub.get("items") or {}).get("data") or []
    period_end = sub.get("current_period_end") or (items[0].get("current_period_end") if items else None)
    user.subscription_period_end = _from_ts(period_end)


def handle_event(db: Session, event: dict) -> None:
    if db.get(StripeEvent, event["id"]):
        return  # already processed
    etype = event["type"]
    obj = event["data"]["object"]
    if etype == "checkout.session.completed" and obj.get("subscription"):
        user = _user_for(db, obj)
        if user and not user.stripe_customer_id:
            user.stripe_customer_id = obj.get("customer")
        sub = _d(client().v1.subscriptions.retrieve(obj["subscription"]))
        apply_subscription(db, sub)
    elif etype in (
        "customer.subscription.created",
        "customer.subscription.updated",
        "customer.subscription.deleted",
        "customer.subscription.paused",
        "customer.subscription.resumed",
    ):
        apply_subscription(db, obj)
    elif etype in ("invoice.paid", "invoice.payment_failed"):
        sub_id = obj.get("subscription") or (
            ((obj.get("parent") or {}).get("subscription_details") or {}).get("subscription")
        )
        if sub_id:
            apply_subscription(db, _d(client().v1.subscriptions.retrieve(sub_id)))
    db.add(StripeEvent(id=event["id"], type=etype))
    db.commit()


def parse_webhook(payload: bytes, sig_header: str | None) -> dict:
    """Verify the signature and return the event as a plain dict."""
    s = get_settings()
    if not s.stripe_webhook_secret:
        raise BillingError("Webhook secret not configured")
    stripe.Webhook.construct_event(payload, sig_header, s.stripe_webhook_secret)
    return json.loads(payload)
