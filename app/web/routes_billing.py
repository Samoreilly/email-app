"""Billing pages and the Stripe webhook."""

import logging

import stripe
from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session

from app import billing
from app.db import get_db
from app.models import User
from app.web.deps import check_csrf, current_user, flash, redirect, render

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/billing")
def billing_page(request: Request, checkout: str = "", user: User = Depends(current_user)):
    if checkout == "success":
        flash(request, "Thanks! Your subscription is being activated; this page updates within a minute.", "success")
    elif checkout == "cancelled":
        flash(request, "Checkout cancelled. You haven't been charged.", "info")
    return render(request, "billing.html", quantity=billing.billable_quantity(user))


@router.post("/billing/checkout", dependencies=[Depends(check_csrf)])
def billing_checkout(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if user.subscribed:
        return redirect("/billing")
    try:
        return redirect(billing.create_checkout_session(db, user))
    except billing.BillingError as exc:
        flash(request, str(exc), "error")
    except stripe.StripeError:
        log.exception("checkout failed")
        flash(request, "Payment provider error. Please try again in a minute.", "error")
    return redirect("/billing")


@router.post("/billing/portal", dependencies=[Depends(check_csrf)])
def billing_portal(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    try:
        return redirect(billing.create_portal_session(db, user))
    except billing.BillingError as exc:
        flash(request, str(exc), "error")
    except stripe.StripeError:
        log.exception("portal failed")
        flash(request, "Payment provider error. Please try again in a minute.", "error")
    return redirect("/billing")


@router.post("/billing/webhook")
async def billing_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    try:
        event = billing.parse_webhook(payload, request.headers.get("stripe-signature"))
    except (ValueError, stripe.SignatureVerificationError, billing.BillingError) as exc:
        log.warning("rejected webhook: %s", exc)
        return PlainTextResponse("invalid", status_code=400)
    try:
        billing.handle_event(db, event)
    except Exception:
        log.exception("webhook %s failed", event.get("id"))
        db.rollback()
        return PlainTextResponse("error", status_code=500)  # Stripe retries
    return PlainTextResponse("ok")
