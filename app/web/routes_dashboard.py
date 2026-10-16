"""The customer dashboard: domains, addresses, contacts, compose, log, settings."""

import asyncio
import json
import re

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app import billing
from app.cloudflare import CloudflareError, apply_records
from app.config import get_settings
from app.dns_check import expected_records, run_checks, validate_domain_name
from app.db import get_db
from app.mailer import get_transport
from app.models import Address, Contact, DeliveryLog, Domain, MessageIdMap, User
from app.relay.contacts import LimitExceeded, daily_limit, get_or_create_contact, sent_last_24h
from app.relay.keys import new_domain_keys
from app.relay.outbound import compose as compose_message
from app.security import verify_password
from app.web.deps import check_csrf, current_user, flash, redirect, render
from app.web.routes_public import EMAIL_RE

router = APIRouter()
LOCAL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._+-]{0,62}[a-z0-9])?$")
RESERVED_LOCALS = {"bounce", "postmaster", "abuse", "mailer-daemon"}


def _domain(db: Session, user: User, domain_id: int) -> Domain:
    d = db.get(Domain, domain_id)
    if d is None or d.user_id != user.id:
        raise HTTPException(404)
    return d


def _address(db: Session, user: User, address_id: int) -> Address:
    a = db.get(Address, address_id)
    if a is None or a.domain.user_id != user.id:
        raise HTTPException(404)
    return a


def _contact(db: Session, user: User, contact_id: int) -> Contact:
    c = db.get(Contact, contact_id)
    if c is None or c.address.domain.user_id != user.id:
        raise HTTPException(404)
    return c


def _user_addresses(db: Session, user: User) -> list[Address]:
    return list(
        db.scalars(
            select(Address).join(Domain).where(Domain.user_id == user.id).order_by(Domain.name, Address.local_part)
        )
    )


# --- overview -----------------------------------------------------------------


@router.get("/dashboard")
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    addresses = _user_addresses(db, user)
    n_contacts = db.scalar(
        select(func.count(Contact.id)).join(Address).join(Domain).where(Domain.user_id == user.id)
    )
    steps = [
        ("Confirm your Gmail address", bool(user.email_verified_at), None),
        ("Add your domain", bool(user.domains), "/domains/new"),
        ("Publish DNS records", any(d.verified_at and d.mx_ok and d.dkim_ok for d in user.domains),
         f"/domains/{user.domains[0].id}" if user.domains else None),
        ("Create an address (e.g. you@yourdomain.com)", bool(addresses),
         f"/domains/{user.domains[0].id}#addresses" if user.domains else None),
        ("Send yourself a test: email your address from another account, then reply in Gmail",
         n_contacts > 0, None),
    ]  # fmt: skip
    recent = db.scalars(
        select(DeliveryLog).where(DeliveryLog.user_id == user.id).order_by(DeliveryLog.id.desc()).limit(8)
    ).all()
    return render(
        request, "dashboard.html", steps=steps, addresses=addresses, recent=recent,
        sent_today=sent_last_24h(db, user), limit=daily_limit(user),
    )  # fmt: skip


# --- domains --------------------------------------------------------------------


@router.get("/domains/new")
def domain_new(request: Request, user: User = Depends(current_user)):
    return render(request, "domain_new.html")


@router.post("/domains", dependencies=[Depends(check_csrf)])
def domain_create(
    request: Request,
    name: str = Form(...),
    local_part: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    name = name.strip().lower().removeprefix("http://").removeprefix("https://").removeprefix("www.").strip("/")
    error = validate_domain_name(name)
    if not error and db.scalar(select(Domain).where(Domain.name == name)):
        error = "That domain is already registered. If it's yours and you didn't add it, contact support."
    if not error and len(user.domains) >= user.max_domains:
        error = (
            f"Your free trial includes {user.max_domains} domain. Subscribe to add more."
            if not user.subscribed else "Domain limit reached; contact support."
        )
    local_part = local_part.strip().lower()
    if local_part and (not LOCAL_RE.match(local_part) or local_part in RESERVED_LOCALS):
        error = error or "That address isn't allowed. Use letters, numbers, dots or dashes."
    if error:
        return render(request, "domain_new.html", status_code=400, errors=[error], name=name, local_part=local_part)
    s = get_settings()
    priv, pub = new_domain_keys()
    domain = Domain(user=user, name=name, dkim_selector=s.customer_dkim_selector,
                    dkim_private_key=priv, dkim_public_record=pub)  # fmt: skip
    db.add(domain)
    if local_part:
        db.add(Address(domain=domain, local_part=local_part, display_name=user.name))
    db.commit()
    billing.sync_quantity(user)
    return redirect(f"/domains/{domain.id}")


@router.get("/domains/{domain_id}")
def domain_detail(domain_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domain = _domain(db, user, domain_id)
    return render(request, "domain_detail.html", domain=domain, records=expected_records(domain), results=None)


@router.post("/domains/{domain_id}/check", dependencies=[Depends(check_csrf)])
async def domain_check(domain_id: int, request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    domain = _domain(db, user, domain_id)
    results = await asyncio.to_thread(run_checks, domain)
    db.commit()
    if request.headers.get("accept") == "application/json":
        return JSONResponse({k: {"ok": v.ok, "message": v.message, "found": v.found} for k, v in results.items()})
    return render(request, "domain_detail.html", domain=domain, records=expected_records(domain), results=results)


@router.post("/domains/{domain_id}/cloudflare", dependencies=[Depends(check_csrf)])
async def domain_cloudflare(
    domain_id: int,
    request: Request,
    token: str = Form(...),
    replace_mx: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _domain(db, user, domain_id)
    try:
        changes = await asyncio.to_thread(apply_records, domain, token, bool(replace_mx))
    except CloudflareError as exc:
        flash(request, f"Cloudflare: {exc}", "error")
        return redirect(f"/domains/{domain.id}")
    flash(request, "Cloudflare updated: " + ("; ".join(changes) or "everything was already in place") +
          ". DNS can take a few minutes; then press Check DNS.", "success")  # fmt: skip
    return redirect(f"/domains/{domain.id}")


@router.post("/domains/{domain_id}/settings", dependencies=[Depends(check_csrf)])
def domain_settings(
    domain_id: int,
    request: Request,
    catch_all: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _domain(db, user, domain_id)
    domain.catch_all = bool(catch_all)
    db.commit()
    flash(request, "Saved.", "success")
    return redirect(f"/domains/{domain.id}#addresses")


@router.post("/domains/{domain_id}/delete", dependencies=[Depends(check_csrf)])
def domain_delete(
    domain_id: int,
    request: Request,
    confirm: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _domain(db, user, domain_id)
    if confirm.strip().lower() != domain.name:
        flash(request, "Type the domain name to confirm deletion.", "error")
        return redirect(f"/domains/{domain.id}")
    db.delete(domain)
    db.commit()
    db.refresh(user)
    billing.sync_quantity(user)
    flash(request, f"{domain.name} removed. Remember to change its MX records.", "success")
    return redirect("/dashboard")


@router.post("/domains/{domain_id}/addresses", dependencies=[Depends(check_csrf)])
def address_create(
    domain_id: int,
    request: Request,
    local_part: str = Form(...),
    display_name: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    domain = _domain(db, user, domain_id)
    local_part = local_part.strip().lower()
    if not LOCAL_RE.match(local_part) or local_part in RESERVED_LOCALS or local_part.startswith("bounce+"):
        flash(request, "That address isn't allowed. Use letters, numbers, dots or dashes.", "error")
    elif any(a.local_part == local_part for a in domain.addresses):
        flash(request, "That address already exists.", "error")
    elif len(domain.addresses) >= 50:
        flash(request, "Address limit reached for this domain.", "error")
    else:
        db.add(Address(domain=domain, local_part=local_part, display_name=display_name.strip()[:200]))
        db.commit()
        flash(request, f"{local_part}@{domain.name} created.", "success")
    return redirect(f"/domains/{domain.id}#addresses")


@router.post("/addresses/{address_id}", dependencies=[Depends(check_csrf)])
def address_update(
    address_id: int,
    request: Request,
    display_name: str = Form(""),
    enabled: str = Form(""),
    action: str = Form("save"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    address = _address(db, user, address_id)
    domain_id = address.domain_id
    if action == "delete":
        db.delete(address)
        flash(request, "Address deleted.", "success")
    else:
        address.display_name = display_name.strip()[:200]
        address.enabled = bool(enabled)
        flash(request, "Saved.", "success")
    db.commit()
    return redirect(f"/domains/{domain_id}#addresses")


# --- contacts -------------------------------------------------------------------


@router.get("/contacts")
def contacts(request: Request, q: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)):
    stmt = select(Contact).join(Address).join(Domain).where(Domain.user_id == user.id)
    if q:
        like = f"%{q.strip().lower()}%"
        stmt = stmt.where(or_(Contact.email.like(like), func.lower(Contact.name).like(like)))
    rows = db.scalars(stmt.order_by(Contact.last_used_at.desc().nulls_last(), Contact.id.desc()).limit(200)).all()
    return render(request, "contacts.html", contacts=rows, q=q, addresses=_user_addresses(db, user))


@router.post("/contacts", dependencies=[Depends(check_csrf)])
def contact_add(
    request: Request,
    email: str = Form(...),
    name: str = Form(""),
    address_id: int = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    address = _address(db, user, address_id)
    email = email.strip().lower()
    if not EMAIL_RE.match(email):
        flash(request, "Enter a valid email address.", "error")
        return redirect("/contacts")
    try:
        contact, created = get_or_create_contact(db, address, email, name.strip(), origin="manual")
    except LimitExceeded as exc:
        flash(request, str(exc), "error")
        return redirect("/contacts")
    db.commit()
    flash(
        request,
        f"To email {email} from Gmail as {address.email}, write to {contact.reverse_alias}. "
        "Tip: save it in your phone's contacts.",
        "success",
    )
    return redirect(f"/contacts?q={email}")


@router.post("/contacts/{contact_id}", dependencies=[Depends(check_csrf)])
def contact_update(
    contact_id: int,
    request: Request,
    action: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    contact = _contact(db, user, contact_id)
    if action == "block":
        contact.blocked = True
        flash(request, f"Mail from {contact.email} will be dropped.", "success")
    elif action == "unblock":
        contact.blocked = False
        flash(request, f"{contact.email} unblocked.", "success")
    elif action == "delete":
        db.delete(contact)
        flash(request, "Contact deleted. Their old reverse alias stops working.", "success")
    db.commit()
    return redirect("/contacts")


# --- compose --------------------------------------------------------------------


@router.get("/compose")
def compose_form(request: Request, to: str = "", user: User = Depends(current_user), db: Session = Depends(get_db)):
    return render(request, "compose.html", addresses=_user_addresses(db, user), to=to)


@router.post("/compose", dependencies=[Depends(check_csrf)])
async def compose_send(
    request: Request,
    address_id: int = Form(...),
    to: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    address = _address(db, user, address_id)
    to_name, to_email = "", to.strip()
    m = re.match(r"^\s*(.*?)\s*<([^>]+)>\s*$", to)
    if m:
        to_name, to_email = m.group(1).strip('" '), m.group(2)
    to_email = to_email.lower()
    errors = []
    if not EMAIL_RE.match(to_email):
        errors.append("Enter a valid recipient address.")
    if not subject.strip():
        errors.append("Add a subject.")
    if len(body) > 200_000:
        errors.append("Message is too long.")
    if errors:
        return render(request, "compose.html", status_code=400, errors=errors,
                      addresses=_user_addresses(db, user), to=to, subject=subject, body=body)  # fmt: skip
    outcome = await compose_message(
        db, user, address, to_email, to_name, subject.strip()[:300], body, get_transport()
    )
    db.commit()
    if outcome.status == "delivered":
        flash(request, f"Sent to {to_email} from {address.email}. A copy is in your Gmail; replies arrive there.", "success")
        return redirect("/compose")
    return render(request, "compose.html", status_code=400, errors=[outcome.message],
                  addresses=_user_addresses(db, user), to=to, subject=subject, body=body)  # fmt: skip


# --- log --------------------------------------------------------------------------


@router.get("/log")
def delivery_log(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    rows = db.scalars(
        select(DeliveryLog).where(DeliveryLog.user_id == user.id).order_by(DeliveryLog.id.desc()).limit(300)
    ).all()
    return render(request, "log.html", rows=rows)


# --- settings / GDPR ----------------------------------------------------------------


@router.get("/settings")
def settings_page(request: Request, user: User = Depends(current_user)):
    return render(request, "settings.html")


@router.post("/settings/profile", dependencies=[Depends(check_csrf)])
def settings_profile(request: Request, name: str = Form(""), user: User = Depends(current_user), db: Session = Depends(get_db)):
    user.name = name.strip()[:200]
    db.commit()
    flash(request, "Saved.", "success")
    return redirect("/settings")


@router.post("/settings/password", dependencies=[Depends(check_csrf)])
def settings_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    from app.security import hash_password
    from app.web.deps import login

    if not verify_password(current, user.password_hash):
        flash(request, "Current password is wrong.", "error")
    elif len(new) < 10:
        flash(request, "Use at least 10 characters.", "error")
    else:
        user.password_hash = hash_password(new)
        db.commit()
        login(request, user)
        flash(request, "Password changed.", "success")
    return redirect("/settings")


@router.get("/settings/export")
def settings_export(user: User = Depends(current_user), db: Session = Depends(get_db)):
    """GDPR data export: everything we hold about the account."""
    data = {
        "account": {"email": user.email, "name": user.name, "created_at": str(user.created_at),
                    "trial_ends_at": str(user.trial_ends_at), "subscription_status": user.subscription_status},
        "domains": [
            {"name": d.name, "verified_at": str(d.verified_at), "catch_all": d.catch_all,
             "addresses": [
                 {"address": a.email, "display_name": a.display_name, "enabled": a.enabled,
                  "contacts": [{"email": c.email, "name": c.name, "reverse_alias": c.reverse_alias,
                                "blocked": c.blocked, "created_at": str(c.created_at)} for c in a.contacts]}
                 for a in d.addresses]}
            for d in user.domains
        ],
        "delivery_log": [
            {"at": str(r.created_at), "direction": r.direction, "address": r.address, "contact": r.contact,
             "status": r.status, "detail": r.detail}
            for r in db.scalars(select(DeliveryLog).where(DeliveryLog.user_id == user.id))
        ],
    }  # fmt: skip
    return Response(
        json.dumps(data, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=account-export.json"},
    )


@router.post("/settings/delete", dependencies=[Depends(check_csrf)])
def settings_delete(
    request: Request,
    password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(password, user.password_hash):
        flash(request, "Password is wrong; account not deleted.", "error")
        return redirect("/settings")
    if user.stripe_subscription_id and user.subscribed and get_settings().billing_enabled:
        try:
            billing.client().v1.subscriptions.cancel(user.stripe_subscription_id)
        except Exception:
            flash(request, "We couldn't cancel your subscription automatically; contact support.", "error")
            return redirect("/settings")
    db.execute(delete(MessageIdMap).where(MessageIdMap.user_id == user.id))
    db.execute(delete(DeliveryLog).where(DeliveryLog.user_id == user.id))
    db.delete(user)
    db.commit()
    request.session.clear()
    return render(request, "message.html", user=None, title="Account deleted",
                  body="Your account and all its data have been deleted. Remember to point your MX records elsewhere.")  # fmt: skip
