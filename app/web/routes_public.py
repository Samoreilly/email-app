"""Landing page, waitlist and legal pages."""

import re

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db, utcnow
from app.mailer import send_system_email
from app.models import User, WaitlistEntry
from app.security import RateLimiter
from app.web.deps import check_csrf, current_user_optional, flash, redirect, render

router = APIRouter()
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
waitlist_limiter = RateLimiter(10, 3600)

SETUPS = {
    "cloudflare": "Cloudflare Email Routing + Gmail",
    "improvmx": "ImprovMX + Gmail",
    "registrar": "Registrar forwarding (Namecheap, Porkbun, etc.) + Gmail",
    "workspace": "Google Workspace",
    "other": "Something else",
}


@router.get("/")
def landing(request: Request, user: User | None = Depends(current_user_optional)):
    return render(request, "landing.html", setups=SETUPS)


@router.post("/waitlist", dependencies=[Depends(check_csrf)])
async def join_waitlist(
    request: Request,
    email: str = Form(...),
    current_setup: str = Form(""),
    domain_count: str = Form(""),
    consent: str = Form(""),
    website: str = Form(""),  # honeypot; humans leave it empty
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    if website:
        return redirect("/waitlist/thanks")
    if not waitlist_limiter.allow(request.client.host if request.client else "?"):
        flash(request, "Too many attempts. Please try again later.", "error")
        return redirect("/#waitlist")
    if not EMAIL_RE.match(email) or len(email) > 320:
        flash(request, "Please enter a valid email address.", "error")
        return redirect("/#waitlist")
    if not consent:
        flash(request, "Please tick the box so we're allowed to email you.", "error")
        return redirect("/#waitlist")
    entry = db.scalar(select(WaitlistEntry).where(WaitlistEntry.email == email))
    if entry is None:
        entry = WaitlistEntry(
            email=email,
            current_setup=current_setup if current_setup in SETUPS else "",
            domain_count=domain_count[:16],
            source=(request.headers.get("referer") or "")[:200],
        )
        db.add(entry)
        db.commit()
    if not entry.confirmed_at:
        s = get_settings()
        await send_system_email(
            email,
            f"Confirm your spot on the {s.app_name} waitlist",
            f"Thanks for your interest in {s.app_name}.\n\n"
            f"Please confirm your email so we can tell you when we launch:\n"
            f"{s.base_url}/waitlist/confirm/{entry.confirm_token}\n\n"
            "If you didn't sign up, ignore this email and we'll delete your address in 30 days.",
        )
    return redirect("/waitlist/thanks")


@router.get("/waitlist/thanks")
def waitlist_thanks(request: Request):
    return render(request, "message.html", title="Check your inbox",
                  body="We've sent you a confirmation link. Click it to secure your spot.")  # fmt: skip


@router.get("/waitlist/confirm/{token}")
def waitlist_confirm(token: str, request: Request, db: Session = Depends(get_db)):
    entry = db.scalar(select(WaitlistEntry).where(WaitlistEntry.confirm_token == token))
    if entry is None:
        return render(request, "message.html", status_code=404, title="Link not valid",
                      body="This confirmation link is invalid or has expired.")  # fmt: skip
    if not entry.confirmed_at:
        entry.confirmed_at = utcnow()
        db.commit()
    return render(request, "message.html", title="You're on the list",
                  body="Thanks! We'll email you as soon as you can set up your domain.")  # fmt: skip


@router.get("/waitlist/unsubscribe/{token}")
def waitlist_unsubscribe(token: str, request: Request, db: Session = Depends(get_db)):
    entry = db.scalar(select(WaitlistEntry).where(WaitlistEntry.confirm_token == token))
    if entry:
        db.delete(entry)
        db.commit()
    return render(request, "message.html", title="Removed", body="Your address has been deleted from the waitlist.")


@router.get("/privacy")
def privacy(request: Request):
    return render(request, "legal_privacy.html")


@router.get("/terms")
def terms(request: Request):
    return render(request, "legal_terms.html")


@router.get("/dpa")
def dpa(request: Request):
    return render(request, "legal_dpa.html")


@router.get("/guide/gmail-send-as-alternative")
def guide(request: Request):
    return render(request, "guide.html")


@router.get("/healthz")
def healthz():
    return PlainTextResponse("ok")


@router.get("/robots.txt")
def robots():
    return PlainTextResponse(
        f"User-agent: *\nDisallow: /dashboard\nDisallow: /domains\nDisallow: /admin\n"
        f"Sitemap: {get_settings().base_url}/sitemap.xml\n"
    )


@router.get("/sitemap.xml")
def sitemap():
    base = get_settings().base_url
    urls = ["/", "/guide/gmail-send-as-alternative", "/privacy", "/terms", "/dpa"]
    body = "".join(f"<url><loc>{base}{u}</loc></url>" for u in urls)
    return PlainTextResponse(
        f'<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{body}</urlset>',
        media_type="application/xml",
    )
