"""Signup, login, email verification, password reset."""

from datetime import timedelta

from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.crypto import make_token, read_token
from app.db import get_db, utcnow
from app.mailer import send_system_email
from app.models import User
from app.security import RateLimiter, hash_password, verify_password
from app.web.deps import check_csrf, current_user, flash, login, redirect, render
from app.web.routes_public import EMAIL_RE

router = APIRouter()
login_limiter = RateLimiter(10, 900)
signup_limiter = RateLimiter(5, 3600)
reset_limiter = RateLimiter(5, 3600)


def _ip(request: Request) -> str:
    # uvicorn runs with --proxy-headers behind Caddy, so this is the real IP.
    return request.client.host if request.client else "?"


def _safe_next(url: str | None) -> str:
    return url if url and url.startswith("/") and not url.startswith("//") else "/dashboard"


async def send_verification(user: User) -> None:
    s = get_settings()
    token = make_token("verify-email", {"uid": user.id, "email": user.email})
    await send_system_email(
        user.email,
        f"Confirm your {s.app_name} account",
        f"Hi{' ' + user.name if user.name else ''},\n\n"
        f"Confirm this is your Gmail address so we can forward your domain's mail to it:\n"
        f"{s.base_url}/verify-email/{token}\n\n"
        "The link works for 3 days. If you didn't sign up, ignore this email.",
    )


@router.get("/signup")
def signup_form(request: Request):
    if not get_settings().signups_open:
        return redirect("/#waitlist")
    return render(request, "signup.html")


@router.post("/signup", dependencies=[Depends(check_csrf)])
async def signup(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    name: str = Form(""),
    terms: str = Form(""),
    db: Session = Depends(get_db),
):
    s = get_settings()
    if not s.signups_open:
        return redirect("/#waitlist")
    email = email.strip().lower()
    errors = []
    if not EMAIL_RE.match(email):
        errors.append("Enter a valid email address.")
    if len(password) < 10:
        errors.append("Use a password of at least 10 characters.")
    if not terms:
        errors.append("Please accept the terms and privacy policy.")
    if not errors and db.scalar(select(User).where(User.email == email)):
        errors.append("An account with that email already exists. Log in instead.")
    if not errors and not signup_limiter.allow(_ip(request)):
        errors.append("Too many signups from your network. Try again later.")
    if errors:
        return render(request, "signup.html", status_code=400, errors=errors, email=email, name=name)
    user = User(
        email=email,
        name=name.strip()[:200],
        password_hash=hash_password(password),
        trial_ends_at=utcnow() + timedelta(days=s.trial_days),
    )
    db.add(user)
    db.commit()
    await send_verification(user)
    login(request, user)
    flash(request, f"Welcome! We've sent a confirmation link to {email}.", "success")
    return redirect("/dashboard")


@router.get("/verify-email/{token}")
def verify_email(token: str, request: Request, db: Session = Depends(get_db)):
    data = read_token("verify-email", token, max_age=3 * 24 * 3600)
    user = db.get(User, data["uid"]) if data else None
    if user is None or user.email != data["email"]:
        return render(request, "message.html", status_code=400, title="Link expired",
                      body="This link is invalid or has expired. Log in to get a new one.")  # fmt: skip
    if not user.email_verified_at:
        user.email_verified_at = utcnow()
        db.commit()
    flash(request, "Email confirmed.", "success")
    return redirect("/dashboard")


@router.post("/resend-verification", dependencies=[Depends(check_csrf)])
async def resend_verification(request: Request, user: User = Depends(current_user)):
    if not user.email_verified_at and reset_limiter.allow(f"verify:{user.id}"):
        await send_verification(user)
    flash(request, "Confirmation email sent.", "success")
    return redirect("/dashboard")


@router.get("/login")
def login_form(request: Request, next: str = ""):
    return render(request, "login.html", next=_safe_next(next))


@router.post("/login", dependencies=[Depends(check_csrf)])
def login_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
    db: Session = Depends(get_db),
):
    email = email.strip().lower()
    if not login_limiter.allow(_ip(request)) or not login_limiter.allow(f"acct:{email}"):
        return render(request, "login.html", status_code=429, email=email, next=_safe_next(next),
                      errors=["Too many attempts. Wait 15 minutes and try again."])  # fmt: skip
    user = db.scalar(select(User).where(User.email == email))
    if user is None or not verify_password(password, user.password_hash):
        return render(request, "login.html", status_code=400, email=email, next=_safe_next(next),
                      errors=["Wrong email or password."])  # fmt: skip
    login(request, user)
    return redirect(_safe_next(next))


@router.post("/logout", dependencies=[Depends(check_csrf)])
def logout(request: Request):
    request.session.clear()
    return redirect("/")


@router.get("/forgot")
def forgot_form(request: Request):
    return render(request, "forgot.html")


@router.post("/forgot", dependencies=[Depends(check_csrf)])
async def forgot(request: Request, email: str = Form(...), db: Session = Depends(get_db)):
    email = email.strip().lower()
    user = db.scalar(select(User).where(User.email == email))
    if user and reset_limiter.allow(f"reset:{email}") and reset_limiter.allow(_ip(request)):
        s = get_settings()
        # Tie the token to the current hash so it stops working once used.
        token = make_token("reset", {"uid": user.id, "h": user.password_hash[-12:]})
        await send_system_email(
            email,
            f"Reset your {s.app_name} password",
            f"Someone asked to reset your password. If it was you, use this link within an hour:\n"
            f"{s.base_url}/reset/{token}\n\nIf it wasn't you, ignore this email.",
        )
    return render(request, "message.html", title="Check your inbox",
                  body="If that address has an account, we've emailed a reset link.")  # fmt: skip


def _reset_user(db: Session, token: str) -> User | None:
    data = read_token("reset", token, max_age=3600)
    user = db.get(User, data["uid"]) if data else None
    if user is None or user.password_hash[-12:] != data["h"]:
        return None
    return user


@router.get("/reset/{token}")
def reset_form(token: str, request: Request, db: Session = Depends(get_db)):
    if _reset_user(db, token) is None:
        return render(request, "message.html", status_code=400, title="Link expired",
                      body="This reset link is invalid or has already been used.")  # fmt: skip
    return render(request, "reset.html", token=token)


@router.post("/reset/{token}", dependencies=[Depends(check_csrf)])
def reset(token: str, request: Request, password: str = Form(...), db: Session = Depends(get_db)):
    user = _reset_user(db, token)
    if user is None:
        return render(request, "message.html", status_code=400, title="Link expired",
                      body="This reset link is invalid or has already been used.")  # fmt: skip
    if len(password) < 10:
        return render(request, "reset.html", token=token, errors=["Use at least 10 characters."])
    user.password_hash = hash_password(password)
    if not user.email_verified_at:
        user.email_verified_at = utcnow()  # they proved access to the inbox
    db.commit()
    login(request, user)
    flash(request, "Password updated.", "success")
    return redirect("/dashboard")
