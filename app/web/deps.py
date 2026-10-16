"""Shared web helpers: templates, current user, CSRF, flash messages."""

from pathlib import Path

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import get_db
from app.models import User
from app.security import csrf_ok, csrf_token

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).resolve().parent.parent / "templates"))


class LoginRequired(Exception):
    pass


def flash(request: Request, message: str, kind: str = "info") -> None:
    request.session.setdefault("flash", []).append([kind, message])


def _pop_flash(request: Request) -> list:
    return request.session.pop("flash", [])


def render(request: Request, template: str, status_code: int = 200, **ctx):
    ctx.setdefault("user", getattr(request.state, "user", None))
    return TEMPLATES.TemplateResponse(
        request,
        template,
        {
            "settings": get_settings(),
            "csrf": csrf_token(request.session),
            "flashes": _pop_flash(request),
            **ctx,
        },
        status_code=status_code,
    )


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)


def current_user_optional(request: Request, db: Session = Depends(get_db)) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    user = db.get(User, uid)
    if user is None or request.session.get("pwv") != user.password_hash[-12:]:
        # Password changed elsewhere: log this session out.
        request.session.clear()
        return None
    request.state.user = user
    return user


def current_user(user: User | None = Depends(current_user_optional)) -> User:
    if user is None:
        raise LoginRequired()
    return user


def admin_user(user: User = Depends(current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(404)
    return user


async def check_csrf(request: Request) -> None:
    form = await request.form()
    if not csrf_ok(request.session, form.get("csrf")):
        raise HTTPException(400, "Your session expired. Go back, refresh the page and try again.")


def login(request: Request, user: User) -> None:
    request.session.clear()
    request.session["uid"] = user.id
    request.session["pwv"] = user.password_hash[-12:]


def owned_or_404(obj, user: User):
    if obj is None:
        raise HTTPException(404)
    return obj
