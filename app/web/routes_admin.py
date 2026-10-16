"""Minimal operator console (ADMIN_EMAILS)."""

import csv
import io

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import ACTIVE_SUB_STATUSES, DeliveryLog, Domain, Suppression, User, WaitlistEntry
from app.web.deps import admin_user, check_csrf, flash, redirect, render

router = APIRouter(prefix="/admin")


@router.get("")
def admin_home(request: Request, q: str = "", admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    stats = {
        "Users": db.scalar(select(func.count(User.id))),
        "Paying": db.scalar(select(func.count(User.id)).where(User.subscription_status.in_(ACTIVE_SUB_STATUSES))),
        "Domains": db.scalar(select(func.count(Domain.id))),
        "Verified domains": db.scalar(select(func.count(Domain.id)).where(Domain.verified_at.is_not(None))),
        "Waitlist (confirmed)": db.scalar(select(func.count(WaitlistEntry.id)).where(WaitlistEntry.confirmed_at.is_not(None))),
        "Waitlist (all)": db.scalar(select(func.count(WaitlistEntry.id))),
        "Suppressed": db.scalar(select(func.count(Suppression.id))),
    }  # fmt: skip
    stmt = select(User).order_by(User.id.desc()).limit(100)
    if q:
        stmt = select(User).where(User.email.like(f"%{q.lower()}%")).limit(100)
    users = db.scalars(stmt).all()
    rejected = db.scalars(
        select(DeliveryLog).where(DeliveryLog.status.in_(("rejected", "bounced", "complaint")))
        .order_by(DeliveryLog.id.desc()).limit(30)
    ).all()  # fmt: skip
    return render(request, "admin.html", stats=stats, users=users, rejected=rejected, q=q)


@router.post("/users/{user_id}", dependencies=[Depends(check_csrf)])
def admin_user_action(
    user_id: int,
    request: Request,
    action: str = Form(...),
    reason: str = Form(""),
    limit: str = Form(""),
    admin: User = Depends(admin_user),
    db: Session = Depends(get_db),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(404)
    if action == "suspend":
        user.suspended, user.suspended_reason = True, reason[:500]
    elif action == "unsuspend":
        user.suspended, user.suspended_reason = False, ""
    elif action == "limit":
        user.daily_send_limit = int(limit) if limit.isdigit() else None
    db.commit()
    flash(request, f"{user.email}: {action} done.", "success")
    return redirect("/admin")


@router.post("/suppressions/remove", dependencies=[Depends(check_csrf)])
def admin_unsuppress(request: Request, email: str = Form(...), admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    row = db.scalar(select(Suppression).where(Suppression.email == email.strip().lower()))
    if row:
        db.delete(row)
        db.commit()
    flash(request, "Removed from suppression list." if row else "Not found.", "success" if row else "error")
    return redirect("/admin")


@router.get("/waitlist.csv")
def waitlist_csv(admin: User = Depends(admin_user), db: Session = Depends(get_db)):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["email", "confirmed", "current_setup", "domain_count", "created_at", "unsubscribe_token"])
    for e in db.scalars(select(WaitlistEntry).order_by(WaitlistEntry.id)):
        w.writerow([e.email, bool(e.confirmed_at), e.current_setup, e.domain_count, e.created_at, e.confirm_token])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=waitlist.csv"})  # fmt: skip
