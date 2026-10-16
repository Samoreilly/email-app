"""Process one SMTP transaction: route every recipient, then relay."""

import logging

from sqlalchemy.orm import Session

from app.config import get_settings
from app.mailer import Transport
from app.relay import auth
from app.relay.bounces import handle_bounce
from app.relay.inbound import Envelope, Outcome, relay_inbound
from app.relay.outbound import relay_reply
from app.relay.routing import Refused, Route, classify

log = logging.getLogger(__name__)


async def process(
    db: Session, raw: bytes, env: Envelope, transport: Transport, dnsfunc: auth.DnsFunc = None
) -> Outcome:
    """Return the single SMTP reply for DATA.

    With several recipients we answer with the "worst" outcome only if
    nothing was delivered; once anything has gone out we must say 250, or the
    sender would retry and duplicate it.
    """
    routes: list[Route] = []
    for rcpt in env.rcpts:
        try:
            routes.append(classify(db, rcpt))
        except Refused:
            continue  # already refused at RCPT time
    if not routes:
        return Outcome(554, "5.5.1 No valid recipients", "rejected")

    outcomes: list[Outcome] = []

    # Bounces / complaints / operator mail.
    for r in routes:
        if r.kind == "bounce":
            handle_bounce(db, r.bounce_ref, raw)
            outcomes.append(Outcome(250, "2.0.0 OK", "accepted"))
        elif r.kind == "operator":
            s = get_settings()
            if s.operator_email:
                await transport.send(f"bounce+op@{s.relay_domain}", [s.operator_email], raw)
            log.warning("operator mail for %s from %s", r.rcpt, env.mail_from)
            outcomes.append(Outcome(250, "2.0.0 OK", "accepted"))

    # Inbound: one copy per customer, however many of their addresses it hit.
    seen_users = set()
    for r in routes:
        if r.kind == "inbound" and r.user.id not in seen_users:
            seen_users.add(r.user.id)
            outcomes.append(
                await relay_inbound(db, raw, env, r.user, r.domain, r.address, r.rcpt, transport, dnsfunc)
            )

    # Replies: group the reverse aliases per customer into one outgoing message.
    by_user: dict[int, list[Route]] = {}
    for r in routes:
        if r.kind == "reply":
            by_user.setdefault(r.user.id, []).append(r)
    for group in by_user.values():
        outcomes.append(
            await relay_reply(db, raw, env, group[0].user, [r.contact for r in group], transport, dnsfunc)
        )

    db.commit()
    if any(o.code < 300 for o in outcomes):
        return next(o for o in outcomes if o.code < 300)
    if any(400 <= o.code < 500 for o in outcomes):
        return next(o for o in outcomes if 400 <= o.code < 500)
    return outcomes[0]
