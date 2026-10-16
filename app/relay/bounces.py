"""Bounces (DSNs) and spam complaints (ARF feedback reports).

Every message we send uses an envelope sender of the form
bounce+<log id>-<mac>@domain, so a later bounce tells us exactly which
delivery failed without storing anything about the message itself.
"""

import email
import logging
import re
from email import policy

from sqlalchemy.orm import Session

from app.crypto import short_mac
from app.models import DeliveryLog
from app.relay.contacts import suppress

log = logging.getLogger(__name__)


def bounce_address(log_id: int, domain: str) -> str:
    ref = str(log_id)
    return f"bounce+{ref}-{short_mac('bounce:' + ref)}@{domain}"


def parse_bounce_ref(ref: str) -> int | None:
    m = re.fullmatch(r"(\d+)-([a-z2-7]+)", ref)
    if not m or short_mac("bounce:" + m.group(1)) != m.group(2):
        return None
    return int(m.group(1))


def _strip_type(value: str) -> str:
    # "rfc822; someone@example.com" -> "someone@example.com"
    return value.split(";", 1)[-1].strip().strip("<>").lower()


def parse_dsn(raw: bytes) -> list[tuple[str, str, str]]:
    """Return [(recipient, action, status)] from a delivery status notification."""
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    out = []
    for part in msg.walk():
        if part.get_content_type() != "message/delivery-status":
            continue
        payload = part.get_payload()
        # compat32 parses delivery-status into a list of header blocks.
        blocks = payload if isinstance(payload, list) else []
        for block in blocks:
            rcpt = block.get("Final-Recipient") or block.get("Original-Recipient")
            if rcpt:
                out.append(
                    (_strip_type(rcpt), (block.get("Action") or "").lower(), block.get("Status") or "")
                )
    return out


def parse_arf(raw: bytes) -> list[str]:
    """Return the original recipients named in a spam complaint (ARF)."""
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    if msg.get_content_type() != "multipart/report" or msg.get_param("report-type") != "feedback-report":
        return []
    out = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype == "message/feedback-report":
            blocks = part.get_payload()
            for block in blocks if isinstance(blocks, list) else []:
                rcpt = block.get("Original-Rcpt-To")
                if rcpt:
                    out.append(_strip_type(rcpt))
        elif ctype in ("message/rfc822", "text/rfc822-headers") and not out:
            inner = part.get_payload()
            if isinstance(inner, list) and inner:
                inner = inner[0]
            if isinstance(inner, str):
                inner = email.message_from_string(inner)
            to = inner.get("To") if inner is not None else None
            if to:
                out.extend(a.lower() for _, a in email.utils.getaddresses([to]) if a)
    return out


def handle_bounce(db: Session, ref: str, raw: bytes) -> None:
    log_id = parse_bounce_ref(ref)
    entry = db.get(DeliveryLog, log_id) if log_id else None

    complaints = parse_arf(raw)
    for rcpt in complaints:
        suppress(db, rcpt, "complaint", "Spam complaint (feedback report)")
    if complaints:
        if entry:
            entry.status = "complaint"
            entry.detail = "Recipient marked the message as spam"
        log.warning("complaint for %s (log %s)", complaints, log_id)
        return

    for rcpt, action, status in parse_dsn(raw):
        if action != "failed" or not status.startswith("5"):
            continue
        # 5.1.x = bad mailbox/domain, 5.2.1 = disabled: never going to work.
        if re.match(r"5\.(1\.\d|2\.1)", status):
            suppress(db, rcpt, "bounce", f"Hard bounce {status}")
        if entry:
            entry.status = "bounced"
            entry.detail = f"Bounced: {status} for {rcpt}"
    if entry is None:
        log.info("bounce with unknown ref %r ignored", ref)
