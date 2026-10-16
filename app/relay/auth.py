"""Email authentication: checking incoming mail, signing outgoing mail.

Everything cryptographic goes through dkimpy / authheaders / pyspf; nothing is
hand-rolled here.
"""

import logging
import re
from collections.abc import Callable

import dkim
from authheaders import authenticate_message

from app.relay.message import RawMessage, domain_of

log = logging.getLogger(__name__)

# Optional DNS override (tests inject a fake resolver: name bytes -> TXT bytes).
DnsFunc = Callable[[bytes], bytes] | None

DKIM_SIGN_HEADERS = [
    b"from", b"to", b"cc", b"subject", b"date", b"message-id", b"reply-to",
    b"in-reply-to", b"references", b"mime-version", b"content-type",
    b"content-transfer-encoding", b"list-unsubscribe",
]  # fmt: skip


def authenticate(
    raw: bytes,
    srv_id: str,
    ip: str | None,
    helo: str | None,
    mail_from: str | None,
    dnsfunc: DnsFunc = None,
) -> str:
    """Return an Authentication-Results header *value* (without the name)."""
    kwargs = {"dnsfunc": dnsfunc} if dnsfunc else {}
    try:
        header = authenticate_message(
            raw, srv_id, spf=bool(ip), ip=ip, mail_from=mail_from or "", helo=helo or "",
            dkim=True, arc=True, dmarc=True, **kwargs,
        )  # fmt: skip
    except Exception as exc:  # DNS failures, malformed mail
        log.warning("authentication check failed: %s", exc)
        return f"{srv_id}; none"
    return header.split(":", 1)[1].strip()


def dmarc_reject(auth_results: str) -> bool:
    """True when DMARC failed and the sender's policy says reject."""
    text = auth_results.lower()
    return bool(re.search(r"\bdmarc=fail\b", text)) and "policy.dmarc=reject" in text


def dkim_sign(raw: bytes, domain: str, selector: str, private_pem: bytes) -> bytes:
    """Return the DKIM-Signature header field bytes to prepend."""
    msg = RawMessage.parse(raw)
    present = {n.lower().encode() for n, _ in msg.headers}
    include = [h for h in DKIM_SIGN_HEADERS if h in present]
    return dkim.sign(
        raw,
        selector.encode(),
        domain.encode(),
        private_pem,
        canonicalize=(b"relaxed", b"relaxed"),
        include_headers=include,
    )


def arc_sign(raw: bytes, domain: str, selector: str, private_pem: bytes, srv_id: str) -> list[bytes]:
    """Return ARC header fields to prepend (empty if ARC can't be applied)."""
    try:
        return dkim.arc_sign(
            raw, selector.encode(), domain.encode(), private_pem, srv_id.encode()
        )
    except Exception as exc:
        log.info("ARC signing skipped: %s", exc)
        return []


def sign_message(
    msg: RawMessage,
    domain: str,
    selector: str,
    private_pem: bytes,
    *,
    arc_srv_id: str | None = None,
) -> bytes:
    """Optionally ARC-seal, then DKIM-sign, returning the final bytes."""
    if arc_srv_id:
        for field in reversed(arc_sign(msg.to_bytes(), domain, selector, private_pem, arc_srv_id)):
            msg.prepend_raw(field)
    msg.prepend_raw(dkim_sign(msg.to_bytes(), domain, selector, private_pem))
    return msg.to_bytes()


def has_aligned_dkim_pass(raw: bytes, from_addr: str, dnsfunc: DnsFunc = None) -> bool:
    """True if at least one DKIM signature verifies with d= equal to (or a
    parent of) the From address's domain."""
    from_domain = domain_of(from_addr)
    msg = RawMessage.parse(raw)
    sigs = msg.get_all("DKIM-Signature")
    if not sigs:
        return False
    d = dkim.DKIM(raw)
    for idx, sig in enumerate(sigs):
        m = re.search(r"(?:^|;)\s*d\s*=\s*([^;\s]+)", sig)
        if not m:
            continue
        sig_domain = m.group(1).lower()
        if not (from_domain == sig_domain or from_domain.endswith("." + sig_domain)):
            continue
        try:
            kwargs = {"dnsfunc": dnsfunc} if dnsfunc else {}
            if d.verify(idx=idx, **kwargs):
                return True
        except Exception as exc:
            log.info("DKIM verify error for d=%s: %s", sig_domain, exc)
    return False
