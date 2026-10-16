"""Outbound transport.

Delivery is synchronous: the relay hands a message on while the upstream
server is still connected to us. If delivery fails temporarily we answer 4xx
and the upstream server (Gmail, or the contact's provider) keeps the message
in *its* queue and retries. That means we never have to store message bodies.
"""

import asyncio
import logging
import ssl
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate
from pathlib import Path

import aiosmtplib
import dns.asyncresolver
import dns.resolver

from app.config import get_settings
from app.db import utcnow
from app.relay.message import domain_of, make_msgid

log = logging.getLogger(__name__)


@dataclass
class RcptResult:
    code: int
    message: str

    @property
    def ok(self) -> bool:
        return 200 <= self.code < 300

    @property
    def permanent(self) -> bool:
        return self.code >= 500


@dataclass
class DeliveryResult:
    results: dict[str, RcptResult] = field(default_factory=dict)

    @property
    def all_ok(self) -> bool:
        return bool(self.results) and all(r.ok for r in self.results.values())

    @property
    def any_ok(self) -> bool:
        return any(r.ok for r in self.results.values())

    @property
    def all_permanent_fail(self) -> bool:
        return bool(self.results) and all(r.permanent for r in self.results.values())

    def summary(self) -> str:
        return "; ".join(f"{k}: {v.code} {v.message[:120]}" for k, v in self.results.items())


class Transport:
    async def send(self, mail_from: str, rcpts: list[str], data: bytes) -> DeliveryResult:
        raise NotImplementedError


class FileTransport(Transport):
    """Development transport: writes each message to var/outbox/*.eml."""

    def __init__(self, directory: Path):
        self.directory = directory

    async def send(self, mail_from, rcpts, data):
        self.directory.mkdir(parents=True, exist_ok=True)
        stamp = utcnow().strftime("%Y%m%dT%H%M%S%f")
        path = self.directory / f"{stamp}.eml"
        envelope = f"X-Envelope-From: {mail_from}\r\nX-Envelope-To: {', '.join(rcpts)}\r\n"
        path.write_bytes(envelope.encode() + data)
        log.info("wrote %s (from=%s to=%s)", path, mail_from, rcpts)
        return DeliveryResult({r: RcptResult(250, f"written to {path.name}") for r in rcpts})


class MemoryTransport(Transport):
    """Test transport that records messages, optionally failing recipients."""

    def __init__(self):
        self.sent: list[tuple[str, list[str], bytes]] = []
        self.fail: dict[str, RcptResult] = {}

    async def send(self, mail_from, rcpts, data):
        res = DeliveryResult()
        ok = []
        for r in rcpts:
            res.results[r] = self.fail.get(r, RcptResult(250, "ok"))
            if res.results[r].ok:
                ok.append(r)
        if ok:
            self.sent.append((mail_from, ok, data))
        return res


async def _smtp_session(
    host: str,
    port: int,
    mail_from: str,
    rcpts: list[str],
    data: bytes,
    *,
    starttls: str,  # "require" | "opportunistic" | "never"
    username: str = "",
    password: str = "",
) -> DeliveryResult:
    s = get_settings()
    res = DeliveryResult()
    client = aiosmtplib.SMTP(
        hostname=host,
        port=port,
        local_hostname=s.smtp_hostname,
        timeout=60,
        start_tls=False,
        use_tls=False,
    )
    await client.connect()
    try:
        await client.ehlo()
        if starttls != "never" and client.supports_extension("starttls"):
            ctx = ssl.create_default_context()
            if starttls == "opportunistic":
                # MX-to-MX TLS is opportunistic: encrypt even when the cert
                # doesn't match, as every MTA does.
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            await client.starttls(tls_context=ctx)
        elif starttls == "require":
            raise aiosmtplib.SMTPException("server does not offer STARTTLS")
        if username:
            await client.login(username, password)
        size_opt = [f"SIZE={len(data)}"] if client.supports_extension("size") else []
        await client.mail(mail_from, options=size_opt)
        accepted = []
        for r in rcpts:
            try:
                resp = await client.rcpt(r)
                res.results[r] = RcptResult(resp.code, resp.message)
                accepted.append(r)
            except aiosmtplib.SMTPRecipientRefused as exc:
                res.results[r] = RcptResult(exc.code, exc.message)
        if accepted:
            try:
                resp = await client.data(data)
                for r in accepted:
                    res.results[r] = RcptResult(resp.code, resp.message)
            except aiosmtplib.SMTPResponseException as exc:
                for r in accepted:
                    res.results[r] = RcptResult(exc.code, exc.message)
        else:
            await client.rset()
    except aiosmtplib.SMTPResponseException as exc:
        for r in rcpts:
            if r not in res.results or res.results[r].ok:
                res.results[r] = RcptResult(exc.code, exc.message)
    finally:
        try:
            await client.quit()
        except Exception:
            client.close()
    return res


class SmarthostTransport(Transport):
    async def send(self, mail_from, rcpts, data):
        s = get_settings()
        try:
            return await _smtp_session(
                s.smarthost_host, s.smarthost_port, mail_from, rcpts, data,
                starttls="require" if s.smarthost_starttls else "never",
                username=s.smarthost_username, password=s.smarthost_password,
            )  # fmt: skip
        except (aiosmtplib.SMTPException, OSError, asyncio.TimeoutError) as exc:
            return DeliveryResult({r: RcptResult(451, f"smarthost error: {exc}") for r in rcpts})


async def resolve_mx(domain: str) -> list[str]:
    try:
        answer = await dns.asyncresolver.resolve(domain, "MX", lifetime=10)
        hosts = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answer)
        hosts = [h for _, h in hosts if h]
        if not hosts:  # Null MX (RFC 7505): domain accepts no mail.
            return []
        return hosts
    except dns.resolver.NXDOMAIN:
        return []
    except dns.resolver.NoAnswer:
        return [domain]  # implicit MX


class DirectTransport(Transport):
    """Deliver straight to each recipient domain's MX hosts."""

    async def send(self, mail_from, rcpts, data):
        res = DeliveryResult()
        by_domain: dict[str, list[str]] = {}
        for r in rcpts:
            by_domain.setdefault(domain_of(r), []).append(r)
        for domain, group in by_domain.items():
            try:
                hosts = await resolve_mx(domain)
            except Exception as exc:
                for r in group:
                    res.results[r] = RcptResult(451, f"DNS error for {domain}: {exc}")
                continue
            if not hosts:
                for r in group:
                    res.results[r] = RcptResult(550, f"{domain} does not accept mail")
                continue
            last: DeliveryResult | None = None
            for host in hosts[:3]:
                try:
                    last = await _smtp_session(host, 25, mail_from, group, data, starttls="opportunistic")
                except (aiosmtplib.SMTPException, OSError, asyncio.TimeoutError) as exc:
                    last = DeliveryResult({r: RcptResult(451, f"{host}: {exc}") for r in group})
                    continue
                # Try the next MX only if every recipient failed temporarily.
                if any(not (400 <= v.code < 500) for v in last.results.values()):
                    break
            res.results.update(last.results)
        return res


_transport: Transport | None = None


def get_transport() -> Transport:
    global _transport
    if _transport is None:
        s = get_settings()
        _transport = {
            "file": lambda: FileTransport(s.outbox_dir),
            "smtp": SmarthostTransport,
            "direct": DirectTransport,
        }[s.outbound_mode]()
    return _transport


def set_transport(t: Transport | None) -> None:
    global _transport
    _transport = t


# --- System mail (verification links, password resets) ----------------------


def build_system_message(to: str, subject: str, text: str) -> EmailMessage:
    s = get_settings()
    msg = EmailMessage()
    msg["From"] = f"{s.app_name} <{s.system_from}>"
    msg["To"] = to
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(s.relay_domain)
    msg["Auto-Submitted"] = "auto-generated"
    msg.set_content(text)
    return msg


async def send_system_email(to: str, subject: str, text: str) -> bool:
    from app.relay import keys
    from app.relay.auth import sign_message
    from app.relay.message import RawMessage

    s = get_settings()
    msg = RawMessage.parse(build_system_message(to, subject, text).as_bytes())
    pem = keys.relay_private_key()
    data = sign_message(msg, domain_of(s.system_from), s.relay_dkim_selector, pem) if pem else msg.to_bytes()
    if s.outbound_mode == "file":
        log.info("system email to %s: %s\n%s", to, subject, text)
    result = await get_transport().send(f"bounce+sys@{s.relay_domain}", [to], data)
    if not result.all_ok:
        log.error("system email to %s failed: %s", to, result.summary())
    return result.all_ok
