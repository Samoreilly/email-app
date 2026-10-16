"""The SMTP listener (port 25 in production).

Run with:  uv run python -m app.relay.server
"""

import asyncio
import logging
import signal
import ssl

from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope as SMTPEnvelope, Session as SMTPSession

from app.config import get_settings
from app.db import create_all, new_session
from app.mailer import get_transport
from app.relay import keys
from app.relay.inbound import Envelope
from app.relay.maintenance import maintenance_loop
from app.relay.pipeline import process
from app.relay.routing import Refused, classify

log = logging.getLogger("relay")


class RelayHandler:
    async def handle_RCPT(self, server, session: SMTPSession, envelope: SMTPEnvelope, address: str, rcpt_options):
        s = get_settings()
        if len(envelope.rcpt_tos) >= s.max_recipients_per_message * 5:
            return "452 4.5.3 Too many recipients"
        db = new_session()
        try:
            classify(db, address)
        except Refused as exc:
            log.info("refused rcpt %s from %s (%s): %s", address, envelope.mail_from, session.peer, exc.message)
            return exc.smtp
        finally:
            db.close()
        envelope.rcpt_tos.append(address)
        return "250 2.1.5 OK"

    async def handle_DATA(self, server, session: SMTPSession, envelope: SMTPEnvelope):
        raw = envelope.original_content or envelope.content
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogateescape")
        env = Envelope(
            mail_from=envelope.mail_from or "",
            rcpts=list(envelope.rcpt_tos),
            peer_ip=session.peer[0] if session.peer else None,
            helo=session.host_name,
        )
        db = new_session()
        try:
            outcome = await process(db, raw, env, get_transport())
        except Exception:
            log.exception("processing failed for %s -> %s", env.mail_from, env.rcpts)
            db.rollback()
            return "451 4.3.0 Internal error, please retry"
        finally:
            db.close()
        log.info("%s -> %s: %s", env.mail_from, env.rcpts, outcome.smtp)
        return outcome.smtp


def _tls_context() -> ssl.SSLContext | None:
    s = get_settings()
    if not (s.smtp_tls_cert and s.smtp_tls_key):
        return None
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(s.smtp_tls_cert, s.smtp_tls_key)
    return ctx


class RelayController(Controller):
    def factory(self):
        s = get_settings()
        return SMTP(
            self.handler,
            hostname=s.smtp_hostname,
            data_size_limit=s.max_message_bytes,
            enable_SMTPUTF8=True,
            decode_data=False,
            tls_context=_tls_context(),
            require_starttls=False,  # MX servers must accept plaintext too
            ident=f"{s.app_name} relay",
        )


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = get_settings()
    create_all()
    keys.relay_private_key()  # generate on first run and log the DNS record
    controller = RelayController(RelayHandler(), hostname=s.smtp_listen_host, port=s.smtp_listen_port)
    controller.start()
    log.info("SMTP relay listening on %s:%s (outbound=%s)", s.smtp_listen_host, s.smtp_listen_port, s.outbound_mode)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    task = asyncio.create_task(maintenance_loop())
    await stop.wait()
    task.cancel()
    controller.stop()


if __name__ == "__main__":
    asyncio.run(main())
