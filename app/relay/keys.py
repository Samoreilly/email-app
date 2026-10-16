"""Access to DKIM private keys."""

import logging
from functools import lru_cache

from app import crypto
from app.config import get_settings
from app.models import Domain

log = logging.getLogger(__name__)


@lru_cache
def relay_private_key() -> bytes | None:
    """The relay domain's DKIM key. Generated on first use if missing, and the
    DNS record to publish is logged."""
    s = get_settings()
    path = s.relay_dkim_key_path
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        pem, record = crypto.generate_dkim_keypair()
        path.write_bytes(pem)
        path.chmod(0o600)
        log.warning(
            "Generated relay DKIM key at %s. Publish this TXT record:\n  %s._domainkey.%s  \"%s\"",
            path, s.relay_dkim_selector, s.relay_domain, record,
        )  # fmt: skip
    return path.read_bytes()


def relay_public_record() -> str:
    pem = relay_private_key()
    return crypto.public_record_from_pem(pem) if pem else ""


def domain_private_key(domain: Domain) -> bytes:
    return crypto.decrypt(domain.dkim_private_key).encode()


def new_domain_keys() -> tuple[str, str]:
    """Return (encrypted private PEM, public TXT record) for a new domain."""
    pem, record = crypto.generate_dkim_keypair()
    return crypto.encrypt(pem.decode()), record
