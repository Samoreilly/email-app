import os
import sys
from pathlib import Path

import dkim
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


@pytest.fixture(autouse=True)
def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path}/test.db")
    monkeypatch.setenv("RELAY_DKIM_KEY_PATH", str(tmp_path / "relay.pem"))
    monkeypatch.setenv("RELAY_DOMAIN", "relay.test")
    monkeypatch.setenv("SMTP_HOSTNAME", "mx.relay.test")
    monkeypatch.setenv("BASE_URL", "http://testserver")
    monkeypatch.setenv("OUTBOUND_MODE", "file")
    monkeypatch.setenv("OUTBOX_DIR", str(tmp_path / "outbox"))
    monkeypatch.setenv("STRIPE_SECRET_KEY", "")
    monkeypatch.setenv("STRIPE_PRICE_ID", "")
    monkeypatch.setenv("ADMIN_EMAILS", "admin@gmail.com")
    from app import config, crypto, db, mailer
    from app.relay import keys

    config.get_settings.cache_clear()
    crypto._fernet.cache_clear()
    keys.relay_private_key.cache_clear()
    db.init_engine()
    db.create_all()
    transport = mailer.MemoryTransport()
    mailer.set_transport(transport)
    yield
    mailer.set_transport(None)


@pytest.fixture
def transport():
    from app import mailer

    return mailer.get_transport()


@pytest.fixture
def session():
    from app.db import new_session

    s = new_session()
    yield s
    s.close()


class FakeDNS:
    def __init__(self):
        self.txt: dict[str, str] = {}

    def __call__(self, name, timeout=5):
        if isinstance(name, bytes):
            name = name.decode()
        value = self.txt.get(name.rstrip(".").lower())
        return value.encode() if value else None


@pytest.fixture
def dns():
    return FakeDNS()


@pytest.fixture
def gmail_key(dns):
    """A stand-in for Gmail's DKIM key, published in the fake DNS."""
    from app.crypto import generate_dkim_keypair

    pem, record = generate_dkim_keypair(1024)
    dns.txt["20230601._domainkey.gmail.com"] = record

    def sign(raw: bytes) -> bytes:
        sig = dkim.sign(raw, b"20230601", b"gmail.com", pem,
                        include_headers=[b"from", b"to", b"subject", b"message-id", b"date"])
        return sig + raw

    return sign


@pytest.fixture
def account(session):
    """A verified customer with alice@example.org forwarding to Gmail."""
    from datetime import timedelta

    from app.db import utcnow
    from app.models import Address, Domain, User
    from app.relay.keys import new_domain_keys
    from app.security import hash_password

    priv, pub = new_domain_keys()
    user = User(email="customer@gmail.com", name="Cust", password_hash=hash_password("pw-123456789"),
                email_verified_at=utcnow(), trial_ends_at=utcnow() + timedelta(days=14))
    dom = Domain(user=user, name="example.org", verified_at=utcnow(), dkim_ok=True,
                 dkim_selector="replyas1", dkim_private_key=priv, dkim_public_record=pub)
    addr = Address(domain=dom, local_part="alice", display_name="Alice Example")
    session.add_all([user, dom, addr])
    session.commit()
    return user
