import hashlib
import hmac
import json
import re
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models import Domain, User, WaitlistEntry


@pytest.fixture
def client():
    from app.web.main import create_app

    with TestClient(create_app()) as c:
        yield c


def csrf(client, path="/"):
    html = client.get(path).text
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


def signup(client, email="new@gmail.com"):
    tok = csrf(client, "/signup")
    return client.post("/signup", data={"csrf": tok, "email": email, "password": "correct-horse-battery",
                                        "name": "New", "terms": "1"}, follow_redirects=False)


def test_landing_and_legal_pages(client):
    for path in ["/", "/privacy", "/terms", "/dpa", "/guide/gmail-send-as-alternative", "/healthz", "/sitemap.xml"]:
        assert client.get(path).status_code == 200, path
    assert "Send as" in client.get("/").text


def test_waitlist_double_opt_in(client, session, transport):
    tok = csrf(client)
    r = client.post("/waitlist", data={"csrf": tok, "email": "Fan@Example.com", "consent": "1",
                                       "current_setup": "cloudflare"}, follow_redirects=False)
    assert r.status_code == 303
    entry = session.scalar(select(WaitlistEntry))
    assert entry.email == "fan@example.com" and entry.confirmed_at is None
    assert transport.sent and transport.sent[0][1] == ["fan@example.com"]
    client.get(f"/waitlist/confirm/{entry.confirm_token}")
    session.refresh(entry)
    assert entry.confirmed_at is not None


def test_csrf_required(client):
    r = client.post("/waitlist", data={"email": "x@y.com", "consent": "1"})
    assert r.status_code == 400


def test_signup_verify_and_dashboard(client, session, transport):
    r = signup(client)
    assert r.headers["location"] == "/dashboard"
    body = transport.sent[-1][2].decode()
    link = re.search(r"http://testserver(/verify-email/\S+)", body.replace("=\r\n", "")).group(1)
    assert client.get(link).status_code == 200
    user = session.scalar(select(User).where(User.email == "new@gmail.com"))
    session.refresh(user)
    assert user.email_verified_at and user.in_trial
    assert "Get set up" in client.get("/dashboard").text


def test_dashboard_requires_login(client):
    r = client.get("/dashboard", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


def test_add_domain_shows_dns_records(client, session):
    signup(client)
    tok = csrf(client, "/domains/new")
    r = client.post("/domains", data={"csrf": tok, "name": "https://www.MyBiz.ie/", "local_part": "hello"},
                    follow_redirects=True)
    assert r.status_code == 200
    assert "mybiz.ie" in r.text and "v=DKIM1" in r.text and "include:" in r.text
    d = session.scalar(select(Domain))
    assert d.name == "mybiz.ie" and d.addresses[0].local_part == "hello"
    # Trial allows one domain only.
    tok = csrf(client, "/domains/new")
    r = client.post("/domains", data={"csrf": tok, "name": "second.ie"})
    assert r.status_code == 400 and "Subscribe" in r.text


def test_cannot_register_gmail_or_others_domain(client):
    signup(client)
    tok = csrf(client, "/domains/new")
    assert client.post("/domains", data={"csrf": tok, "name": "gmail.com"}).status_code == 400


def test_other_users_domain_is_404(client, session, account):
    signup(client)
    d = session.scalar(select(Domain).where(Domain.name == "example.org"))
    assert client.get(f"/domains/{d.id}").status_code == 404


def test_login_logout(client, account):
    tok = csrf(client, "/login")
    r = client.post("/login", data={"csrf": tok, "email": "customer@gmail.com", "password": "nope"})
    assert r.status_code == 400
    r = client.post("/login", data={"csrf": tok, "email": "customer@gmail.com", "password": "pw-123456789"},
                    follow_redirects=False)
    assert r.headers["location"] == "/dashboard"
    assert client.get("/contacts").status_code == 200


def test_billing_page_without_stripe(client, account):
    tok = csrf(client, "/login")
    client.post("/login", data={"csrf": tok, "email": "customer@gmail.com", "password": "pw-123456789"})
    assert "Payments are being set up" in client.get("/billing").text


def _signed(payload: bytes, secret: str) -> str:
    ts = int(time.time())
    sig = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def test_stripe_webhook_updates_subscription(client, session, account, monkeypatch):
    from app import config

    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_test")
    config.get_settings.cache_clear()
    account.stripe_customer_id = "cus_123"
    session.commit()
    event = {
        "id": "evt_1", "type": "customer.subscription.updated",
        "data": {"object": {"id": "sub_1", "object": "subscription", "customer": "cus_123", "status": "active",
                            "metadata": {}, "items": {"data": [{"id": "si_1", "quantity": 1,
                                                                 "current_period_end": 1830000000}]}}},
    }
    payload = json.dumps(event).encode()
    r = client.post("/billing/webhook", content=payload, headers={"stripe-signature": "t=1,v1=bad"})
    assert r.status_code == 400
    r = client.post("/billing/webhook", content=payload, headers={"stripe-signature": _signed(payload, "whsec_test")})
    assert r.status_code == 200, r.text
    session.refresh(account)
    assert account.subscription_status == "active" and account.subscribed
    assert account.subscription_period_end.year == 2027
    # Replays are ignored.
    r = client.post("/billing/webhook", content=payload, headers={"stripe-signature": _signed(payload, "whsec_test")})
    assert r.status_code == 200


def test_account_deletion(client, session, account):
    tok = csrf(client, "/login")
    client.post("/login", data={"csrf": tok, "email": "customer@gmail.com", "password": "pw-123456789"})
    tok = csrf(client, "/settings")
    r = client.post("/settings/delete", data={"csrf": tok, "password": "pw-123456789"})
    assert "Account deleted" in r.text
    session.expire_all()
    assert session.scalar(select(User)) is None and session.scalar(select(Domain)) is None
