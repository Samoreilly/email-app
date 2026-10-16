"""One-time Stripe setup: product, yearly per-domain price, webhook, portal.

Usage:
    STRIPE_SECRET_KEY=sk_live_... BASE_URL=https://yourdomain uv run python scripts/stripe_setup.py

Prints the env values to put in .env. Safe to re-run: it reuses the product,
price and webhook if they already exist.
"""

import os
import sys

import stripe

key = os.environ.get("STRIPE_SECRET_KEY")
base = os.environ.get("BASE_URL", "").rstrip("/")
amount = int(os.environ.get("PRICE_CENTS", "3000"))
currency = os.environ.get("PRICE_CURRENCY", "usd")
name = os.environ.get("APP_NAME", "ReplyAs")
if not key or not base.startswith("https://"):
    sys.exit("Set STRIPE_SECRET_KEY and BASE_URL (https://...)")

c = stripe.StripeClient(key)

products = [p for p in c.v1.products.list(params={"active": True, "limit": 100}).data
            if (p.metadata or {}).get("app") == "replyas"]
product = products[0] if products else c.v1.products.create(
    params={"name": f"{name}: per domain", "metadata": {"app": "replyas"},
            "description": "Send and reply as your own domain from Gmail. Billed per domain per year."}
)
prices = [p for p in c.v1.prices.list(params={"product": product.id, "active": True}).data
          if p.unit_amount == amount and p.currency == currency and p.recurring and p.recurring.interval == "year"]
price = prices[0] if prices else c.v1.prices.create(
    params={"product": product.id, "unit_amount": amount, "currency": currency,
            "recurring": {"interval": "year"}, "tax_behavior": "exclusive"}
)

url = f"{base}/billing/webhook"
events = [
    "checkout.session.completed", "customer.subscription.created", "customer.subscription.updated",
    "customer.subscription.deleted", "customer.subscription.paused", "customer.subscription.resumed",
    "invoice.paid", "invoice.payment_failed",
]
existing = [w for w in c.v1.webhook_endpoints.list().data if w.url == url]
secret = None
if existing:
    c.v1.webhook_endpoints.update(existing[0].id, params={"enabled_events": events})
    print(f"# Webhook already exists ({existing[0].id}); keep your existing STRIPE_WEBHOOK_SECRET")
else:
    secret = c.v1.webhook_endpoints.create(params={"url": url, "enabled_events": events}).secret

c.v1.billing_portal.configurations.create(params={
    "business_profile": {"headline": f"{name} billing",
                         "privacy_policy_url": f"{base}/privacy", "terms_of_service_url": f"{base}/terms"},
    "features": {
        "invoice_history": {"enabled": True},
        "payment_method_update": {"enabled": True},
        "customer_update": {"enabled": True, "allowed_updates": ["email", "address", "tax_id", "name"]},
        "subscription_cancel": {"enabled": True, "mode": "at_period_end",
                                "cancellation_reason": {"enabled": True, "options": [
                                    "too_expensive", "missing_features", "switched_service", "unused", "other"]}},
    },
    "default_return_url": f"{base}/billing",
})

print(f"STRIPE_PRICE_ID={price.id}")
if secret:
    print(f"STRIPE_WEBHOOK_SECRET={secret}")
