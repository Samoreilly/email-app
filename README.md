# ReplyAs

Keep replying from **you@yourdomain.com** inside Gmail, on phone and desktop, after Google removes "Send as" for non-Google addresses in January 2027.

- **Inbound:** a customer's domain MX points at us. Each sender gets a per-contact *reverse alias* (`r-xxxx@relay.<ourdomain>`), and the message is ARC-sealed, DKIM-signed and forwarded to the customer's Gmail.
- **Replies:** Gmail replies to the reverse alias. We require the From address to be the customer's registered Gmail **and** an aligned, valid DKIM signature. We strip Gmail headers, remap Message-IDs, sign with the customer's domain key and send it to the real contact.
- **New mail:** a web compose page, or "Add contact" to get a reverse alias the customer can email from the Gmail app.
- **Billing:** Stripe Checkout + customer portal, $30/domain/year, 14-day trial without a card.
- **Privacy:** message bodies are never stored. Delivery is synchronous, so if it fails temporarily we answer 4xx and the *sender's* server retries.

## Run locally

```sh
uv sync
uv run uvicorn app.web.main:app --reload       # http://localhost:8000
uv run python -m app.relay.server               # SMTP on :2525
uv run pytest                                   # 28 tests
```

In dev (`OUTBOUND_MODE=file`), outgoing mail, including signup verification links, is written to `var/outbox/*.eml` and logged to the console.

Try the relay by hand:

```sh
swaks --server localhost:2525 --to you@yourdomain.test --from friend@example.net
```

(The domain must exist and be verified in the database. Use the dashboard, or set `verified_at` by hand while testing.)

## Layout

| Path | What |
| --- | --- |
| `app/relay/inbound.py` | contact → Gmail rewrite (reverse aliases, ARC, DKIM) |
| `app/relay/outbound.py` | Gmail reply → contact (sender verification, header stripping, Message-ID mapping), plus compose |
| `app/relay/routing.py` | recipient classification; refuses everything else (no open relay) |
| `app/relay/bounces.py` | VERP bounce addresses, DSN + ARF complaint parsing → suppression list |
| `app/relay/server.py` | aiosmtpd listener |
| `app/mailer.py` | outbound transports: direct MX, smarthost, file |
| `app/dns_check.py`, `app/cloudflare.py` | onboarding wizard: expected records, live checker, one-click Cloudflare |
| `app/billing.py` | Stripe Checkout, portal, webhooks, per-domain quantity |
| `app/web/` | FastAPI routes; templates in `app/templates/` |

See [docs/DEPLOY.md](docs/DEPLOY.md) to go live, including the Stripe setup, and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design decisions and risks.
