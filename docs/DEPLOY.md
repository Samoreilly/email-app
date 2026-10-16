# Going live

## 1. Server (EU)

- A VPS with a static IPv4, e.g. Hetzner Cloud (Falkenstein, Nuremberg or Helsinki), CX22 is enough.
- **Port 25 outbound:** Hetzner blocks it on new accounts. Open a support request once your first invoice is paid. Without it, use `OUTBOUND_MODE=smtp` with a smarthost whose terms allow relaying personal mail.
- **Reverse DNS (PTR)** for the IP must be `MX_HOST` (e.g. `mx.replyas.app`). Set it in the Hetzner console.
- Install Docker and the Docker Compose plugin.

## 2. Domains and DNS for the service

Choose a product domain, e.g. `replyas.app`, and set in `.env`:

```
APP_HOST=replyas.app
BASE_URL=https://replyas.app
MX_HOST=mx.replyas.app
SMTP_HOSTNAME=mx.replyas.app
RELAY_DOMAIN=relay.replyas.app
SPF_INCLUDE=spf.replyas.app
```

Then publish the records printed by:

```sh
docker compose run --rm web python -m scripts.infra_dns   # with SERVER_IP=... set
```

Those are: A for the app and MX host, MX for the relay domain, SPF for the relay domain and the `spf.` include, DMARC, and the relay DKIM key. The relay DKIM key is generated on first run in the `appdata` volume. **Back it up**, along with `SECRET_KEY`, which encrypts every customer's DKIM key.

## 3. Start

```sh
cp .env.example .env    # fill it in; generate SECRET_KEY and POSTGRES_PASSWORD
docker compose up -d --build
docker compose logs -f smtp web
```

Caddy gets TLS certificates for `APP_HOST` and `MX_HOST`. The SMTP server picks up the MX certificate for STARTTLS automatically; until it exists, the server runs plaintext only.

## 4. Stripe

1. Create or activate your Stripe account (Ireland). Complete business details and bank account.
2. Run the setup in **test mode** first:
   ```sh
   docker compose run --rm -e STRIPE_SECRET_KEY=sk_test_... -e BASE_URL=https://replyas.app web python scripts/stripe_setup.py
   ```
   It creates the product, a $30/year recurring price, the webhook endpoint (`/billing/webhook`) and the customer portal configuration. Then it prints `STRIPE_PRICE_ID` and `STRIPE_WEBHOOK_SECRET`.
3. Put `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID` and `STRIPE_WEBHOOK_SECRET` in `.env`, then run `docker compose up -d`.
4. Test with card `4242 4242 4242 4242`. The billing page should show "Active" (or "Trialing") within seconds.
5. Repeat with the live key (`sk_live_...`).
6. **VAT:** once you're VAT-registered, enable Stripe Tax in the dashboard and set `STRIPE_AUTOMATIC_TAX=true`. Prices are tax-exclusive.

Change the price with `PRICE_CENTS=2500 PRICE_CURRENCY=eur` when running the script, and update `PRICE_DISPLAY`.

## 5. Before opening signups

Keep `SIGNUPS_OPEN=false` (waitlist only) until you've done the following:

- [ ] Sent mail from an outside account to your own test domain, and it arrived in Gmail (not Spam).
- [ ] Replied from the Gmail **Android/iOS app** and from the web; the reply arrived from your domain with DKIM=pass and DMARC=pass. Check with "Show original".
- [ ] Checked a reply at https://www.mail-tester.com and scored 9+/10.
- [ ] Confirmed Gmail's real DKIM keys verify (they rotate selectors; we look up whatever `s=` the message uses).
- [ ] Bought test domains on Cloudflare and on a registrar, and run through the wizard on your phone.
- [ ] Added your admin email to `ADMIN_EMAILS` and checked `/admin`.
- [ ] Registered the relay domain with Google Postmaster Tools.

## 6. Operations

- Backups: `pg_dump` the `db` service daily, off-site. Back up the `appdata` volume (relay DKIM key).
- Logs: `docker compose logs smtp`. Each relayed message logs one line with the envelope and outcome.
- Abuse: `/admin` shows rejections, bounces and complaints. You can suspend users and set per-user daily limits there. `postmaster@` and `abuse@` on the relay domain are forwarded to `OPERATOR_EMAIL`.
