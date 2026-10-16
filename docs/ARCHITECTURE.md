# Architecture and decisions

## Stack

- **Python 3.13, FastAPI, Jinja templates**: one language for web and mail, and server-rendered pages that work well on phones.
- **aiosmtpd** for inbound SMTP, **dkimpy / authheaders / pyspf** for DKIM, ARC, SPF and DMARC. No hand-rolled crypto.
- **Postgres** in production, SQLite in dev and tests, via SQLAlchemy 2.
- **Own SMTP in and out** (`OUTBOUND_MODE=direct`), with a smarthost fallback.

## Key decisions

- **No message storage.** Relaying is synchronous inside the SMTP transaction. On a temporary failure we return 4xx and the upstream server keeps the message and retries, so we never need a queue on disk.
- **Sender verification on replies:** the From header must equal the account's Gmail (dots, +tags and googlemail normalised), *and* there must be a valid DKIM signature aligned with the From domain. Otherwise we reject with 550. This is what keeps us from being an open relay.
- **Inbound mail is from the relay domain**, DKIM-signed by us and ARC-sealed, so DMARC passes at Gmail even though we rewrote From.
- **Outbound mail is from the customer's domain**, signed with a per-domain 2048-bit key (encrypted at rest with a key derived from `SECRET_KEY`). The envelope sender is `bounce+<log id>-<mac>@customerdomain`, so SPF aligns and async bounces can be traced without storing anything.
- **Message-ID mapping:** Gmail's ids (`<CA...@mail.gmail.com>`) are swapped for `<uuid@customerdomain>` on the way out, and swapped back in `In-Reply-To`/`References` on the way in, so threads join on both sides.
- **Reply-all self copies** (customer@gmail replying to their own custom address) are dropped once DKIM checks out.
- **Billing per domain:** the Stripe subscription quantity equals the number of domains, and is synced when domains are added or removed.

## Riskiest assumptions, and cheap tests

| Assumption | Cheap test |
| --- | --- |
| People will pay ~$30/yr instead of moving to Zoho free or Workspace | Waitlist with pricing visible (live now). Measure confirmed sign-ups per post. Run a pre-sale by opening Checkout to the waitlist before launch. |
| Gmail delivers forwarded mail from `r-…@relay` to the Inbox, not Spam | Send 50 varied messages through a test domain into 3 Gmail accounts and count Inbox placement |
| Replies sent from our IP reach Outlook/Yahoo inboxes | mail-tester.com, plus test accounts at Outlook.com, Yahoo and iCloud. Have a smarthost ready as a fallback |
| Gmail's own DKIM keys verify reliably after Gmail processing | Run 20 replies from the Android app, iOS app and web, and check the rejection log is empty |
| Users accept that new emails go through compose or a contact alias | Watch how often compose is used versus replies. Interview the first 10 users |
| Hetzner will unblock port 25 | Ask support in week 1; otherwise budget for a smarthost |

## Known limitations / next steps

- With several recipients in one SMTP transaction, the reply is a single answer. Partial failures are logged but not retried individually.
- No inbound spam scoring yet beyond DMARC p=reject enforcement. Next step: put rspamd in front, or call it from `relay_inbound`.
- Rate limiting for web logins is per process. Use Redis if you run more than one web worker.
- Schema changes need a migration tool (add Alembic before the first schema change after launch).
- Chrome extension (From dropdown on desktop) and migration helpers are post-MVP.
