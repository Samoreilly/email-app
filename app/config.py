"""Settings, read from environment variables (or a .env file).

Every setting has a development-friendly default so `uv run` works out of the
box. See .env.example for what to set in production.
"""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- Product -----------------------------------------------------------
    app_name: str = "ReplyAs"
    base_url: str = "http://localhost:8000"
    support_email: str = "support@replyas.example"
    # Who runs the service (shown in privacy policy / DPA).
    company_name: str = "ReplyAs"
    company_address: str = "Dublin, Ireland"
    # Listed as sub-processors in the privacy policy and DPA.
    hosting_provider: str = "Hetzner Online GmbH (Germany, EU)"
    outbound_provider: str = ""  # e.g. a smarthost company, if outbound_mode=smtp
    # While False the landing page only offers the waitlist.
    signups_open: bool = True
    admin_emails: str = ""  # comma separated

    # --- Security ------------------------------------------------------------
    # Signs sessions and tokens and derives the key that encrypts DKIM private
    # keys at rest. Never change it once customers exist.
    secret_key: str = "dev-insecure-secret-change-me"
    session_cookie_secure: bool = False

    # --- Storage -------------------------------------------------------------
    database_url: str = "sqlite:///./var/app.db"

    # --- Mail infrastructure -------------------------------------------------
    # Domain that hosts reverse aliases (r-xxxx@relay_domain). Needs MX -> us.
    relay_domain: str = "relay.replyas.example"
    # Hostname customers point their MX records at.
    mx_host: str = "mx.replyas.example"
    # Customers add `include:<spf_include>` to their SPF record.
    spf_include: str = "spf.replyas.example"
    # Used in Authentication-Results / ARC and in our SMTP greeting.
    smtp_hostname: str = "mx.replyas.example"
    # DKIM key for the relay domain (signs forwarded mail and system mail).
    relay_dkim_selector: str = "rs1"
    relay_dkim_key_path: Path = Path("var/relay_dkim.pem")
    # Selector used for keys we generate for customer domains.
    customer_dkim_selector: str = "replyas1"
    # Prefix for the ownership TXT record: _<prefix>.<domain>.
    verify_record_prefix: str = "replyas"
    # Where operator mail (postmaster@/abuse@ relay domain) goes.
    operator_email: str = ""
    system_mail_from: str = ""  # defaults to noreply@relay_domain

    # SMTP listener
    smtp_listen_host: str = "0.0.0.0"
    smtp_listen_port: int = 2525
    smtp_tls_cert: Path | None = None
    smtp_tls_key: Path | None = None

    # Outbound: "direct" (MX delivery), "smtp" (smarthost) or "file" (dev).
    outbound_mode: str = "file"
    outbox_dir: Path = Path("var/outbox")
    smarthost_host: str = ""
    smarthost_port: int = 587
    smarthost_username: str = ""
    smarthost_password: str = ""
    smarthost_starttls: bool = True

    # Sender verification on replies. Only disable for local experiments.
    require_dkim_on_replies: bool = True
    # Reject inbound mail that fails DMARC on a p=reject domain.
    enforce_inbound_dmarc_reject: bool = True

    # --- Abuse limits --------------------------------------------------------
    max_message_bytes: int = 25 * 1024 * 1024
    max_recipients_per_message: int = 10
    daily_send_limit: int = 200
    daily_new_contact_limit: int = 50

    # --- Plans & billing -----------------------------------------------------
    trial_days: int = 14
    trial_max_domains: int = 1
    # Days after trial/subscription ends during which inbound still forwards.
    inbound_grace_days: int = 7
    price_display: str = "$30"
    price_interval_display: str = "year"
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_price_id: str = ""  # recurring yearly price, billed per domain
    stripe_automatic_tax: bool = False

    @property
    def admin_email_set(self) -> set[str]:
        return {e.strip().lower() for e in self.admin_emails.split(",") if e.strip()}

    @property
    def billing_enabled(self) -> bool:
        return bool(self.stripe_secret_key and self.stripe_price_id)

    @property
    def system_from(self) -> str:
        return self.system_mail_from or f"noreply@{self.relay_domain}"


@lru_cache
def get_settings() -> Settings:
    return Settings()
