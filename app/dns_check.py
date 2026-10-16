"""The DNS records a customer must publish, and a live checker for them."""

import re
from dataclasses import dataclass

import dns.exception
import dns.resolver

from app.config import get_settings
from app.db import utcnow
from app.models import Domain


@dataclass
class Record:
    key: str  # verify / mx / spf / dkim / dmarc
    title: str
    type: str
    host: str  # relative name as shown in DNS panels ("@" for the apex)
    fqdn: str
    value: str
    priority: int | None = None
    required: bool = True
    help: str = ""


@dataclass
class CheckResult:
    ok: bool
    found: list[str]
    message: str


def expected_records(domain: Domain) -> list[Record]:
    s = get_settings()
    d = domain.name
    prefix = s.verify_record_prefix
    return [
        Record(
            "verify", "Ownership", "TXT", f"_{prefix}", f"_{prefix}.{d}",
            f"{prefix}-verify={domain.verification_token}",
            help="Proves you control this domain.",
        ),
        Record(
            "mx", "Receive mail", "MX", "@", d, s.mx_host, priority=10,
            help="Sends mail for your domain to us so we can forward it to Gmail. "
            "Remove any other MX records (e.g. ImprovMX or Cloudflare Email Routing).",
        ),
        Record(
            "spf", "SPF", "TXT", "@", d, f"v=spf1 include:{s.spf_include} ~all",
            help="Authorises our servers to send as your domain. If you already have a "
            f"v=spf1 record, add include:{s.spf_include} to it instead of creating a second one.",
        ),
        Record(
            "dkim", "DKIM", "TXT", f"{domain.dkim_selector}._domainkey",
            f"{domain.dkim_selector}._domainkey.{d}", domain.dkim_public_record,
            help="Lets receivers verify mail we send for you really is from your domain.",
        ),
        Record(
            "dmarc", "DMARC", "TXT", "_dmarc", f"_dmarc.{d}",
            f"v=DMARC1; p=quarantine; adkim=r; aspf=r",
            required=False,
            help="Recommended. Tells Gmail and others what to do with mail that fails checks. "
            "Keep your existing DMARC record if you have one.",
        ),
    ]  # fmt: skip


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.lifetime = 6
    r.timeout = 3
    r.cache = None
    return r


def _txt(name: str) -> list[str]:
    try:
        ans = _resolver().resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    return [b"".join(r.strings).decode("utf-8", "replace") for r in ans]


def _mx(name: str) -> list[str]:
    try:
        ans = _resolver().resolve(name, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    return [str(r.exchange).rstrip(".").lower() for r in sorted(ans, key=lambda r: r.preference)]


def _norm(v: str) -> str:
    return re.sub(r"\s+", "", v).lower()


def check_record(rec: Record) -> CheckResult:
    s = get_settings()
    if rec.key == "mx":
        found = _mx(rec.fqdn)
        ours = s.mx_host.lower() in found
        others = [h for h in found if h != s.mx_host.lower()]
        if ours and not others:
            return CheckResult(True, found, "MX points to us.")
        if ours:
            return CheckResult(False, found, f"Remove the other MX records: {', '.join(others)}")
        return CheckResult(False, found, "MX doesn't point to us yet." if found else "No MX record found.")

    found = _txt(rec.fqdn)
    if rec.key == "verify":
        ok = any(_norm(v) == _norm(rec.value) for v in found)
        return CheckResult(ok, found, "Verified." if ok else "Ownership TXT record not found yet.")
    if rec.key == "spf":
        spf = [v for v in found if v.lower().startswith("v=spf1")]
        if len(spf) > 1:
            return CheckResult(False, spf, "You have more than one SPF record; merge them into one.")
        ok = bool(spf) and f"include:{s.spf_include.lower()}" in spf[0].lower()
        msg = "SPF includes us." if ok else (f"Add include:{s.spf_include} to your SPF record." if spf else "No SPF record found.")
        return CheckResult(ok, spf, msg)
    if rec.key == "dkim":
        want = re.search(r"p=([A-Za-z0-9+/=]+)", rec.value).group(1)
        ok = any(want in re.sub(r"\s+", "", v) for v in found)
        return CheckResult(ok, found, "DKIM key published." if ok else "DKIM record not found or doesn't match.")
    if rec.key == "dmarc":
        dm = [v for v in found if v.lower().startswith("v=dmarc1")]
        return CheckResult(bool(dm), dm, "DMARC record found." if dm else "No DMARC record (recommended).")
    return CheckResult(False, found, "Unknown record")


def run_checks(domain: Domain) -> dict[str, CheckResult]:
    """Check every record and store the results on the domain."""
    results = {rec.key: check_record(rec) for rec in expected_records(domain)}
    if results["verify"].ok and domain.verified_at is None:
        domain.verified_at = utcnow()
    domain.mx_ok = results["mx"].ok
    domain.spf_ok = results["spf"].ok
    domain.dkim_ok = results["dkim"].ok
    domain.dmarc_ok = results["dmarc"].ok
    domain.last_checked_at = utcnow()
    return results


DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
FREEMAIL = {
    "gmail.com", "googlemail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "yandex.com",
}  # fmt: skip


def validate_domain_name(name: str) -> str | None:
    """Return an error message, or None if the name is acceptable."""
    if not DOMAIN_RE.match(name):
        return "That doesn't look like a domain name (e.g. yourbusiness.com)."
    if name in FREEMAIL or name.endswith("." + get_settings().relay_domain):
        return "You can only add a domain you own and control DNS for."
    if name == get_settings().relay_domain:
        return "That domain isn't available."
    return None
