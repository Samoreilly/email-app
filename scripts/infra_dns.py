"""Print the DNS records for *our* infrastructure (relay domain, MX host, SPF).

Usage: SERVER_IP=1.2.3.4 uv run python -m scripts.infra_dns
"""

import os

from app.config import get_settings
from app.relay.keys import relay_public_record

s = get_settings()
ip = os.environ.get("SERVER_IP", "<server IPv4>")
print(f"{s.mx_host}.                 A     {ip}")
print(f"{s.relay_domain}.            MX 10 {s.mx_host}.")
print(f'{s.relay_domain}.            TXT   "v=spf1 ip4:{ip} -all"')
print(f'{s.spf_include}.             TXT   "v=spf1 ip4:{ip} -all"')
print(f'_dmarc.{s.relay_domain}.     TXT   "v=DMARC1; p=reject; rua=mailto:postmaster@{s.relay_domain}"')
print(f'{s.relay_dkim_selector}._domainkey.{s.relay_domain}. TXT "{relay_public_record()}"')
print(f"\nReverse DNS (PTR) for {ip} must be {s.mx_host} (set at your hosting provider).")
