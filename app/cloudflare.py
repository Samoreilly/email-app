"""One-click DNS setup for domains on Cloudflare.

The customer pastes an API token scoped to "Zone: DNS: Edit" for their zone.
We use it once and never store it.
"""

import httpx

from app.config import get_settings
from app.dns_check import expected_records
from app.models import Domain

API = "https://api.cloudflare.com/client/v4"


class CloudflareError(Exception):
    pass


def _check(resp: httpx.Response) -> dict:
    try:
        data = resp.json()
    except ValueError:
        raise CloudflareError(f"Cloudflare returned HTTP {resp.status_code}")
    if not data.get("success"):
        errors = "; ".join(e.get("message", "") for e in data.get("errors", [])) or resp.text[:200]
        raise CloudflareError(errors)
    return data


def apply_records(domain: Domain, token: str, replace_mx: bool, client: httpx.Client | None = None) -> list[str]:
    """Create/update the records. Returns a human-readable list of changes."""
    s = get_settings()
    own_client = client is None
    client = client or httpx.Client(timeout=20)
    client.headers["Authorization"] = f"Bearer {token.strip()}"
    changes: list[str] = []
    try:
        zones = _check(client.get(f"{API}/zones", params={"name": domain.name}))["result"]
        if not zones:
            raise CloudflareError(
                f"No Cloudflare zone named {domain.name} is visible to this token. "
                "Check the token has Zone:DNS:Edit for this domain."
            )
        zid = zones[0]["id"]
        base = f"{API}/zones/{zid}/dns_records"

        def records(rtype: str, name: str) -> list[dict]:
            return _check(client.get(base, params={"type": rtype, "name": name, "per_page": 100}))["result"]

        for rec in expected_records(domain):
            if rec.key == "mx":
                existing = records("MX", rec.fqdn)
                if any(r["content"].lower().rstrip(".") == s.mx_host.lower() for r in existing):
                    others = [r for r in existing if r["content"].lower().rstrip(".") != s.mx_host.lower()]
                else:
                    others = existing
                    _check(client.post(base, json={"type": "MX", "name": rec.fqdn, "content": rec.value,
                                                   "priority": rec.priority, "ttl": 1}))  # fmt: skip
                    changes.append(f"Added MX {rec.value}")
                if others and replace_mx:
                    for r in others:
                        resp = client.delete(f"{base}/{r['id']}")
                        try:
                            _check(resp)
                        except CloudflareError as exc:
                            raise CloudflareError(
                                f"Couldn't remove MX {r['content']} ({exc}). If Cloudflare Email Routing "
                                "is on, disable it under Email > Email Routing > Settings first, then retry."
                            )
                        changes.append(f"Removed old MX {r['content']}")
                elif others:
                    changes.append("Left existing MX records in place (tick 'replace MX' to remove them)")
            elif rec.key == "spf":
                spf = [r for r in records("TXT", rec.fqdn) if r["content"].strip('"').lower().startswith("v=spf1")]
                include = f"include:{s.spf_include}"
                if not spf:
                    _check(client.post(base, json={"type": "TXT", "name": rec.fqdn, "content": rec.value, "ttl": 1}))
                    changes.append("Added SPF record")
                elif include not in spf[0]["content"].lower():
                    parts = spf[0]["content"].strip('"').split()
                    parts.insert(1, include)
                    _check(client.patch(f"{base}/{spf[0]['id']}", json={"content": " ".join(parts)}))
                    changes.append("Added our include to your SPF record")
            else:
                existing = records("TXT", rec.fqdn)
                if rec.key == "dmarc":
                    if any(r["content"].strip('"').lower().startswith("v=dmarc1") for r in existing):
                        continue
                elif any(r["content"].strip('"') == rec.value for r in existing):
                    continue
                if rec.key == "dkim":
                    for r in existing:  # stale key under our selector
                        _check(client.delete(f"{base}/{r['id']}"))
                _check(client.post(base, json={"type": "TXT", "name": rec.fqdn, "content": rec.value, "ttl": 1}))
                changes.append(f"Added {rec.title} record")
    except httpx.HTTPError as exc:
        raise CloudflareError(f"Couldn't reach Cloudflare: {exc}")
    finally:
        if own_client:
            client.close()
    return changes
