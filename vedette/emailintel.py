"""Email intelligence helpers for Vedette's email legs.

- parse_email: validate an address and split it into local/domain parts.
- mx_records: MX lookup via DNS-over-HTTPS (Cloudflare), keyless, no new
  dependencies (uses requests, already required).
- hibp_breaches: HaveIBeenPwned breach list for an address. Needs
  HIBP_API_KEY in the environment (1Password-injected). Without the key the
  function returns None and the caller treats breach data as NOT FOUND.
  Key values are never logged, printed, or audited.

Audit records carry provider, query, and result counts -- never key material.
"""

from __future__ import annotations

import os
import re
import urllib.parse

import requests

USER_AGENT = "Vedette-OSINT/1.0 (identity research)"

HIBP_KEY_ENV = "HIBP_API_KEY"
HIBP_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

DOH_URL = "https://cloudflare-dns.com/dns-query"

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

# Domains commonly used for throwaway addresses; not exhaustive, used only
# as a hint for the deliverability leg.
DISPOSABLE_HINTS = (
    "mailinator.com", "guerrillamail.com", "10minutemail.com",
    "tempmail.com", "yopmail.com", "trashmail.com",
)


class EmailIntelError(Exception):
    """Raised for email-intel failures (DNS, HIBP transport)."""


def parse_email(raw):
    """Return {"email", "local", "domain"} or None if not an address."""
    raw = (raw or "").strip()
    if not EMAIL_RE.match(raw):
        return None
    local, domain = raw.rsplit("@", 1)
    return {"email": raw, "local": local, "domain": domain.lower()}


def mx_records(domain, timeout=15):
    """MX records for a domain via DNS-over-HTTPS. Returns
    [{"preference": int, "exchange": str}]; raises EmailIntelError on failure.
    """
    domain = (domain or "").strip().lower().rstrip(".")
    if not domain:
        raise EmailIntelError("empty domain")
    resp = requests.get(
        DOH_URL,
        params={"name": domain, "type": "MX"},
        headers={"Accept": "application/dns-json", "User-Agent": USER_AGENT},
        timeout=timeout,
    )
    resp.raise_for_status()
    data = resp.json()
    records = []
    for ans in (data or {}).get("Answer") or []:
        # MX rdata: "10 mx.example.com."
        parts = (ans.get("data") or "").split()
        if len(parts) == 2 and parts[0].isdigit():
            records.append({"preference": int(parts[0]),
                            "exchange": parts[1].rstrip(".").lower()})
    records.sort(key=lambda r: r["preference"])
    return records


def is_disposable_domain(domain):
    """Heuristic hint only: is this a known throwaway-mail domain?"""
    return (domain or "").lower() in DISPOSABLE_HINTS


def hibp_breaches(email, timeout=20):
    """Breach list for an address via HaveIBeenPwned.

    Returns a list of {"name", "date"} dicts, [] when the address has no
    known breaches, or None when the check was skipped (no HIBP_API_KEY)
    or failed. Raises nothing; transport failures return None.
    """
    api_key = os.environ.get(HIBP_KEY_ENV)
    if not api_key:
        return None
    url = HIBP_URL.format(email=urllib.parse.quote(email, safe=""))
    try:
        resp = requests.get(
            url,
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": api_key, "User-Agent": USER_AGENT},
            timeout=timeout,
        )
        if resp.status_code == 404:
            return []  # address not found in any known breach
        resp.raise_for_status()
        out = []
        for item in resp.json() or []:
            out.append({"name": item.get("Name") or "",
                        "date": item.get("BreachDate") or ""})
        return out
    except Exception:  # noqa: BLE001 - breach check must not kill a run
        return None


def format_deliverability(parsed, mx, audit_note=""):
    """Render a deliverability context block for the research prompt."""
    lines = ["## Email deliverability signals (keyless checks)"]
    lines.append("Address: %s" % parsed["email"])
    lines.append("Local part: %s | Domain: %s"
                 % (parsed["local"], parsed["domain"]))
    if mx:
        lines.append("MX records (preference order):")
        for r in mx:
            lines.append("- %d %s" % (r["preference"], r["exchange"]))
    else:
        lines.append("MX records: none found -- the domain likely cannot "
                     "receive mail.")
    if is_disposable_domain(parsed["domain"]):
        lines.append("Note: the domain is a known disposable-mail provider.")
    if audit_note:
        lines.append(audit_note)
    return "\n".join(lines)


def format_breaches(email, breaches):
    """Render an HIBP result as a context block. breaches=None means skipped."""
    lines = ["## Breach exposure (HaveIBeenPwned)"]
    if breaches is None:
        lines.append("Skipped: %s is not set in the environment. Treat breach "
                     "exposure as NOT FOUND unless other sources show it."
                     % HIBP_KEY_ENV)
    elif not breaches:
        lines.append("%s: no known breaches." % email)
    else:
        lines.append("%s appears in %d known breach(es):" % (email, len(breaches)))
        for b in breaches:
            lines.append("- %s (%s)" % (b["name"], b["date"] or "date unknown"))
    return "\n".join(lines)
