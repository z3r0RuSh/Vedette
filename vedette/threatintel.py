"""Threat-intel enrichment for Vedette's domain legs.

Keyed sources (optional; skipped gracefully without a key, following the
Serper/Bing/HIBP pattern -- key values never logged or audited):
- VirusTotal (VT_API_KEY): domain reputation, analysis stats, DNS records.
- AlienVault OTX (OTX_API_KEY): pulses mentioning the domain, reputation.

Keyless sources (always available):
- urlscan.io: recent scans of the domain (page URLs, scan dates).
- crt.sh: certificate-transparency subdomains and issuance history.

Every lookup writes a JSONL audit record through the caller-supplied
audit_fn: source, query, outcome, result counts. Nothing here raises;
failures return None and the caller treats the data as NOT FOUND.
"""

from __future__ import annotations

import os
import urllib.parse

import requests

USER_AGENT = "Vedette-OSINT/1.0 (threat research)"

VT_KEY_ENV = "VT_API_KEY"
OTX_KEY_ENV = "OTX_API_KEY"

VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
OTX_GENERAL_URL = ("https://otx.alienvault.com/api/v1/indicators/domain/"
                   "{domain}/general")
OTX_URL_LIST_URL = ("https://otx.alienvault.com/api/v1/indicators/domain/"
                    "{domain}/url_list")
URLSCAN_SEARCH_URL = "https://urlscan.io/api/v1/search/"
CRTSH_URL = "https://crt.sh/"


class ThreatIntelError(Exception):
    """Raised for threat-intel configuration failures."""


def _get(url, headers=None, params=None, timeout=20):
    resp = requests.get(url, headers=headers, params=params,
                        timeout=timeout)
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# VirusTotal (keyed)
# ---------------------------------------------------------------------------

def vt_domain_report(domain, audit_fn=None):
    """VirusTotal domain report dict, or None when skipped/failed.

    Skipped (None) when VT_API_KEY is not set. Returned dict has:
    analysis_stats, categories, registrar, creation_date, dns_records.
    """
    api_key = os.environ.get(VT_KEY_ENV)
    if not api_key:
        return None
    domain = (domain or "").strip().lower()
    try:
        data = _get(VT_DOMAIN_URL.format(domain=domain),
                    headers={"x-apikey": api_key,
                             "User-Agent": USER_AGENT})
        attrs = ((data or {}).get("data") or {}).get("attributes") or {}
        report = {
            "analysis_stats": attrs.get("last_analysis_stats") or {},
            "categories": attrs.get("categories") or {},
            "registrar": attrs.get("registrar") or "",
            "creation_date": attrs.get("creation_date") or "",
            "dns_records": [
                {"type": r.get("type"), "value": r.get("value")}
                for r in (attrs.get("last_dns_records") or [])[:10]
            ],
        }
        if audit_fn:
            audit_fn({"event": "threatintel_lookup", "source": "virustotal",
                      "query": domain, "outcome": "ok"})
        return report
    except Exception as exc:  # noqa: BLE001 - intel must not kill a run
        if audit_fn:
            audit_fn({"event": "threatintel_lookup", "source": "virustotal",
                      "query": domain, "outcome": "error",
                      "error": str(exc)})
        return None


def format_vt_report(domain, report):
    lines = ["## VirusTotal domain report"]
    if report is None:
        lines.append("Skipped: %s is not set in the environment."
                     % VT_KEY_ENV)
        return "\n".join(lines)
    stats = report.get("analysis_stats") or {}
    lines.append(
        "Detections for %s: %d malicious / %d suspicious / %d harmless / "
        "%d undetected (of reporting engines)."
        % (domain, stats.get("malicious", 0), stats.get("suspicious", 0),
           stats.get("harmless", 0), stats.get("undetected", 0)))
    cats = report.get("categories") or {}
    if cats:
        lines.append("Categories: " + ", ".join(
            "%s=%s" % (k, v) for k, v in list(cats.items())[:5]))
    if report.get("registrar"):
        lines.append("Registrar: %s" % report["registrar"])
    if report.get("creation_date"):
        lines.append("Creation date: %s" % report["creation_date"])
    dns = report.get("dns_records") or []
    if dns:
        lines.append("Recent DNS records:")
        for r in dns:
            lines.append("- %s %s" % (r["type"], r["value"]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# AlienVault OTX (keyed)
# ---------------------------------------------------------------------------

def otx_domain_intel(domain, audit_fn=None, url_limit=10):
    """OTX general + URL-list intel for a domain, or None when skipped/failed.

    Returned dict has: reputation, pulse_count, pulses (names), urls.
    """
    api_key = os.environ.get(OTX_KEY_ENV)
    if not api_key:
        return None
    domain = (domain or "").strip().lower()
    headers = {"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT}
    try:
        general = _get(OTX_GENERAL_URL.format(domain=domain), headers=headers)
        url_list = _get(OTX_URL_LIST_URL.format(domain=domain),
                        headers=headers,
                        params={"limit": url_limit, "page": 1})
        pulses = [p.get("name") for p in (general.get("pulse_info") or {})
                  .get("pulses") or [] if p.get("name")]
        intel = {
            "reputation": general.get("reputation"),
            "pulse_count": (general.get("pulse_info") or {}).get("count", 0),
            "pulses": pulses[:10],
            "urls": [u.get("url") for u in (url_list.get("url_list") or [])
                     if u.get("url")][:url_limit],
        }
        if audit_fn:
            audit_fn({"event": "threatintel_lookup", "source": "otx",
                      "query": domain, "outcome": "ok",
                      "pulse_count": intel["pulse_count"]})
        return intel
    except Exception as exc:  # noqa: BLE001 - intel must not kill a run
        if audit_fn:
            audit_fn({"event": "threatintel_lookup", "source": "otx",
                      "query": domain, "outcome": "error",
                      "error": str(exc)})
        return None


def format_otx_intel(domain, intel):
    lines = ["## AlienVault OTX"]
    if intel is None:
        lines.append("Skipped: %s is not set in the environment."
                     % OTX_KEY_ENV)
        return "\n".join(lines)
    lines.append("Reputation score: %s | Pulses mentioning %s: %d"
                 % (intel.get("reputation"), domain, intel.get("pulse_count", 0)))
    if intel.get("pulses"):
        lines.append("Pulses:")
        for name in intel["pulses"]:
            lines.append("- %s" % name)
    if intel.get("urls"):
        lines.append("Associated URLs seen by OTX:")
        for u in intel["urls"]:
            lines.append("- %s" % u)
    if not intel.get("pulses") and not intel.get("urls"):
        lines.append("No pulses or URLs recorded for this domain.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# urlscan.io (keyless)
# ---------------------------------------------------------------------------

def urlscan_search(domain, size=5, timeout=20):
    """Recent urlscan.io scans for a domain; [] on failure/empty."""
    domain = (domain or "").strip().lower()
    try:
        data = _get(URLSCAN_SEARCH_URL,
                    params={"q": "domain:%s" % domain, "size": size},
                    timeout=timeout)
        out = []
        for r in (data or {}).get("results") or []:
            task = r.get("task") or {}
            page = r.get("page") or {}
            out.append({"scan": task.get("time") or "",
                        "url": task.get("url") or page.get("url") or "",
                        "screenshot": r.get("screenshot") or ""})
        return out
    except Exception:  # noqa: BLE001 - intel must not kill a run
        return []


def format_urlscan(domain, scans):
    lines = ["## urlscan.io recent scans"]
    if not scans:
        lines.append("No scans found for %s (or lookup failed)." % domain)
    else:
        for s in scans:
            lines.append("- %s -- %s" % (s["scan"], s["url"]))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# crt.sh (keyless)
# ---------------------------------------------------------------------------

def crtsh_subdomains(domain, timeout=25, limit=30):
    """Subdomains from certificate transparency; [] on failure/empty."""
    domain = (domain or "").strip().lower()
    try:
        data = _get(CRTSH_URL,
                    params={"q": "%%.%s" % domain, "output": "json"},
                    timeout=timeout)
        subs = set()
        for entry in data or []:
            for name in (entry.get("name_value") or "").split("\n"):
                name = name.strip().lower()
                if name and not name.startswith("*") and \
                        name.endswith(domain):
                    subs.add(name)
        return sorted(subs)[:limit]
    except Exception:  # noqa: BLE001 - intel must not kill a run
        return []


def format_crtsh(domain, subdomains):
    lines = ["## Certificate transparency (crt.sh)"]
    if not subdomains:
        lines.append("No subdomains found in CT logs for %s (or lookup "
                     "failed)." % domain)
    else:
        lines.append("Subdomains seen in certificates (%d shown):"
                     % len(subdomains))
        for s in subdomains:
            lines.append("- %s" % s)
    return "\n".join(lines)
