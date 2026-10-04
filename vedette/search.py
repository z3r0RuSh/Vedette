"""Built-in web search for the Vedette's research legs.

The research legs call these tools directly, so company/product/domain
name-search works with *every* model backend -- including local Ollama --
instead of depending on a hosted backend's server-side web search.

Providers:
  duckduckgo - keyless, via the lite HTML endpoint (polite UA, rate-limited)
  serper     - Google results via https://google.serper.dev (SERPER_API_KEY)
  bing       - https://api.bing.microsoft.com/v7.0/search (BING_API_KEY)

Every search writes a JSONL audit record through the caller-supplied
audit_fn: provider, query, result count, and each result's URL + fetch
timestamp. API key values are never logged, printed, or audited.
"""

from __future__ import annotations

import html as html_mod
import os
import re
import time
import urllib.parse
from datetime import datetime, timezone

import requests

USER_AGENT = "OSINTAgent/1.0 (security research)"

VALID_PROVIDERS = ("auto", "duckduckgo", "serper", "bing")

# Env var holding the API key for each keyed provider. Values are read from
# the environment only (1Password-injected) and never logged or audited.
PROVIDER_KEY_ENV = {
    "serper": "SERPER_API_KEY",
    "bing": "BING_API_KEY",
}


class SearchError(Exception):
    """Raised for search configuration or provider failures."""


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _domain_of(name, url):
    """Best-effort domain for query templating, from the URL, name, or email."""
    for raw in (url or "", name or ""):
        raw = raw.strip()
        if not raw:
            continue
        if "@" in raw and "://" not in raw:
            raw = raw.rsplit("@", 1)[1]  # email address -> domain part
        if "://" not in raw and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", raw, re.I):
            return raw.lower()
        try:
            host = urllib.parse.urlparse(
                raw if "://" in raw else "https://" + raw).hostname
        except Exception:  # noqa: BLE001 - best effort only
            host = None
        if host:
            return host.lower()
    return (name or "").strip()


# Per-type, per-axis search queries run by the research legs before the
# model call. {name} = target name, {domain} = best-effort domain.
AXIS_QUERIES = {
    "company": {
        "jurisdiction": [
            "{name} terms of service governing law jurisdiction",
            "{name} data center locations headquarters country",
        ],
        "contractual": [
            "{name} data processing agreement DPA",
            "{name} privacy policy customer data AI training",
        ],
        "compliance": [
            "{name} SOC 2 ISO 27001 certification",
            "{name} trust center security compliance",
        ],
        "incidents": [
            "{name} data breach security incident",
            "{name} law enforcement investigation",
        ],
        "posture": [
            "{name} bug bounty vulnerability disclosure program",
            "{name} security whitepaper penetration testing policy",
        ],
        # ---- corporate profile ----
        "ownership": [
            "{name} parent company ownership subsidiaries",
            "{name} incorporation corporate structure",
        ],
        "leadership": [
            "{name} CEO executive team leadership",
            "{name} board of directors",
        ],
        "financials": [
            "{name} annual revenue headcount",
            "{name} financial results earnings",
        ],
        "footprint": [
            "{name} headquarters office locations",
            "{name} data center locations regions",
        ],
        "partnerships": [
            "{name} customers partners announced",
            "{name} strategic partnership alliance",
        ],
        # ---- financial profile ----
        "funding": [
            "{name} funding rounds total raised",
            "{name} Series A B C funding announced",
        ],
        "investors": [
            "{name} investors venture capital backers",
            "{name} lead investor funding round",
        ],
        "revenue": [
            "{name} revenue 2024 2025 reported estimated",
            "{name} annual recurring revenue ARR",
        ],
        "manda": [
            "{name} acquisitions acquired",
            "{name} merger acquisition rumors",
        ],
        "valuation": [
            "{name} valuation funding round",
            "{name} market capitalization",
        ],
        # ---- reputation profile ----
        "coverage": [
            "{name} news coverage",
            "{name} press announcement 2025 2026",
        ],
        "controversies": [
            "{name} controversy scandal",
            "{name} lawsuit filed",
        ],
        "regulatory": [
            "{name} regulatory fine enforcement action",
            "{name} investigation regulator",
        ],
        "sentiment": [
            "{name} employee reviews rating",
            "{name} customer reviews complaints",
        ],
        # ---- technology profile ----
        "techstack": [
            "{name} engineering blog technology stack",
            "{name} tech stack built with",
        ],
        "engineering": [
            "{name} engineering jobs hiring",
            "{name} engineering team blog",
        ],
        "patents": [
            "{name} patents filed",
            "{name} research publications R&D",
        ],
        "opensource": [
            "{name} github open source",
            "{name} open source projects maintained",
        ],
    },
    "software": {
        "supply_chain": [
            "{name} open source repository maintainers",
            "{name} release signing SBOM software bill of materials",
        ],
        "vulnerabilities": [
            "{name} CVE vulnerabilities",
            "{name} security advisory",
        ],
        "maintenance": [
            "{name} release cadence end of life support policy",
            "{name} latest release changelog",
        ],
        "data_handling": [
            "{name} telemetry data collection privacy",
            "{name} license terms commercial use",
        ],
        "assurance": [
            "{name} security audit bug bounty",
            "{name} penetration test report",
        ],
    },
    "domain": {
        "registration": [
            '"{domain}" whois registrar domain registration',
            '"{domain}" domain age creation date',
        ],
        "hosting": [
            "'{domain}' hosting provider nameservers",
            "'{domain}' IP address geolocation hosting",
        ],
        "tls": [
            "'{domain}' SSL TLS certificate issuer",
            "'{domain}' security headers HSTS",
        ],
        "phishing": [
            "'{domain}' phishing malicious blocklist",
            "'{domain}' malware abuse report",
        ],
        "infra": [
            "'{domain}' subdomains DNS records",
            "'{domain}' MX records mail infrastructure",
        ],
    },
    "person": {
        "p_background": [
            "{name} biography education",
            "{name} early life background",
        ],
        "p_career": [
            "{name} career history roles",
            "{name} appointed CEO executive",
        ],
        "p_affiliations": [
            "{name} board member advisor",
            "{name} founded co-founded organization",
        ],
        "p_presence": [
            "{name} interview talk",
            "{name} social media official profile",
        ],
        "p_controversies": [
            "{name} controversy allegations",
            "{name} lawsuit legal",
        ],
        "p_social": [
            "{name} linkedin twitter github",
            '"{name}" social media profile',
        ],
    },
    "email": {
        "e_format": [
            '"{name}" email',
        ],
        "e_deliverability": [
            '"{domain}" MX records mail server',
            '"{domain}" SPF DKIM DMARC',
        ],
        "e_breaches": [
            '"{name}" breach',
            '"{name}" leaked pastebin',
        ],
        "e_associations": [
            '"{name}"',
            '"{name}" forum github',
        ],
    },
}


class SearchClient:
    """One configured search provider with throttling."""

    DDG_URL = "https://lite.duckduckgo.com/lite/"
    SERPER_URL = "https://google.serper.dev/search"
    BING_URL = "https://api.bing.microsoft.com/v7.0/search"

    # DuckDuckGo lite result markup.
    _DDG_LINK_RE = re.compile(
        r'<a rel="nofollow" href="([^"]+)"[^>]*>(.*?)</a>', re.S)
    _DDG_SNIPPET_RE = re.compile(
        r'''<td class=['"]result-snippet['"][^>]*>(.*?)</td>''', re.S)
    _TAG_RE = re.compile(r"<[^>]+>")

    def __init__(self, provider="auto", max_results=6, rate_limit_s=1.0,
                 timeout=30):
        self.provider = self._resolve_provider(provider)
        self.max_results = max(1, int(max_results or 6))
        self.rate_limit_s = max(0.0, float(rate_limit_s or 0))
        self.timeout = timeout
        self._last_call = 0.0
        env_name = PROVIDER_KEY_ENV.get(self.provider)
        self._api_key = os.environ.get(env_name) if env_name else None

    # -- provider selection ------------------------------------------------
    @staticmethod
    def _resolve_provider(provider):
        provider = (provider or "auto").lower()
        if provider not in VALID_PROVIDERS:
            raise SearchError(
                "Unknown search provider %r (expected one of: %s)."
                % (provider, ", ".join(VALID_PROVIDERS)))
        if provider == "auto":
            for cand, env_name in (("serper", "SERPER_API_KEY"),
                                   ("bing", "BING_API_KEY")):
                if os.environ.get(env_name):
                    return cand
            return "duckduckgo"
        env_name = PROVIDER_KEY_ENV.get(provider)
        if env_name and not os.environ.get(env_name):
            raise SearchError(
                "Search provider %r needs %s in the environment "
                "(keys are read from env only, never from config files)."
                % (provider, env_name))
        return provider

    # -- public API --------------------------------------------------------
    def search(self, query):
        """Run one query; returns [{url, title, snippet, fetched_at}]."""
        self._throttle()
        if self.provider == "duckduckgo":
            results = self._ddg_search(query)
        elif self.provider == "serper":
            results = self._serper_search(query)
        elif self.provider == "bing":
            results = self._bing_search(query)
        else:  # pragma: no cover - guarded by _resolve_provider
            raise SearchError("Unknown provider %r" % self.provider)
        fetched_at = _now_iso()
        for r in results:
            r["fetched_at"] = fetched_at
        return results[: self.max_results]

    def fetch_text(self, url, max_chars=20000):
        """Fetch a page and return plain text (scripts/styles stripped)."""
        self._throttle()
        resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                            timeout=self.timeout)
        resp.raise_for_status()
        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype and "text" not in ctype:
            raise SearchError("Not a text page: %s (%s)" % (url, ctype))
        text = self._TAG_RE.sub(" ", self._strip_scripts(resp.text))
        text = html_mod.unescape(re.sub(r"\s+", " ", text)).strip()
        return text[:max_chars]

    @staticmethod
    def _strip_scripts(html):
        return re.sub(r"<(script|style)[^>]*>.*?</\1>", " ",
                      html, flags=re.S | re.I)

    def _throttle(self):
        if self.rate_limit_s <= 0:
            return
        wait = self.rate_limit_s - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    # -- DuckDuckGo (keyless) ----------------------------------------------
    def _ddg_search(self, query):
        resp = requests.post(self.DDG_URL, data={"q": query},
                             headers={"User-Agent": USER_AGENT},
                             timeout=self.timeout)
        resp.raise_for_status()
        return self.parse_ddg_lite(resp.text, self.max_results)

    @classmethod
    def parse_ddg_lite(cls, html, max_results):
        """Parse lite.duckduckgo.com result HTML. Pure function (tested)."""
        links = cls._DDG_LINK_RE.findall(html or "")
        snippets = cls._DDG_SNIPPET_RE.findall(html or "")
        results = []
        for i, (href, title_html) in enumerate(links):
            if len(results) >= max_results:
                break
            url = cls._ddg_real_url(href)
            if not url:
                continue
            title = html_mod.unescape(
                cls._TAG_RE.sub("", title_html)).strip()
            snippet = ""
            if i < len(snippets):
                snippet = html_mod.unescape(
                    cls._TAG_RE.sub("", snippets[i])).strip()
            results.append({"title": title, "url": url, "snippet": snippet})
        return results

    @staticmethod
    def _ddg_real_url(href):
        if not href or href.startswith("#") or href.startswith("javascript:"):
            return None
        if "uddg=" in href:
            try:
                qs = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(href).query)
                real = (qs.get("uddg") or [""])[0]
                return urllib.parse.unquote(real) or None
            except Exception:  # noqa: BLE001 - best effort only
                return None
        if href.startswith("//"):
            return "https:" + href
        if href.startswith("http://") or href.startswith("https://"):
            return href
        return None

    # -- Serper ------------------------------------------------------------
    def _serper_search(self, query):
        resp = requests.post(
            self.SERPER_URL,
            json={"q": query, "num": self.max_results},
            headers={"X-API-KEY": self._api_key,
                     "Content-Type": "application/json"},
            timeout=self.timeout)
        resp.raise_for_status()
        return self.parse_serper(resp.json(), self.max_results)

    @staticmethod
    def parse_serper(data, max_results):
        results = []
        for item in (data or {}).get("organic", [])[:max_results]:
            url = item.get("link") or ""
            if not url:
                continue
            results.append({
                "title": item.get("title") or "",
                "url": url,
                "snippet": item.get("snippet") or "",
            })
        return results

    # -- Bing --------------------------------------------------------------
    def _bing_search(self, query):
        resp = requests.get(
            self.BING_URL,
            params={"q": query, "count": self.max_results,
                    "responseFilter": "Webpages", "textDecorations": False},
            headers={"Ocp-Apim-Subscription-Key": self._api_key},
            timeout=self.timeout)
        resp.raise_for_status()
        return self.parse_bing(resp.json(), self.max_results)

    @staticmethod
    def parse_bing(data, max_results):
        results = []
        pages = ((data or {}).get("webPages") or {}).get("value", [])
        for item in pages[:max_results]:
            url = item.get("url") or ""
            if not url:
                continue
            results.append({
                "title": item.get("name") or "",
                "url": url,
                "snippet": item.get("snippet") or "",
            })
        return results


def search_for_axis(target_type, axis, name, url, client, audit_fn):
    """Run the axis queries and build a context block for the research prompt.

    Never raises: per-query failures are audited as web_search_error and the
    leg continues with whatever results were gathered. Returns "" when no
    results were found.
    """
    templates = (AXIS_QUERIES.get(target_type) or {}).get(axis) or []
    domain = _domain_of(name, url)
    blocks = []
    for template in templates:
        query = template.format(name=name or "", domain=domain)
        try:
            results = client.search(query)
        except Exception as exc:  # noqa: BLE001 - search must not kill a run
            audit_fn({"event": "web_search_error", "provider": client.provider,
                      "query": query, "error": str(exc)})
            continue
        audit_fn({
            "event": "web_search",
            "provider": client.provider,
            "query": query,
            "result_count": len(results),
            # URLs + fetch timestamps only; never key material.
            "results": [{"url": r["url"], "title": r["title"],
                         "fetched_at": r["fetched_at"]} for r in results],
        })
        if not results:
            continue
        lines = ["Query: %s" % query]
        for i, r in enumerate(results, 1):
            lines.append("%d. %s -- %s" % (i, r["title"] or "(no title)",
                                           r["url"]))
            if r["snippet"]:
                lines.append("   %s" % r["snippet"])
        blocks.append("\n".join(lines))
    if not blocks:
        return ""
    header = ("## Live web search (provider: %s, fetched %s)\n"
              "Use these results as leads; verify claims against the cited "
              "pages before repeating them." % (client.provider, _now_iso()))
    return header + "\n\n" + "\n\n".join(blocks)
