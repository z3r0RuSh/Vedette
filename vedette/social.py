"""Social-profile association tools for Vedette's identity legs.

Keyless Sherlock-style username enumeration: for a candidate handle, probe
each platform's public profile URL and record hit/miss/unknown. Every probe
writes a JSONL audit record through the caller-supplied audit_fn: platform,
handle, URL, outcome, confidence, HTTP status. No key material exists here;
everything is keyless.

Also: Gravatar existence check for an email address (documented d=404 mode).

Confidence levels:
- high: the platform returns a clean 404 for unknown handles, so a 200 is
  a reliable hit.
- medium: the platform always returns 200 and existence is inferred from
  page content markers; treat as a lead, not proof.
"""

from __future__ import annotations

import hashlib
import re
import time

import requests

USER_AGENT = "Vedette-OSINT/1.0 (identity research)"

# (name, url_template, check)
# check "status":            200 -> hit, 404 -> miss
# check ("absent", marker):   200 + marker absent from body -> hit (medium)
PLATFORMS = (
    ("github", "https://github.com/{h}", "status"),
    ("gitlab", "https://gitlab.com/{h}", "status"),
    ("reddit", "https://www.reddit.com/user/{h}/", "status"),
    ("medium", "https://medium.com/@{h}", "status"),
    ("keybase", "https://keybase.io/{h}", "status"),
    ("vimeo", "https://vimeo.com/{h}", "status"),
    ("twitch", "https://twitch.tv/{h}", "status"),
    ("about.me", "https://about.me/{h}", "status"),
    ("hackernews", "https://news.ycombinator.com/user?id={h}",
     ("absent", "No such user.")),
    ("tiktok", "https://www.tiktok.com/@{h}",
     ("absent", "Couldn't find this account")),
    ("x", "https://x.com/{h}", ("absent", "This account doesn")),
)

_HANDLE_RE = re.compile(r"^[A-Za-z0-9._-]{1,39}$")


class SocialError(Exception):
    """Raised for social-tool configuration failures."""


def sanitize_handle(handle):
    """Return the handle if it looks like a plausible username, else None."""
    handle = (handle or "").strip().lstrip("@")
    if _HANDLE_RE.match(handle):
        return handle
    return None


def handles_for_name(name):
    """Derive a small set of candidate handles from a person's name."""
    parts = re.findall(r"[a-z0-9]+", (name or "").lower())
    if not parts:
        return []
    candidates = []
    if len(parts) >= 2:
        first, last = parts[0], parts[-1]
        candidates.extend([
            first + last,
            first + "." + last,
            first + "_" + last,
            first[0] + last,
        ])
    else:
        candidates.append(parts[0])
    seen = []
    for c in candidates:
        h = sanitize_handle(c)
        if h and h not in seen:
            seen.append(h)
    return seen[:4]


def handles_for_email_local(local):
    """Candidate handles from an email local part (plus dot/underscore swaps)."""
    local = (local or "").strip().lower()
    variants = {local,
                local.replace(".", ""), local.replace("_", ""),
                local.replace(".", "_"), local.replace("_", "."),
                local.replace("-", "")}
    seen = []
    for v in variants:
        h = sanitize_handle(v)
        if h and h not in seen:
            seen.append(h)
    return seen[:4]


class SocialClient:
    """Username enumerator with throttling; all checks are keyless."""

    def __init__(self, rate_limit_s=0.5, timeout=15):
        self.rate_limit_s = max(0.0, float(rate_limit_s or 0))
        self.timeout = timeout
        self._last_call = 0.0

    def _throttle(self):
        if self.rate_limit_s <= 0:
            return
        wait = self.rate_limit_s - (time.monotonic() - self._last_call)
        if wait > 0:
            time.sleep(wait)
        self._last_call = time.monotonic()

    def check_handle(self, platform, handle):
        """Probe one platform; returns a result dict, never raises."""
        name, template, check = platform
        url = template.format(h=handle)
        self._throttle()
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                                timeout=self.timeout, allow_redirects=True)
            status = resp.status_code
            if check == "status":
                if status == 200:
                    outcome, confidence = "hit", "high"
                elif status == 404:
                    outcome, confidence = "miss", "high"
                else:
                    outcome, confidence = "unknown", "high"
            else:
                marker = check[1]
                if status == 200 and marker not in resp.text:
                    outcome, confidence = "hit", "medium"
                elif status == 200:
                    outcome, confidence = "miss", "medium"
                else:
                    outcome, confidence = "unknown", "medium"
        except Exception:  # noqa: BLE001 - network flakiness, keep going
            status, outcome, confidence = None, "unknown", "high"
        return {"platform": name, "handle": handle, "url": url,
                "outcome": outcome, "confidence": confidence,
                "http_status": status}

    def enumerate(self, handle, audit_fn):
        """Probe all platforms for one handle; audits each probe.

        Never raises: per-platform failures are audited as unknown.
        Returns the list of result dicts.
        """
        handle = sanitize_handle(handle)
        if not handle:
            return []
        results = []
        for platform in PLATFORMS:
            result = self.check_handle(platform, handle)
            results.append(result)
            try:
                audit_fn({"event": "social_probe",
                          "platform": result["platform"],
                          "handle": handle,
                          "url": result["url"],
                          "outcome": result["outcome"],
                          "confidence": result["confidence"],
                          "http_status": result["http_status"]})
            except Exception:  # noqa: BLE001 - auditing must not kill a run
                pass
        return results

    def gravatar_hit(self, email):
        """True/False whether the email has a Gravatar; None on error."""
        digest = hashlib.md5((email or "").strip().lower().encode("utf-8")
                             ).hexdigest()
        url = "https://www.gravatar.com/avatar/%s?d=404" % digest
        self._throttle()
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT},
                                timeout=self.timeout)
            if resp.status_code == 200:
                return True
            if resp.status_code == 404:
                return False
            return None
        except Exception:  # noqa: BLE001 - network flakiness
            return None


def format_results(results):
    """Render enumeration results as a context block for a research prompt."""
    hits = [r for r in results if r["outcome"] == "hit"]
    lines = ["## Social handle enumeration (keyless, Sherlock-style)"]
    if not hits:
        lines.append("No handle hits on the probed platforms.")
    else:
        lines.append("Hits (verify each belongs to the target before "
                     "asserting association):")
        for r in hits:
            lines.append("- %s: %s (confidence: %s)"
                         % (r["platform"], r["url"], r["confidence"]))
    unknown = [r["platform"] for r in results if r["outcome"] == "unknown"]
    if unknown:
        lines.append("Uncheckable (rate-limited or errored): "
                     + ", ".join(unknown))
    return "\n".join(lines)
