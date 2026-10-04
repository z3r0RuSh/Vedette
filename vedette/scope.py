"""Out-of-scope guard: this agent does OSINT research on legitimate targets.

Target types are company, software, domain, person, and email -- researched
under the security profile or the OSINT collection profiles (corporate,
financial, reputation, technology). Anything else (general trivia,
entertainment, how-tos, ...) is refused with a short message, not a lecture.
"""

from __future__ import annotations

REFUSAL = ("Out of scope: this tool only performs OSINT research "
           "(companies, software, domains, people, emails).")


class ScopeError(Exception):
    """Raised when a target is not a security-research target."""


# Heuristic hints that a "target" is really a non-security request.
NON_SECURITY_HINTS = (
    "recipe", "cook ", "pizza", "restaurant", "movie", "film ", "song",
    "lyrics", "poem", "poetry", "joke", "meme", "horoscope", "dating",
    "fashion", "outfit", "workout", "diet ", "lottery", "sports score",
    "game score", "travel itinerary", "hotel", "flight ", "homework",
    "essay", "birthday", "wedding",
)


def looks_non_security(name, url=""):
    """Heuristic: does this look like a non-security request?"""
    text = ("%s %s" % (name or "", url or "")).lower()
    return any(hint in text for hint in NON_SECURITY_HINTS)


def check_target(name, url=""):
    """Raise ScopeError with the short refusal message if out of scope."""
    if not (name or "").strip() and not (url or "").strip():
        raise ScopeError(REFUSAL + " (empty target)")
    if looks_non_security(name, url):
        raise ScopeError("%s Got: %r" % (REFUSAL, (name or url or "").strip()))
